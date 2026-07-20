"""Natural language query engine for Security Shallots."""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shallots.config import AIConfig
    from shallots.store.db import AlertDB

from shallots.ai.ollama_client import OllamaClient
from shallots.ai.prompts import (
    NL_QUERY_SYSTEM,
    NL_QUERY_TEMPLATE,
    SUMMARIZE_TEMPLATE,
)
from shallots.store.models import QueryLog, now_iso

log = logging.getLogger(__name__)

# SQL validation: allowlist + blocklist approach
_SELECT_RE = re.compile(r"^\s*SELECT\b", re.IGNORECASE)
_MUTATION_RE = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|ATTACH|DETACH|REPLACE|TRUNCATE"
    r"|PRAGMA\s+\w+\s*=|VACUUM|REINDEX|LOAD_EXTENSION|RANDOMBLOB)\b",
    re.IGNORECASE,
)
# Only allow queries against these tables
_ALLOWED_TABLES = {"alerts", "triage", "correlations", "queries", "alerts_fts", "meta"}
_TABLE_RE = re.compile(r"\bFROM\s+(\w+)", re.IGNORECASE)
_JOIN_RE = re.compile(r"\bJOIN\s+(\w+)", re.IGNORECASE)
# Whole FROM clause (up to the next major keyword) so comma-joined tables
# like "FROM alerts, sqlite_master" are all validated, not just the first.
_FROM_CLAUSE_RE = re.compile(
    r"\bFROM\s+(.+?)(?=\bWHERE\b|\bGROUP\b|\bORDER\b|\bLIMIT\b|"
    r"\bHAVING\b|\bWINDOW\b|\bJOIN\b|\bUNION\b|\)|;|$)",
    re.IGNORECASE | re.DOTALL,
)
_MAX_RESULT_ROWS = 200
_MAX_RESULT_CHARS = 8000  # chars to send back to AI for summarization
_QUERY_TIMEOUT_SEC = 5  # kill long-running AI-generated queries


class NLQueryEngine:
    """Translates natural language questions into SQL, runs them, and summarizes results.

    Pipeline:
      1. Send question + schema to AI → receive SQL query.
      2. Validate SQL (SELECT only, no mutations).
      3. Execute SQL against the alert database.
      4. Send results back to AI for a natural language summary.
      5. Log the query and result to the queries table.
      6. Return the summary string.
    """

    def __init__(self, cfg: AIConfig, db: AlertDB) -> None:
        self._cfg = cfg
        self._db = db
        self._client = OllamaClient(
            base_url=cfg.ollama_url or "http://localhost:11434",
        )

    async def close(self) -> None:
        """Release underlying HTTP session."""
        await self._client.close()

    async def query(self, question: str) -> str:
        """Run a natural-language query against the alert database.

        Args:
            question: Free-text question from the user, e.g.
                      "How many alerts from Russia in the last 24 hours?"

        Returns:
            Natural-language summary of the query results, or an error message
            if SQL generation, validation, or execution failed.
        """
        question = question.strip()
        if not question:
            return "Please provide a question."

        generated_sql = ""
        result_summary = ""

        try:
            # Step 1: generate SQL
            generated_sql = await self._generate_sql(question)
            log.debug("NLQueryEngine: generated SQL: %s", generated_sql)

            # Step 2: validate SQL
            _validate_sql(generated_sql)

            # Step 3: execute
            rows = await self._db.execute_sql(generated_sql)
            log.debug("NLQueryEngine: query returned %d rows", len(rows))

            # Step 4: summarize
            if not rows:
                result_summary = (
                    f"The query returned no results. "
                    f"(SQL: {generated_sql})"
                )
            else:
                result_summary = await self._summarize(question, generated_sql, rows)

        except SQLValidationError as exc:
            log.warning("NLQueryEngine: invalid SQL generated: %s | SQL: %s", exc, generated_sql)
            result_summary = (
                f"The AI generated an invalid query and it was blocked for safety: {exc}. "
                f"Please rephrase your question."
            )
        except ValueError as exc:
            # execute_sql raises ValueError for non-SELECT
            log.warning("NLQueryEngine: SQL execution blocked: %s", exc)
            result_summary = f"Query blocked: {exc}"
        except Exception as exc:
            log.error("NLQueryEngine: unexpected error: %s", exc, exc_info=True)
            result_summary = f"An error occurred while processing your query: {exc}"
        finally:
            # Step 5: log regardless of success/failure
            await self._log_query(question, generated_sql, result_summary)

        return result_summary

    # ── AI calls ─────────────────────────────────────────────

    async def _generate_sql(self, question: str) -> str:
        """Ask the AI to generate a SQL query for the given question."""
        prompt = NL_QUERY_TEMPLATE.format(question=question)

        raw = await self._dispatch_ai(prompt, NL_QUERY_SYSTEM.strip())

        # Strip markdown fences / whitespace
        sql = _strip_markdown(raw).strip()
        # Remove trailing semicolon — aiosqlite handles that fine, but be tidy
        sql = sql.rstrip(";").strip()
        return sql

    async def _summarize(
        self,
        question: str,
        sql: str,
        rows: list[dict[str, Any]],
    ) -> str:
        """Ask the AI to summarize query results in natural language."""
        # Truncate results to avoid blowing out context window
        results_json = _truncate_results(rows, _MAX_RESULT_CHARS)

        prompt = SUMMARIZE_TEMPLATE.format(
            question=question,
            sql=sql,
            row_count=len(rows),
            results_json=results_json,
        )

        try:
            summary = await self._dispatch_ai(prompt, system=None)
            return summary.strip() or f"Query returned {len(rows)} row(s)."
        except Exception as exc:
            log.warning("NLQueryEngine: summarization failed: %s", exc)
            # Fall back to a simple count-based answer
            return f"Query returned {len(rows)} row(s). (AI summarization unavailable: {exc})"

    async def _dispatch_ai(self, prompt: str, system: str | None) -> str:
        """Route to the configured AI backend."""
        cfg = self._cfg
        tier = cfg.tier

        if tier in ("remote_micro", "remote_standard", "local"):
            return await self._client.generate(
                prompt=prompt,
                model=cfg.ollama_model,
                system=system,
            )

        if tier == "remote_api":
            if cfg.openai_api_key:
                return await self._client.generate_openai(
                    prompt=prompt,
                    model=cfg.ollama_model or "gpt-4o-mini",
                    api_key=cfg.openai_api_key,
                    system=system,
                )
            if cfg.anthropic_api_key:
                return await self._client.generate_anthropic(
                    prompt=prompt,
                    model=cfg.ollama_model or "claude-3-haiku-20240307",
                    api_key=cfg.anthropic_api_key,
                    system=system,
                )
            raise ValueError("remote_api tier requires openai_api_key or anthropic_api_key")

        if tier == "none":
            raise ValueError("AI tier is 'none'; NL query requires an AI backend.")

        raise ValueError(f"Unknown AI tier: {tier!r}")

    # ── DB helpers ───────────────────────────────────────────

    async def _log_query(
        self,
        question: str,
        generated_sql: str,
        result_summary: str,
    ) -> None:
        """Persist the query and its result to the queries table."""
        try:
            q = QueryLog(
                question=question,
                generated_sql=generated_sql,
                result_summary=result_summary,
                created_at=now_iso(),
            )
            await self._db.log_query(q)
        except Exception:
            log.exception("NLQueryEngine: failed to log query")


# ---------------------------------------------------------------------------
# SQL validation
# ---------------------------------------------------------------------------

class SQLValidationError(ValueError):
    """Raised when the AI-generated SQL fails safety validation."""


def _validate_sql(sql: str) -> None:
    """Ensure the SQL is a safe SELECT against allowed tables only.

    Raises:
        SQLValidationError: If the SQL is not a SELECT, contains mutations,
        or references tables outside the allowlist.
    """
    if not sql:
        raise SQLValidationError("AI returned an empty SQL statement.")

    if not _SELECT_RE.match(sql):
        raise SQLValidationError(
            f"Query must start with SELECT, got: {sql[:60]!r}"
        )

    if _MUTATION_RE.search(sql):
        raise SQLValidationError(
            "Query contains a disallowed mutation or DDL keyword."
        )

    # Check all referenced tables are in the allowlist
    tables_from = {m.group(1).lower() for m in _TABLE_RE.finditer(sql)}
    tables_join = {m.group(1).lower() for m in _JOIN_RE.finditer(sql)}
    # Comma-joined tables ("FROM a, b") — _TABLE_RE only captures the first
    # identifier after FROM, so without this "FROM alerts, sqlite_master"
    # would slip an un-allowlisted table (schema/other-table exfiltration).
    tables_comma: set[str] = set()
    for seg in _FROM_CLAUSE_RE.findall(sql):
        for part in seg.split(","):
            p = part.strip()
            if not p or p.startswith("("):  # subquery: its own FROM is caught above
                continue
            name = p.split()[0].strip("()")
            if name.isidentifier():
                tables_comma.add(name.lower())
    all_tables = tables_from | tables_join | tables_comma
    disallowed = all_tables - _ALLOWED_TABLES
    if disallowed:
        raise SQLValidationError(
            f"Query references disallowed table(s): {', '.join(sorted(disallowed))}"
        )

    # Block semicolons (prevent multi-statement injection)
    if ";" in sql:
        raise SQLValidationError("Multi-statement queries are not allowed.")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def translate_question_to_sql(
    question: str,
    cfg: AIConfig,
    db: AlertDB,
) -> tuple[str, str]:
    """Convenience function for the web API.

    Args:
        question: User's natural language question.
        cfg: AI configuration.
        db: Alert database.

    Returns:
        (sql, summary) tuple.
    """
    engine = NLQueryEngine(cfg, db)
    try:
        generated_sql = await engine._generate_sql(question)
        _validate_sql(generated_sql)
        rows = await db.execute_sql(generated_sql)
        if rows:
            summary = await engine._summarize(question, generated_sql, rows)
        else:
            summary = "No results found for your query."
        return generated_sql, summary
    finally:
        await engine.close()


def _strip_markdown(text: str) -> str:
    """Remove markdown code fences from AI output."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        inner = lines[1:] if len(lines) > 1 else lines
        if inner and inner[-1].strip() == "```":
            inner = inner[:-1]
        text = "\n".join(inner).strip()
    return text


def _truncate_results(rows: list[dict[str, Any]], max_chars: int) -> str:
    """Serialize rows to JSON, truncating if necessary to fit the AI context window."""
    # Trim to MAX_RESULT_ROWS first
    sample = rows[:_MAX_RESULT_ROWS]
    serialized = json.dumps(sample, indent=2, default=str)

    if len(serialized) <= max_chars:
        return serialized

    # Binary-search for how many rows fit within max_chars
    lo, hi = 1, len(sample)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        candidate = json.dumps(sample[:mid], indent=2, default=str)
        if len(candidate) <= max_chars:
            lo = mid
        else:
            hi = mid - 1

    truncated = json.dumps(sample[:lo], indent=2, default=str)
    omitted = len(rows) - lo
    if omitted > 0:
        truncated += f"\n... ({omitted} additional rows omitted for brevity)"
    return truncated
