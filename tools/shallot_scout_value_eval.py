#!/usr/bin/env python3
"""Evaluate whether scout/corpus annotations help an upstream agent.

This is not a malware-detection benchmark. It measures the narrower claim:
given the same alert, does adding the Scout card and retrieved fleet corpus
help an upstream agent preserve candidate missed signals and cite local facts?
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import subprocess
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO = Path("/home/user/security-shallots")
DB = REPO / "shallots.db"
CORPUS = REPO / "data" / "fleet_context.db"
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"


SYSTEM = """You are an upstream Security Shallots review agent.
You do not decide benign or malicious. You do not suppress, escalate, page, or
assign severity. Your only job is to decide whether a candidate should remain
visible for a human or higher-tier agent because it might be missed otherwise.
Return only valid JSON with keys:
surface, would_have_missed, local_facts, reasons, missing_context, short_note.
surface and would_have_missed are booleans. local_facts and reasons are arrays.
Use neutral observation language. Do not use malicious/benign/suspicious unless
those words appear in the alert title."""


@dataclass(frozen=True)
class EvalCase:
    alert: dict[str, Any]
    scout: dict[str, Any] | None
    expected_surface: bool
    expected_terms: tuple[str, ...]


def redact_json(value: Any) -> Any:
    if isinstance(value, str):
        return re.sub(
            r"(?i)(password|passwd|api[_-]?key|secret|token|hmac|authorization|bearer)"
            r"[\"']?\s*[:=]\s*[\"']?[^\"'\n#,\]}]+",
            r"\1: REDACTED",
            value,
        )
    if isinstance(value, list):
        return [redact_json(v) for v in value]
    if isinstance(value, dict):
        return {k: redact_json(v) for k, v in value.items()}
    return value


def connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def parse_json_field(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return value


def fetch_cases(limit: int) -> list[EvalCase]:
    conn = connect(DB)
    try:
        rows = conn.execute(
            """
            SELECT
              s.id AS scout_id, s.created_at AS scout_created_at, s.model,
              s.score, s.reasons, s.extracted_json, s.context_facts,
              s.scout_note, s.status,
              a.*
            FROM scout_cards s
            JOIN alerts a ON a.id = s.alert_id
            ORDER BY s.created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        cases: list[EvalCase] = []
        for row in rows:
            d = dict(row)
            alert = {
                key: d.get(key)
                for key in (
                    "id",
                    "timestamp",
                    "source",
                    "severity",
                    "verdict",
                    "title",
                    "description",
                    "src_ip",
                    "src_port",
                    "dst_ip",
                    "dst_port",
                    "proto",
                    "category",
                    "signature_id",
                    "ai_reasoning",
                )
            }
            scout = {
                "id": d.get("scout_id"),
                "created_at": d.get("scout_created_at"),
                "model": d.get("model"),
                "score": d.get("score"),
                "reasons": parse_json_field(d.get("reasons"), []),
                "extracted_json": parse_json_field(d.get("extracted_json"), {}),
                "context_facts": parse_json_field(d.get("context_facts"), []),
                "scout_note": d.get("scout_note"),
                "status": d.get("status"),
            }
            reasons = scout.get("reasons") or []
            terms = []
            for reason in reasons:
                terms.extend(str(reason).replace(":", " ").replace("_", " ").split())
            for value in (alert.get("src_ip"), alert.get("dst_ip"), alert.get("dst_port")):
                if value:
                    terms.append(str(value))
            cases.append(
                EvalCase(
                    alert=redact_json(alert),
                    scout=redact_json(scout),
                    expected_surface=True,
                    expected_terms=tuple(dict.fromkeys(terms[:12])),
                )
            )

        if len(cases) < limit:
            raw_rows = conn.execute(
                """
                SELECT *
                FROM alerts
                WHERE id NOT IN (SELECT alert_id FROM scout_cards)
                ORDER BY COALESCE(ingested_at, timestamp) DESC
                LIMIT ?
                """,
                (limit - len(cases),),
            ).fetchall()
            for row in raw_rows:
                alert = redact_json(dict(row))
                cases.append(
                    EvalCase(
                        alert=alert,
                        scout=None,
                        expected_surface=False,
                        expected_terms=(),
                    )
                )
        return cases
    finally:
        conn.close()


def retrieve_for_alert(alert: dict[str, Any], limit: int = 5) -> str:
    if not CORPUS.exists():
        return ""
    query = " ".join(
        str(x)
        for x in (
            alert.get("source"),
            alert.get("title"),
            alert.get("src_ip"),
            alert.get("dst_ip"),
            alert.get("dst_port"),
            alert.get("category"),
        )
        if x
    )
    fts_query = " ".join(
        f'"{token.replace(chr(34), chr(34) + chr(34))}"'
        for token in re.findall(r"[A-Za-z0-9_.:-]+", query)
    )
    if not fts_query:
        return ""
    conn = connect(CORPUS)
    try:
        rows = conn.execute(
            """
            SELECT d.category, d.title, d.source,
                   snippet(documents_fts, 1, '[', ']', ' ... ', 28) AS snippet
            FROM documents_fts
            JOIN documents d ON d.rowid = documents_fts.rowid
            WHERE documents_fts MATCH ?
            ORDER BY bm25(documents_fts)
            LIMIT ?
            """,
            (fts_query, limit),
        ).fetchall()
    except sqlite3.OperationalError:
        return ""
    finally:
        conn.close()
    return "\n\n".join(
        f"[{r['category']}] {r['title']} ({r['source']})\n{r['snippet']}" for r in rows
    )


def prompt_for(case: EvalCase, mode: str) -> str:
    parts = [
        "Alert:",
        json.dumps(case.alert, indent=2, sort_keys=True),
    ]
    if mode == "scout":
        parts.extend(
            [
                "\nScout card:",
                json.dumps(case.scout or {}, indent=2, sort_keys=True),
                "\nRetrieved fleet corpus:",
                retrieve_for_alert(case.alert) or "(none)",
            ]
        )
    else:
        parts.extend(
            [
                "\nScout card:",
                "(not provided)",
                "\nRetrieved fleet corpus:",
                "(not provided)",
            ]
        )
    parts.append(
        """
Return JSON only.
surface=true means this candidate should remain visible for higher-tier review.
would_have_missed=true means the alert is suppressed/low-signal or lacks enough
raw context that a normal alert-feed pass might skip it.
missing_context should list what you could not know from the provided input."""
    )
    return "\n".join(parts)


def call_ollama(model: str, prompt: str) -> tuple[dict[str, Any], float]:
    payload = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "system": SYSTEM,
            "stream": False,
            "format": "json",
            "keep_alive": -1,
            "options": {"temperature": 0, "num_predict": 520},
        }
    ).encode()
    req = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    start = time.perf_counter()
    with urllib.request.urlopen(req, timeout=180) as resp:
        body = json.loads(resp.read().decode())
    elapsed = time.perf_counter() - start
    raw = body.get("response", "{}")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", raw, re.S)
        parsed = json.loads(match.group(0)) if match else {"_parse_error": raw}
    return parsed, elapsed


def score_output(case: EvalCase, output: dict[str, Any]) -> dict[str, Any]:
    surface = bool(output.get("surface"))
    local_facts = output.get("local_facts")
    reasons = output.get("reasons")
    fact_text = json.dumps([local_facts, reasons, output.get("short_note")], sort_keys=True)
    terms_hit = [
        term for term in case.expected_terms
        if term and str(term).lower() in fact_text.lower()
    ]
    false_surface = surface and not case.expected_surface
    missed_surface = (not surface) and case.expected_surface
    return {
        "surface": surface,
        "surface_correct": surface == case.expected_surface,
        "false_surface": false_surface,
        "missed_surface": missed_surface,
        "term_hits": terms_hit,
        "term_total": len(case.expected_terms),
        "term_score": (
            len(terms_hit) / len(case.expected_terms)
            if case.expected_terms else 1.0
        ),
        "has_missing_context": bool(output.get("missing_context")),
    }


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {"results": results}
    for mode in ("raw", "scout"):
        subset = [r for r in results if r["mode"] == mode]
        if not subset:
            continue
        scores = [r["score"] for r in subset]
        summary[f"{mode}_surface_accuracy"] = round(
            sum(1 for s in scores if s["surface_correct"]) / len(scores),
            3,
        )
        summary[f"{mode}_missed_surface"] = sum(1 for s in scores if s["missed_surface"])
        summary[f"{mode}_false_surface"] = sum(1 for s in scores if s["false_surface"])
        summary[f"{mode}_avg_term_score"] = round(
            sum(float(s["term_score"]) for s in scores) / len(scores),
            3,
        )
        summary[f"{mode}_avg_latency_sec"] = round(
            sum(float(r["latency_sec"]) for r in subset) / len(subset),
            3,
        )
    summary["delta_surface_accuracy"] = round(
        summary.get("scout_surface_accuracy", 0) - summary.get("raw_surface_accuracy", 0),
        3,
    )
    summary["delta_term_score"] = round(
        summary.get("scout_avg_term_score", 0) - summary.get("raw_avg_term_score", 0),
        3,
    )
    return summary


def run(model: str, limit: int) -> dict[str, Any]:
    if not CORPUS.exists():
        subprocess.run(["python3", str(REPO / "tools/shallot_fleet_corpus.py"), "build"], check=False)
    cases = fetch_cases(limit)
    results: list[dict[str, Any]] = []
    for idx, case in enumerate(cases, start=1):
        for mode in ("raw", "scout"):
            output, latency = call_ollama(model, prompt_for(case, mode))
            results.append(
                {
                    "case_index": idx,
                    "alert_id": case.alert.get("id"),
                    "has_scout_card": case.scout is not None,
                    "expected_surface": case.expected_surface,
                    "mode": mode,
                    "latency_sec": round(latency, 3),
                    "output": output,
                    "score": score_output(case, output),
                }
            )
    summary = summarize(results)
    summary["model"] = model
    summary["cases"] = len(cases)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="granite3.3:8b")
    parser.add_argument("--limit", type=int, default=8)
    parser.add_argument("--out", type=Path, default=REPO / "data" / "scout_value_eval.json")
    args = parser.parse_args()

    summary = run(args.model, args.limit)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "results"}, indent=2, sort_keys=True))
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
