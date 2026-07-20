"""OAuth-backed Claude brain for the escalation ladder.

The ladder's upper tiers (Haiku / Sonnet / Opus) run through the operator's
Claude Code **OAuth subscription** rather than a metered API key. We shell out
to the ``claude`` CLI in headless mode:

    claude -p "<prompt>" --model <haiku|sonnet|opus> --output-format json

Why the CLI (Method A) and not raw ``POST /v1/messages`` with the bearer token
(Method B)?  The CLI **auto-refreshes the short-lived OAuth access token** on
every invocation and persists it back to ``~/.claude/.credentials.json``. That
is precisely the "automatically deal with token expiry" requirement: because the
ladder calls Claude on a fixed cadence (10 min / 1 h / 4 h), the refresh token
keeps rolling and never idle-expires. Model *aliases* (haiku/sonnet/opus) also
resolve to the latest model server-side, so there are no model IDs to rot.

This module is deliberately dependency-free (stdlib only) and synchronous — the
ladder tiers are short-lived timer processes, not part of the async daemon.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass

log = logging.getLogger(__name__)

# Recognisable substrings in CLI output/stderr that mean "the OAuth token is
# stale / auth failed" — triggers a refresh-poke and one retry.
_AUTH_FAIL_MARKERS = (
    "401",
    "unauthorized",
    "authentication",
    "invalid_token",
    "expired",
    "please run /login",
    "not logged in",
    "credentials",
)


class BrainError(RuntimeError):
    """Raised when a Claude call cannot be completed (after retries)."""


class BrainAuthError(BrainError):
    """Raised specifically when the failure looks like an auth/token problem."""


@dataclass
class BrainResult:
    text: str
    model: str
    latency_ms: int
    cost_usd: float = 0.0
    session_id: str = ""
    raw: dict | None = None


class OAuthBrain:
    """Calls Claude models through the local Claude Code OAuth login.

    Parameters
    ----------
    claude_bin:
        Path to (or name of) the ``claude`` executable. Resolved on ``PATH`` if
        a bare name is given.
    creds_path:
        Path to the Claude Code credential store, used only to *proactively*
        poke a refresh when the access token is within ``refresh_margin_sec`` of
        expiry. The CLI still refreshes on its own; this just avoids a wasted
        first call on a cold, long-idle token.
    """

    def __init__(
        self,
        claude_bin: str = "claude",
        creds_path: str = "~/.claude/.credentials.json",
        refresh_margin_sec: int = 300,
        workdir: str | None = None,
    ) -> None:
        self.claude_bin = shutil.which(claude_bin) or claude_bin
        self.creds_path = os.path.expanduser(creds_path)
        self.refresh_margin_sec = refresh_margin_sec
        # Run in an empty scratch dir so the CLI never picks up a project's
        # CLAUDE.md / files / MCP config and never tries to touch the cwd.
        self.workdir = workdir or "/tmp"

    # ── availability / self-test ─────────────────────────────────────────

    def available(self) -> bool:
        return bool(shutil.which(self.claude_bin) or os.path.exists(self.claude_bin))

    def creds_expiry_epoch(self) -> float | None:
        """Return the access-token expiry (unix seconds) if readable, else None."""
        try:
            with open(self.creds_path) as fh:
                oauth = json.load(fh).get("claudeAiOauth", {})
            exp = oauth.get("expiresAt")
            return (exp / 1000.0) if exp else None
        except Exception:
            return None

    def self_test(self) -> BrainResult:
        """Cheap end-to-end auth check. Raises BrainAuthError on failure."""
        return self.ask("haiku", system="", user="Reply with exactly: LADDER_OK",
                        max_tokens=16, expect_json=False, timeout=90)

    # ── token freshness ──────────────────────────────────────────────────

    def _poke_refresh(self) -> None:
        """Force the CLI to refresh & persist the OAuth token."""
        try:
            subprocess.run(
                [self.claude_bin, "-p", "ok", "--model", "haiku",
                 "--output-format", "text"],
                capture_output=True, text=True, timeout=90, cwd=self.workdir,
            )
            log.info("oauth_brain: refreshed OAuth token via CLI poke")
        except Exception as exc:  # noqa: BLE001
            log.warning("oauth_brain: refresh poke failed: %s", exc)

    def _maybe_refresh(self) -> None:
        exp = self.creds_expiry_epoch()
        if exp is not None and (exp - time.time()) < self.refresh_margin_sec:
            self._poke_refresh()

    # ── core call ────────────────────────────────────────────────────────

    def ask(
        self,
        model: str,
        system: str,
        user: str,
        max_tokens: int = 2048,
        expect_json: bool = True,
        timeout: int = 180,
    ) -> BrainResult:
        """Call a Claude model. ``model`` is an alias: haiku|sonnet|opus.

        The system prompt is folded into the printed prompt (headless ``-p`` has
        no separate system role). Returns a BrainResult; ``.text`` is the model's
        answer. Raises BrainError / BrainAuthError on failure.
        """
        self._maybe_refresh()
        prompt = (system.strip() + "\n\n" + user.strip()) if system.strip() else user.strip()

        try:
            return self._invoke(model, prompt, timeout)
        except BrainAuthError:
            # One shot at self-healing a stale token, then retry.
            log.warning("oauth_brain: auth failure on %s — poking refresh + retry", model)
            self._poke_refresh()
            return self._invoke(model, prompt, timeout)

    def _invoke(self, model: str, prompt: str, timeout: int) -> BrainResult:
        t0 = time.time()
        # SECURITY: alert titles/log excerpts (attacker-writable) are in the prompt.
        # --dangerously-skip-permissions would leave the CLI's default tools ENABLED
        # with no gate = prompt-injection -> tool execution. Instead disable every
        # tool (nothing to permit -> no headless hang) and cap to a single turn.
        cmd = [
            self.claude_bin, "-p", prompt,
            "--model", model,
            "--output-format", "json",
            "--disallowed-tools", "Bash", "Edit", "Write", "Read", "WebFetch",
            "WebSearch", "Glob", "Grep", "NotebookEdit", "Task",
            "--max-turns", "1",
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, cwd=self.workdir,
            )
        except subprocess.TimeoutExpired as exc:
            raise BrainError(f"claude CLI timed out after {timeout}s ({model})") from exc
        except FileNotFoundError as exc:
            raise BrainError(
                f"claude CLI not found at '{self.claude_bin}'. Install it and log in "
                "on this host (see ladder setup)."
            ) from exc

        latency_ms = int((time.time() - t0) * 1000)
        out, err = proc.stdout.strip(), proc.stderr.strip()

        if proc.returncode != 0 or not out:
            blob = (out + " " + err).lower()
            if any(m in blob for m in _AUTH_FAIL_MARKERS):
                raise BrainAuthError(f"auth/token failure ({model}): {err[:200] or out[:200]}")
            raise BrainError(f"claude CLI rc={proc.returncode} ({model}): {err[:300] or out[:300]}")

        # --output-format json → envelope: {type, result, usage, total_cost_usd, ...}
        try:
            env = json.loads(out)
        except json.JSONDecodeError:
            # Some CLI versions print the answer directly; treat as text.
            env = {"result": out}

        if isinstance(env, dict) and env.get("is_error"):
            blob = json.dumps(env).lower()
            if any(m in blob for m in _AUTH_FAIL_MARKERS):
                raise BrainAuthError(f"auth failure in envelope ({model})")
            raise BrainError(f"claude reported error ({model}): {str(env.get('result'))[:300]}")

        text = env.get("result", "") if isinstance(env, dict) else str(env)
        return BrainResult(
            text=text,
            model=model,
            latency_ms=latency_ms,
            cost_usd=float(env.get("total_cost_usd", 0.0) or 0.0) if isinstance(env, dict) else 0.0,
            session_id=env.get("session_id", "") if isinstance(env, dict) else "",
            raw=env if isinstance(env, dict) else None,
        )

    # ── JSON helper ──────────────────────────────────────────────────────

    def ask_json(
        self,
        model: str,
        system: str,
        user: str,
        max_tokens: int = 2048,
        timeout: int = 180,
    ) -> dict:
        """Like ``ask`` but parses the model's answer as a JSON object.

        Tolerates code fences and surrounding prose by extracting the first
        balanced ``{...}`` block. Raises BrainError if no object is found.
        """
        res = self.ask(model, system, user, max_tokens, expect_json=True, timeout=timeout)
        obj = _extract_json_object(res.text)
        if obj is None:
            raise BrainError(f"{model} did not return a JSON object: {res.text[:200]!r}")
        obj["_meta"] = {
            "model": res.model,
            "latency_ms": res.latency_ms,
            "cost_usd": res.cost_usd,
        }
        return obj


_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


def _extract_json_object(text: str) -> dict | None:
    """Best-effort extraction of a single JSON object from model output."""
    if not text:
        return None
    candidates: list[str] = []
    m = _FENCE_RE.search(text)
    if m:
        candidates.append(m.group(1))
    candidates.append(text)

    for cand in candidates:
        cand = cand.strip()
        # Fast path
        try:
            obj = json.loads(cand)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
        # Balanced-brace scan
        start = cand.find("{")
        while start != -1:
            depth = 0
            in_str = False
            esc = False
            for i in range(start, len(cand)):
                ch = cand[i]
                if in_str:
                    if esc:
                        esc = False
                    elif ch == "\\":
                        esc = True
                    elif ch == '"':
                        in_str = False
                    continue
                if ch == '"':
                    in_str = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        blob = cand[start:i + 1]
                        try:
                            obj = json.loads(blob)
                            if isinstance(obj, dict):
                                return obj
                        except json.JSONDecodeError:
                            break
            start = cand.find("{", start + 1)
    return None
