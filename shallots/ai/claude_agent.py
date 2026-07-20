"""Claude CLI Agent for Security Shallots.

A Claude-powered security analyst that connects to shallotd's API and
autonomously triages alerts, investigates threats, and manages the
security posture.  Drop-in alternative to the Ollama-based autopilot.

Can run as:
  - Daemon mode:  Continuous loop, processes alerts in batches
  - One-shot:     Single triage pass, then exit
  - Interactive:  Human-in-the-loop via Claude Code session

Usage:
    python -m shallots.ai.claude_agent [--mode daemon|oneshot] [--interval 120]
    projects launch --profile security-ops   # interactive via Claude Code

Architecture:
    This agent uses the Anthropic SDK with tool_use to give Claude
    direct access to shallotd's REST API.  Claude sees alerts, makes
    triage decisions, creates silence rules, raises squawks, and writes
    shift reports - all through structured tool calls.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from base64 import b64encode
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("shallots.claude_agent")

# ── Status Log (for readout panel) ────────────────────────────────────────

_STATUS_FILE = Path.home() / ".shallot-claude" / "status.json"
_ACTIVITY_LOG = Path.home() / ".shallot-claude" / "activity.jsonl"


def _write_status(status: dict) -> None:
    """Write current agent status to a JSON file for external readout."""
    _STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    status["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    _STATUS_FILE.write_text(json.dumps(status, indent=2, default=str))


def _append_activity(entry: dict) -> None:
    """Append an activity log entry for the readout feed."""
    _ACTIVITY_LOG.parent.mkdir(parents=True, exist_ok=True)
    entry["timestamp"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with open(_ACTIVITY_LOG, "a") as f:
        f.write(json.dumps(entry, default=str) + "\n")
    # Keep last 200 lines
    try:
        lines = _ACTIVITY_LOG.read_text().strip().splitlines()
        if len(lines) > 200:
            _ACTIVITY_LOG.write_text("\n".join(lines[-200:]) + "\n")
    except OSError:
        pass


def read_status() -> dict:
    """Read current agent status (for external consumers)."""
    try:
        return json.loads(_STATUS_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return {"state": "unknown"}


def read_activity(limit: int = 20) -> list[dict]:
    """Read recent activity log entries."""
    try:
        lines = _ACTIVITY_LOG.read_text().strip().splitlines()
        entries = []
        for line in reversed(lines[-limit:]):
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return entries
    except OSError:
        return []


# ── Configuration ──────────────────────────────────────────────────────────

@dataclass
class AgentConfig:
    shallotd_url: str = "https://127.0.0.1:8844"
    username: str = "admin"
    password: str = ""
    model: str = "claude-sonnet-4-20250514"
    max_alerts_per_batch: int = 50
    loop_interval_seconds: int = 300
    shift_report_interval_seconds: int = 14400  # 4 hours
    verify_tls: bool = False

    @property
    def auth_header(self) -> str:
        creds = b64encode(f"{self.username}:{self.password}".encode()).decode()
        return f"Basic {creds}"


# ── Shallotd API Client ───────────────────────────────────────────────────

class ShallotdClient:
    """Thin wrapper around shallotd's REST API."""

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self._ctx = ssl.create_default_context()
        if not config.verify_tls:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    def _request(self, method: str, path: str, data: dict | None = None,
                 params: dict | None = None) -> dict | list | str:
        url = f"{self.config.shallotd_url}{path}"
        if params:
            qs = "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
            if qs:
                url += f"?{qs}"

        body = json.dumps(data).encode() if data else None
        headers = {
            "Content-Type": "application/json",
            "Authorization": self.config.auth_header,
        }

        # Retry with exponential backoff. Short timeout per attempt so a
        # flapping shallotd does not block the daemon for 30s per call.
        delays = [0.5, 1.0, 2.0]
        last_err: str = ""
        for attempt, delay in enumerate([0.0] + delays):
            if delay:
                time.sleep(delay)
            req = urllib.request.Request(url, data=body, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, context=self._ctx, timeout=10) as resp:
                    raw = resp.read().decode()
                    try:
                        return json.loads(raw)
                    except json.JSONDecodeError:
                        return raw
            except urllib.error.HTTPError as e:
                detail = e.read().decode() if e.fp else ""
                # 4xx errors are not retried; the request is malformed.
                if 400 <= e.code < 500:
                    return {"error": f"HTTP {e.code}", "detail": detail}
                last_err = f"HTTP {e.code}: {detail[:200]}"
            except Exception as e:
                last_err = str(e)
        return {"error": last_err or "request failed after retries"}

    def health(self) -> dict:
        return self._request("GET", "/api/health")

    def stats(self) -> dict:
        return self._request("GET", "/api/stats")

    def get_alerts(self, limit: int = 50, offset: int = 0,
                   severity: str | None = None, verdict: str | None = None,
                   since: str | None = None, source: str | None = None) -> dict:
        return self._request("GET", "/api/alerts", params={
            "limit": limit, "offset": offset,
            "severity": severity, "verdict": verdict,
            "since": since, "source": source,
        })

    def get_alert(self, alert_id: int) -> dict:
        return self._request("GET", f"/api/alerts/{alert_id}")

    def get_alert_context(self, alert_id: int) -> dict:
        return self._request("GET", f"/api/agent/context/{alert_id}")

    def set_verdict(self, alert_id: int, verdict: str,
                    confidence: float = 0.9, reasoning: str = "") -> dict:
        return self._request("PATCH", f"/api/alerts/{alert_id}/verdict", data={
            "verdict": verdict, "confidence": confidence, "reasoning": reasoning,
        })

    def bulk_verdict(self, alert_ids: list[int], verdict: str,
                     confidence: float = 0.9, reasoning: str = "") -> dict:
        return self._request("POST", "/api/alerts/bulk-verdict", data={
            "alert_ids": alert_ids, "verdict": verdict,
            "confidence": confidence, "reasoning": reasoning,
        })

    def search_alerts(self, query: str, limit: int = 20) -> dict:
        return self._request("GET", "/api/alerts/search", params={
            "q": query, "limit": limit,
        })

    def get_clusters(self, limit: int = 20, verdict: str | None = None) -> dict:
        return self._request("GET", "/api/clusters", params={
            "limit": limit, "verdict": verdict,
        })

    def set_cluster_verdict(self, cluster_id: int, verdict: str,
                            reasoning: str = "") -> dict:
        return self._request("PATCH", f"/api/clusters/{cluster_id}/verdict", data={
            "verdict": verdict, "reasoning": reasoning,
        })

    def get_correlations(self) -> dict:
        return self._request("GET", "/api/correlations")

    def get_incidents(self, limit: int = 10) -> dict:
        return self._request("GET", "/api/incidents", params={"limit": limit})

    def create_silence_rule(self, pattern: str, field: str = "title",
                            reason: str = "", duration_hours: int = 24) -> dict:
        return self._request("POST", "/api/silence-rules", data={
            "pattern": pattern, "field": field,
            "reason": reason, "duration_hours": duration_hours,
        })

    def get_silence_rules(self) -> dict:
        return self._request("GET", "/api/silence-rules")

    def add_squawk(self, severity: str, title: str, detail: str,
                   alert_ids: list[int] | None = None) -> dict:
        return self._request("POST", "/api/ai/squawks", data={
            "severity": severity, "title": title,
            "detail": detail, "alert_ids": alert_ids or [],
        })

    def add_shift_report(self, summary: str, detail: str,
                         stats: dict | None = None) -> dict:
        return self._request("POST", "/api/ai/reports", data={
            "summary": summary, "detail": detail, "stats": stats or {},
        })

    def get_stale_alerts(self) -> dict:
        return self._request("GET", "/api/alerts/stale")

    def get_grouped_alerts(self, verdict: str | None = None,
                           limit: int = 20) -> dict:
        return self._request("GET", "/api/alerts/grouped", params={
            "verdict": verdict, "limit": limit,
        })

    def get_agents(self) -> dict:
        return self._request("GET", "/api/agents")

    def submit_investigation(self, alert_id: int, findings: str,
                             verdict: str, iocs: list[str] | None = None) -> dict:
        return self._request("POST", "/api/agent/investigate", data={
            "alert_id": alert_id, "findings": findings,
            "verdict": verdict, "iocs": iocs or [],
        })

    def briefing(self) -> dict:
        return self._request("GET", "/api/agent/briefing")

    def get_ip_reputation(self, ip: str) -> dict:
        return self._request("GET", f"/api/reputation/{ip}")

    def block_ip(self, ip: str, reason: str = "") -> dict:
        return self._request("POST", f"/api/firewall/block/{ip}", data={
            "reason": reason,
        })


# ── Tool Definitions for Claude ───────────────────────────────────────────

TOOLS = [
    {
        "name": "get_dashboard_stats",
        "description": "Get overall dashboard statistics - alert totals, breakdowns by source/severity, pending counts. Use this first to understand the current state.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_pending_alerts",
        "description": "Get alerts awaiting triage (verdict=pending). Returns newest first. Use this to find alerts that need your attention.",
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max alerts to return (default 50)", "default": 50},
                "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"], "description": "Filter by severity"},
                "since": {"type": "string", "description": "Time window, e.g. '1h', '24h', '7d'"},
                "source": {"type": "string", "description": "Filter by source (suricata, wazuh, argus, clove, etc.)"},
            },
            "required": [],
        },
    },
    {
        "name": "get_alert_context",
        "description": "Get full enriched context for a specific alert - includes the alert details, IP reputation, related alerts, triage history, and chat history. Use this to deeply investigate an alert before making a verdict.",
        "input_schema": {
            "type": "object",
            "properties": {
                "alert_id": {"type": "integer", "description": "Alert ID to investigate"},
            },
            "required": ["alert_id"],
        },
    },
    {
        "name": "search_alerts",
        "description": "Full-text search across all alerts. Use to find patterns, similar alerts, or specific indicators.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query (FTS5 syntax)"},
                "limit": {"type": "integer", "description": "Max results", "default": 20},
            },
            "required": ["query"],
        },
    },
    {
        "name": "set_verdict",
        "description": "Set the triage verdict for a single alert. Use after investigating.",
        "input_schema": {
            "type": "object",
            "properties": {
                "alert_id": {"type": "integer"},
                "verdict": {"type": "string", "enum": ["suppress", "investigate", "escalate"]},
                "confidence": {"type": "number", "description": "0.0-1.0 confidence in verdict"},
                "reasoning": {"type": "string", "description": "Why you made this decision"},
            },
            "required": ["alert_id", "verdict", "reasoning"],
        },
    },
    {
        "name": "bulk_suppress",
        "description": "Suppress multiple alerts at once (noise). Provide a list of alert IDs and the reason they're noise.",
        "input_schema": {
            "type": "object",
            "properties": {
                "alert_ids": {"type": "array", "items": {"type": "integer"}},
                "reasoning": {"type": "string", "description": "Why these are noise"},
            },
            "required": ["alert_ids", "reasoning"],
        },
    },
    {
        "name": "get_alert_clusters",
        "description": "Get alert clusters - groups of similar alerts. Clusters with many alerts are likely noise. Use to identify patterns for bulk suppression.",
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "default": 20},
                "verdict": {"type": "string", "enum": ["pending", "suppress", "investigate", "escalate"]},
            },
            "required": [],
        },
    },
    {
        "name": "suppress_cluster",
        "description": "Suppress an entire cluster of similar alerts as noise.",
        "input_schema": {
            "type": "object",
            "properties": {
                "cluster_id": {"type": "integer"},
                "reasoning": {"type": "string"},
            },
            "required": ["cluster_id", "reasoning"],
        },
    },
    {
        "name": "create_silence_rule",
        "description": "Create a silence rule to auto-suppress future alerts matching a pattern. Use for known false positives or expected noise.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Regex pattern to match against alert title"},
                "field": {"type": "string", "enum": ["title", "src_ip", "description", "signature_id"], "default": "title"},
                "reason": {"type": "string"},
                "duration_hours": {"type": "integer", "description": "How long the rule lasts (default 24h)", "default": 24},
            },
            "required": ["pattern", "reason"],
        },
    },
    {
        "name": "raise_squawk",
        "description": "Raise a SQUAWK - a high-priority threat notice that triggers the red banner on the dashboard and alerts the operator. Only use for confirmed or highly suspicious threats.",
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["high", "critical"]},
                "title": {"type": "string", "description": "Short threat title"},
                "detail": {"type": "string", "description": "Full description of the threat and recommended action"},
                "alert_ids": {"type": "array", "items": {"type": "integer"}, "description": "Related alert IDs"},
            },
            "required": ["severity", "title", "detail"],
        },
    },
    {
        "name": "check_ip_reputation",
        "description": "Check IP reputation - returns VirusTotal, AbuseIPDB, and internal history for an IP address.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to check"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "get_correlations",
        "description": "Get AI-detected cross-alert correlation patterns - shows multi-stage attack chains and related alert groups.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_agent_status",
        "description": "Get status of all registered endpoint agents (Argus, Clove) - heartbeats, active monitors, versions.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "write_shift_report",
        "description": "Write a shift report summarizing your triage session - what you found, what you did, what needs follow-up. Do this at the end of each triage pass or every few hours.",
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string", "description": "One-line summary"},
                "detail": {"type": "string", "description": "Full report in markdown"},
            },
            "required": ["summary", "detail"],
        },
    },
    {
        "name": "submit_investigation",
        "description": "Submit detailed investigation findings for an alert - your analysis, conclusion, and any IOCs found.",
        "input_schema": {
            "type": "object",
            "properties": {
                "alert_id": {"type": "integer"},
                "findings": {"type": "string", "description": "Detailed investigation findings"},
                "verdict": {"type": "string", "enum": ["suppress", "investigate", "escalate"]},
                "iocs": {"type": "array", "items": {"type": "string"}, "description": "Indicators of Compromise found"},
            },
            "required": ["alert_id", "findings", "verdict"],
        },
    },
    {
        "name": "block_ip",
        "description": "Block an IP address at the firewall level. Only use for confirmed malicious IPs after investigation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["ip", "reason"],
        },
    },
]

# ── System Prompt ─────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are the Security Shallots AI Analyst - an autonomous security operations \
agent protecting a home/small-office network.

## Your Role
You are the 24/7 security analyst for this network. You triage alerts, \
investigate threats, suppress noise, and escalate real incidents. You run \
inside the Security Shallots platform (shallotd) which ingests alerts from \
Suricata (IDS), Wazuh (HIDS), Argus (endpoint sentinel), Clove (lightweight \
endpoint watchdog), CrowdSec, pfSense, and syslog.

## How to Work

### Triage Loop
1. **Get stats** - understand current alert volume and pending count
2. **Check pending alerts** - start with high/critical severity
3. **Investigate** - use get_alert_context for suspicious alerts, check IP reputation
4. **Decide** - suppress noise, investigate unknowns, escalate threats
5. **Batch suppress** - group obvious noise and suppress together with reasoning
6. **Create silence rules** - for recurring false positives
7. **Raise squawks** - ONLY for confirmed/high-confidence threats
8. **Write shift report** - summarize what you did

### Decision Framework
- **SUPPRESS**: Known benign, false positive, expected traffic, internal noise, \
  heartbeats, health checks, duplicate alerts
- **INVESTIGATE**: Unknown external IPs with suspicious patterns, unusual ports, \
  new attack signatures, anomalous behavior worth a closer look
- **ESCALATE**: Confirmed exploitation attempts, successful breaches, data exfil, \
  lateral movement, privilege escalation, malware indicators

### Important Rules
- Never suppress critical/high severity alerts without investigating first
- Always check IP reputation before suppressing external IP alerts
- Create silence rules for patterns, not individual alerts
- Squawks are serious - only raise them for real threats
- Write clear reasoning for every verdict (your human operator reads these)
- When in doubt, investigate rather than suppress
- Batch similar noise together for efficiency

### Network Context
This is a home/small-office network. The operator (Ben) runs security \
infrastructure including:
- Suricata IDS on the network perimeter
- Wazuh HIDS on servers
- Argus endpoint sentinel on crown-jewel machines (Windows desktop, Linux workstation)
- Clove lightweight watchdog on smaller devices
- pfSense firewall

Internal IPs (192.168.0.x) talking to each other is usually normal. \
Focus on external threats, unauthorized access, and anomalous internal behavior.
"""

# ── Tool Executor ─────────────────────────────────────────────────────────

class ToolExecutor:
    """Routes Claude's tool calls to the shallotd API."""

    def __init__(self, client: ShallotdClient) -> None:
        self.client = client

    def execute(self, tool_name: str, tool_input: dict) -> str:
        """Execute a tool call and return the result as a string."""
        try:
            result = self._dispatch(tool_name, tool_input)
            if isinstance(result, (dict, list)):
                return json.dumps(result, indent=2, default=str)
            return str(result)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def _dispatch(self, name: str, inp: dict) -> Any:
        match name:
            case "get_dashboard_stats":
                return self.client.stats()
            case "get_pending_alerts":
                return self.client.get_alerts(
                    limit=inp.get("limit", 50),
                    severity=inp.get("severity"),
                    verdict="pending",
                    since=inp.get("since"),
                    source=inp.get("source"),
                )
            case "get_alert_context":
                return self.client.get_alert_context(inp["alert_id"])
            case "search_alerts":
                return self.client.search_alerts(inp["query"], inp.get("limit", 20))
            case "set_verdict":
                return self.client.set_verdict(
                    inp["alert_id"], inp["verdict"],
                    inp.get("confidence", 0.9), inp["reasoning"],
                )
            case "bulk_suppress":
                return self.client.bulk_verdict(
                    inp["alert_ids"], "suppress",
                    0.9, inp["reasoning"],
                )
            case "get_alert_clusters":
                return self.client.get_clusters(
                    inp.get("limit", 20), inp.get("verdict"),
                )
            case "suppress_cluster":
                return self.client.set_cluster_verdict(
                    inp["cluster_id"], "suppress", inp["reasoning"],
                )
            case "create_silence_rule":
                return self.client.create_silence_rule(
                    inp["pattern"], inp.get("field", "title"),
                    inp["reason"], inp.get("duration_hours", 24),
                )
            case "raise_squawk":
                return self.client.add_squawk(
                    inp["severity"], inp["title"],
                    inp["detail"], inp.get("alert_ids", []),
                )
            case "check_ip_reputation":
                return self.client.get_ip_reputation(inp["ip"])
            case "get_correlations":
                return self.client.get_correlations()
            case "get_agent_status":
                return self.client.get_agents()
            case "write_shift_report":
                return self.client.add_shift_report(
                    inp["summary"], inp["detail"],
                )
            case "submit_investigation":
                return self.client.submit_investigation(
                    inp["alert_id"], inp["findings"],
                    inp["verdict"], inp.get("iocs", []),
                )
            case "block_ip":
                return self.client.block_ip(inp["ip"], inp.get("reason", ""))
            case _:
                return {"error": f"Unknown tool: {name}"}


# ── Agent Loop (Claude CLI - no API key needed) ──────────────────────────

def _build_cli_prompt(system: str, user_message: str) -> str:
    """Build a full prompt for claude -p (single-turn pipe mode)."""
    return f"{system}\n\n---\n\n{user_message}"


class ClaudeSecurityAgent:
    """Autonomous security analyst powered by Claude CLI.

    Uses `claude -p` (pipe mode) - same approach as the OpenKeel Command
    Center chat.  No API key needed; authenticates via the user's existing
    Claude Code OAuth session.

    Supports two backends:
      1. CLI mode (default): shells out to `claude -p`
      2. SDK mode: uses anthropic Python SDK (requires ANTHROPIC_API_KEY)
    """

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.client = ShallotdClient(config)
        self.executor = ToolExecutor(self.client)
        self._last_shift_report = time.time()
        self._use_sdk = False

        # Check if SDK is available and API key is set
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if api_key:
            try:
                import anthropic
                self._anthropic = anthropic.Anthropic()
                self._use_sdk = True
                log.info("Using Anthropic SDK (API key found)")
            except ImportError:
                log.info("anthropic package not installed, falling back to CLI")
        else:
            log.info("No ANTHROPIC_API_KEY - using Claude CLI (OAuth)")

    def run_triage_pass(self) -> dict:
        """Run a single triage pass - returns summary stats."""
        log.info("Starting triage pass...")
        _write_status({
            "state": "triaging",
            "model": self.config.model,
            "backend": "SDK" if self._use_sdk else "CLI",
            "pass_started": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        })

        if self._use_sdk:
            stats = self._run_triage_sdk()
        else:
            stats = self._run_triage_cli()

        _write_status({
            "state": "idle",
            "model": self.config.model,
            "backend": "SDK" if self._use_sdk else "CLI",
            "last_pass": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "last_stats": stats,
            "next_pass_seconds": self.config.loop_interval_seconds,
        })
        _append_activity({
            "type": "triage_pass",
            "stats": stats,
        })
        return stats

    # ── CLI backend (claude -p) ──

    def _run_triage_cli(self) -> dict:
        """Run triage using Claude CLI pipe mode."""
        import subprocess

        prompt = self._build_triage_prompt()
        full_prompt = _build_cli_prompt(SYSTEM_PROMPT, prompt)

        # Append tool instructions for CLI mode - Claude can't use tool_use
        # in pipe mode, so we use ACTION: blocks (same pattern as command center)
        full_prompt += "\n\n" + self._tool_instructions()

        # Pre-fetch dashboard stats and pending alerts so Claude has data
        stats_data = self.client.stats()
        pending = self.client.get_alerts(
            limit=self.config.max_alerts_per_batch, verdict="pending",
        )

        full_prompt += f"\n\n## Current Dashboard Stats\n```json\n{json.dumps(stats_data, indent=2, default=str)[:3000]}\n```"

        if isinstance(pending, dict) and "alerts" in pending:
            alerts = pending["alerts"][:self.config.max_alerts_per_batch]
            # Trim alerts for context window
            trimmed = []
            for a in alerts:
                trimmed.append({
                    "id": a.get("id"),
                    "severity": a.get("severity"),
                    "title": a.get("title"),
                    "src_ip": a.get("src_ip"),
                    "dst_ip": a.get("dst_ip"),
                    "source": a.get("source"),
                    "category": a.get("category"),
                    "timestamp": a.get("timestamp"),
                    "verdict": a.get("verdict"),
                })
            full_prompt += f"\n\n## Pending Alerts ({len(trimmed)} shown)\n```json\n{json.dumps(trimmed, indent=2, default=str)[:8000]}\n```"

        stats = {"verdicts_set": 0, "alerts_processed": 0, "squawks_raised": 0,
                 "silence_rules_created": 0, "tool_calls": 0}

        # Hard cap prompt size. If alerts have grown unbounded enrichment
        # data, the CLI subprocess can OOM or hit the 300s timeout. Fail
        # fast and emit an empty pass instead of spinning for 5 minutes.
        MAX_PROMPT_BYTES = 40_000
        if len(full_prompt) > MAX_PROMPT_BYTES:
            log.error(
                "Triage prompt %d bytes exceeds %d cap - skipping pass. "
                "Likely cause: alerts with bloated enrichment / chat / triage history.",
                len(full_prompt), MAX_PROMPT_BYTES,
            )
            return stats

        log.info("Sending triage prompt to Claude CLI (%d chars)...", len(full_prompt))

        try:
            proc = subprocess.run(
                ["claude", "-p", "--model", self.config.model,
                 "--no-session-persistence"],
                input=full_prompt,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except FileNotFoundError:
            log.error("Claude CLI not found. Install: npm install -g @anthropic-ai/claude-code")
            return stats
        except subprocess.TimeoutExpired:
            log.error("Claude CLI timed out after 300s")
            return stats

        response = (proc.stdout or "").strip()
        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            log.error("Claude CLI error (rc=%d): %s", proc.returncode, stderr[:500])
            return stats

        log.info("Claude response (%d chars), parsing actions...", len(response))

        # Parse and execute ACTION: blocks from the response
        stats = self._parse_and_execute_actions(response, stats)
        return stats

    def _tool_instructions(self) -> str:
        """Instructions for CLI mode - Claude emits ACTION: blocks."""
        return """\
## How to Take Actions

To execute actions, emit ACTION blocks in your response. Each action will be
automatically executed against the shallotd API. You can emit multiple actions.

### Available Actions

**Suppress a single alert:**
ACTION:SET_VERDICT{"alert_id": 123, "verdict": "suppress", "reasoning": "why"}

**Investigate an alert:**
ACTION:SET_VERDICT{"alert_id": 123, "verdict": "investigate", "reasoning": "why"}

**Escalate an alert:**
ACTION:SET_VERDICT{"alert_id": 123, "verdict": "escalate", "reasoning": "why"}

**Bulk suppress multiple alerts:**
ACTION:BULK_SUPPRESS{"alert_ids": [1,2,3], "reasoning": "why these are noise"}

**Suppress an entire cluster:**
ACTION:SUPPRESS_CLUSTER{"cluster_id": 5, "reasoning": "why"}

**Create a silence rule (auto-suppress future matches):**
ACTION:SILENCE_RULE{"pattern": "regex pattern", "field": "title", "reason": "why", "duration_hours": 24}

**Raise a SQUAWK (critical threat alert to operator):**
ACTION:SQUAWK{"severity": "critical", "title": "short title", "detail": "full description", "alert_ids": [1,2]}

**Write a shift report:**
ACTION:SHIFT_REPORT{"summary": "one line", "detail": "full markdown report"}

**Check IP reputation (results shown inline):**
ACTION:CHECK_IP{"ip": "1.2.3.4"}

**Block an IP at the firewall:**
ACTION:BLOCK_IP{"ip": "1.2.3.4", "reason": "why"}

### Rules
- Always include reasoning for verdicts
- Batch similar noise with BULK_SUPPRESS
- Only SQUAWK for confirmed/high-confidence threats
- Create SILENCE_RULE for recurring false positives
- Write SHIFT_REPORT at end of triage session
"""

    def _parse_and_execute_actions(self, response: str, stats: dict) -> dict:
        """Parse ACTION: blocks from Claude's response and execute them."""
        import re

        action_pattern = re.compile(r'ACTION:(\w+)(\{[^}]+\})', re.MULTILINE)

        for match in action_pattern.finditer(response):
            action_type = match.group(1)
            try:
                payload = json.loads(match.group(2))
            except json.JSONDecodeError:
                log.warning("Failed to parse action payload: %s", match.group(2)[:200])
                continue

            stats["tool_calls"] += 1
            log.info("Executing action: %s %s", action_type, json.dumps(payload, default=str)[:200])
            _append_activity({
                "type": "action",
                "action": action_type,
                "payload_summary": json.dumps(payload, default=str)[:300],
            })

            try:
                if action_type == "SET_VERDICT":
                    self.client.set_verdict(
                        payload["alert_id"], payload["verdict"],
                        payload.get("confidence", 0.9), payload.get("reasoning", ""),
                    )
                    stats["verdicts_set"] += 1

                elif action_type == "BULK_SUPPRESS":
                    ids = payload.get("alert_ids", [])
                    self.client.bulk_verdict(ids, "suppress", 0.9, payload.get("reasoning", ""))
                    stats["verdicts_set"] += len(ids)

                elif action_type == "SUPPRESS_CLUSTER":
                    self.client.set_cluster_verdict(
                        payload["cluster_id"], "suppress", payload.get("reasoning", ""),
                    )
                    stats["verdicts_set"] += 1

                elif action_type == "SILENCE_RULE":
                    self.client.create_silence_rule(
                        payload["pattern"], payload.get("field", "title"),
                        payload.get("reason", ""), payload.get("duration_hours", 24),
                    )
                    stats["silence_rules_created"] += 1

                elif action_type == "SQUAWK":
                    self.client.add_squawk(
                        payload["severity"], payload["title"],
                        payload["detail"], payload.get("alert_ids", []),
                    )
                    stats["squawks_raised"] += 1
                    _append_activity({
                        "type": "squawk",
                        "severity": payload["severity"],
                        "title": payload["title"],
                    })

                elif action_type == "SHIFT_REPORT":
                    self.client.add_shift_report(
                        payload["summary"], payload["detail"],
                    )
                    _append_activity({
                        "type": "shift_report",
                        "summary": payload["summary"],
                    })

                elif action_type == "CHECK_IP":
                    result = self.client.get_ip_reputation(payload["ip"])
                    log.info("IP reputation for %s: %s", payload["ip"],
                             json.dumps(result, default=str)[:300])

                elif action_type == "BLOCK_IP":
                    self.client.block_ip(payload["ip"], payload.get("reason", ""))

                elif action_type == "GET_ALERT_CONTEXT":
                    result = self.client.get_alert_context(payload["alert_id"])
                    log.info("Alert context for %s: %s", payload["alert_id"],
                             json.dumps(result, default=str)[:500])

                elif action_type == "GET_PENDING_ALERTS":
                    result = self.client.get_alerts(
                        limit=payload.get("limit", 50),
                        severity=payload.get("severity"),
                        verdict="pending",
                        since=payload.get("since"),
                    )
                    log.info("Pending alerts: %s",
                             json.dumps(result, default=str)[:500])

                elif action_type == "GET_CLUSTERS":
                    result = self.client.get_clusters(
                        payload.get("limit", 20), payload.get("verdict"),
                    )
                    log.info("Clusters: %s",
                             json.dumps(result, default=str)[:500])

                else:
                    log.warning("Unknown action type: %s", action_type)

            except Exception as e:
                log.error("Action %s failed: %s", action_type, e)

        stats["alerts_processed"] = stats["verdicts_set"]
        return stats

    # ── SDK backend (Anthropic API) ──

    def _run_triage_sdk(self) -> dict:
        """Run triage using Anthropic SDK (requires API key)."""
        prompt = self._build_triage_prompt()
        messages = [{"role": "user", "content": prompt}]
        stats = {"verdicts_set": 0, "alerts_processed": 0, "squawks_raised": 0,
                 "silence_rules_created": 0, "tool_calls": 0}

        max_turns = 30
        for turn in range(max_turns):
            response = self._anthropic.messages.create(
                model=self.config.model,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                tools=TOOLS,
                messages=messages,
            )

            if response.stop_reason == "tool_use":
                tool_results = []
                for block in response.content:
                    if block.type == "tool_use":
                        stats["tool_calls"] += 1
                        result = self.executor.execute(block.name, block.input)

                        if block.name == "set_verdict":
                            stats["verdicts_set"] += 1
                        elif block.name == "bulk_suppress":
                            stats["verdicts_set"] += len(block.input.get("alert_ids", []))
                        elif block.name == "raise_squawk":
                            stats["squawks_raised"] += 1
                        elif block.name == "create_silence_rule":
                            stats["silence_rules_created"] += 1

                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result[:10000],
                        })

                messages.append({"role": "assistant", "content": response.content})
                messages.append({"role": "user", "content": tool_results})

            elif response.stop_reason == "end_turn":
                final_text = ""
                for block in response.content:
                    if hasattr(block, "text"):
                        final_text += block.text
                log.info("Triage pass complete: %s", final_text[:500])
                break

        stats["alerts_processed"] = stats["verdicts_set"]
        return stats

    # ── Shared ──

    def _build_triage_prompt(self) -> str:
        """Build the prompt for a triage pass."""
        elapsed = time.time() - self._last_shift_report
        shift_report_due = elapsed >= self.config.shift_report_interval_seconds

        prompt = (
            "Run a triage pass on the Security Shallots alert queue. "
            "Start by getting the dashboard stats to understand the current state, "
            "then work through pending alerts starting with the highest severity. "
            "Be efficient - batch-suppress obvious noise, investigate anything "
            "suspicious, and escalate real threats. "
        )

        if shift_report_due:
            prompt += (
                "A shift report is due - after triaging, write a shift report "
                "summarizing what you found and did. "
            )
            self._last_shift_report = time.time()

        prompt += (
            "When you're done triaging the current batch, say so and summarize "
            "your actions."
        )
        return prompt

    def run_daemon(self) -> None:
        """Run continuously, triaging alerts on a loop."""
        backend = "SDK" if self._use_sdk else "CLI"
        log.info("Claude Security Agent starting in daemon mode "
                 "(backend=%s, interval=%ds, model=%s)",
                 backend, self.config.loop_interval_seconds, self.config.model)
        _write_status({
            "state": "starting",
            "model": self.config.model,
            "backend": backend,
        })
        _append_activity({"type": "startup", "model": self.config.model, "backend": backend})

        # Verify connectivity (non-fatal - will retry each pass)
        health = self.client.health()
        if "error" in health:
            log.warning("Cannot reach shallotd yet: %s (will retry)", health["error"])
            _write_status({
                "state": "waiting",
                "model": self.config.model,
                "backend": backend,
                "error": str(health.get("error", "")),
            })
        else:
            log.info("Connected to shallotd - %s total alerts", health.get("total_alerts"))

        # Circuit breaker: if shallotd is unreachable or passes keep
        # failing, back off exponentially instead of hammering shallotd every
        # loop_interval_seconds. This is the failure mode that has
        # historically taken the system down.
        consecutive_failures = 0
        MAX_BACKOFF_SECONDS = 1800  # 30 min ceiling
        FAILURE_DISABLE_THRESHOLD = 10

        while True:
            try:
                stats = self.run_triage_pass()
                log.info("Pass complete: %s", json.dumps(stats))
                consecutive_failures = 0
            except KeyboardInterrupt:
                log.info("Shutting down...")
                break
            except Exception:
                consecutive_failures += 1
                log.exception("Triage pass failed (consecutive=%d)", consecutive_failures)

            # Probe shallotd cheaply; if it is unreachable, count this as
            # a failure even if the pass logic itself did not raise.
            health = self.client.health()
            if isinstance(health, dict) and "error" in health:
                consecutive_failures += 1
                log.warning(
                    "shallotd unreachable: %s (consecutive=%d)",
                    health.get("error"), consecutive_failures,
                )

            if consecutive_failures >= FAILURE_DISABLE_THRESHOLD:
                log.error(
                    "Disabling agent after %d consecutive failures - manual restart required.",
                    consecutive_failures,
                )
                _write_status({
                    "state": "disabled",
                    "reason": f"{consecutive_failures} consecutive failures",
                    "model": self.config.model,
                    "backend": backend,
                })
                break

            if consecutive_failures > 0:
                # 1x, 2x, 4x, 8x, ... loop_interval, capped at MAX_BACKOFF_SECONDS.
                sleep_s = min(
                    MAX_BACKOFF_SECONDS,
                    self.config.loop_interval_seconds * (2 ** (consecutive_failures - 1)),
                )
            else:
                sleep_s = self.config.loop_interval_seconds

            log.info("Sleeping %ds until next pass...", sleep_s)
            try:
                time.sleep(sleep_s)
            except KeyboardInterrupt:
                log.info("Shutting down...")
                break


# ── System Prompt Generator (for Claude Code interactive mode) ────────────

def generate_claude_md(config: AgentConfig) -> str:
    """Generate a CLAUDE.md block for interactive Claude Code sessions."""
    return f"""\
## Security Shallots - AI Analyst Mode

You are operating as the Security Shallots AI Analyst. Your job is to protect
this network by triaging security alerts from the shallotd platform.

### API Access
Shallotd is running at `{config.shallotd_url}`.
Auth: `{config.username}` / (configured)

Use curl to interact with the API. All endpoints require auth:
```bash
curl -sk -u {config.username}:PASSWORD {config.shallotd_url}/api/ENDPOINT
```

### Key Endpoints
- `GET /api/stats` - Dashboard stats
- `GET /api/alerts?verdict=pending&limit=50` - Pending alerts
- `GET /api/agent/context/{{id}}` - Full alert context with enrichment
- `PATCH /api/alerts/{{id}}/verdict` - Set verdict (suppress/investigate/escalate)
- `POST /api/alerts/bulk-verdict` - Bulk verdict
- `GET /api/alerts/search?q=QUERY` - Full-text search
- `GET /api/clusters?verdict=pending` - Alert clusters
- `POST /api/silence-rules` - Create silence rule
- `POST /api/ai/squawks` - Raise threat alert
- `GET /api/reputation/{{ip}}` - IP reputation lookup
- `POST /api/ai/reports` - Write shift report
- `GET /api/agents` - Endpoint agent status

### Your Protocol
1. Check stats first
2. Triage high/critical pending alerts
3. Batch suppress obvious noise
4. Investigate suspicious alerts (check IP rep, context)
5. Escalate confirmed threats
6. Create silence rules for recurring FPs
7. Write shift report when done
"""


# ── CLI Entry Point ──────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Claude Security Agent for Security Shallots"
    )
    parser.add_argument("--mode", choices=["daemon", "oneshot", "generate-claude-md"],
                        default="daemon")
    parser.add_argument("--url", default=os.environ.get(
        "SHALLOTD_URL", "https://127.0.0.1:8844"))
    parser.add_argument("--user", default=os.environ.get("SHALLOTD_USER", "admin"))
    parser.add_argument("--password", default=os.environ.get("SHALLOTD_PASSWORD", ""))
    parser.add_argument("--model", default=os.environ.get(
        "CLAUDE_MODEL", "claude-sonnet-4-20250514"))
    parser.add_argument("--interval", type=int, default=300,
                        help="Seconds between triage passes (daemon mode)")
    parser.add_argument("--max-alerts", type=int, default=50,
                        help="Max alerts per triage batch")
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    config = AgentConfig(
        shallotd_url=args.url,
        username=args.user,
        password=args.password,
        model=args.model,
        loop_interval_seconds=args.interval,
        max_alerts_per_batch=args.max_alerts,
    )

    if args.mode == "generate-claude-md":
        print(generate_claude_md(config))
        return

    agent = ClaudeSecurityAgent(config)

    if args.mode == "oneshot":
        stats = agent.run_triage_pass()
        print(json.dumps(stats, indent=2))
    else:
        agent.run_daemon()


if __name__ == "__main__":
    main()
