#!/usr/bin/env python3
"""Run authenticated Argus canaries and score them with Scout.

This exercises the real Shallots HTTP ingest path, then runs the Scout scoring
logic directly against the live DB. It does not perform scans or exploit tests.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sqlite3
import ssl
import subprocess
import time
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shallots.ai.scout import ScoutWorker
from shallots.config import load_config


ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "shallots.db"
OUT_DIR = ROOT / "data" / "live_canaries"
MGMT_PORTS = {22, 3389, 445, 5985, 5986, 4000, 8844, 8855}
HIDDEN_CANARY_RE = re.compile(r"argus-scout-canary-\d+-[0-9a-f]+", re.IGNORECASE)
SQLITE_TIMEOUT_SECONDS = 30.0


def connect_db(db_path: Path = DB_PATH) -> sqlite3.Connection:
    con = sqlite3.connect(db_path, timeout=SQLITE_TIMEOUT_SECONDS)
    con.execute(f"PRAGMA busy_timeout={int(SQLITE_TIMEOUT_SECONDS * 1000)}")
    con.row_factory = sqlite3.Row
    return con


@dataclass(frozen=True)
class Scenario:
    name: str
    event_type: str
    title: str
    description: str
    category: str
    details: dict[str, Any]
    expected_card: bool
    expectation: str


class CountOnlyDB:
    def __init__(self, db_path: Path) -> None:
        self.con = connect_db(db_path)

    async def count_alerts_matching(self, **kwargs: Any) -> int:
        clauses: list[str] = []
        vals: list[Any] = []
        for key in ("source", "signature_id", "title", "src_ip", "dst_ip", "dst_port", "proto"):
            value = kwargs.get(key)
            if value is not None:
                clauses.append(f"{key} = ?")
                vals.append(value)
        sql = "SELECT COUNT(*) AS c FROM alerts"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        return int(self.con.execute(sql, vals).fetchone()["c"])

    async def execute_sql(self, sql: str, params: tuple = (), max_rows: int = 200, **_: Any) -> list[dict[str, Any]]:
        rows = self.con.execute(sql, params).fetchmany(max_rows)
        return [dict(row) for row in rows]

    def close(self) -> None:
        self.con.close()


def post_argus(events: list[dict[str, Any]], url: str, secret: str) -> dict[str, Any]:
    body = json.dumps(events).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "X-Argus-Secret": secret},
    )
    ctx = ssl._create_unverified_context() if url.startswith("https://") else None
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        return {"status": resp.status, "body": json.loads(resp.read().decode())}


def rows_for_token(token: str) -> list[dict[str, Any]]:
    con = connect_db()
    like = f"%{token}%"
    try:
        rows = con.execute(
            """
            SELECT id, timestamp, ingested_at, source, severity, verdict, title,
                   description, src_ip, dst_ip, dst_port, proto, category,
                   signature_id, ai_reasoning, raw
            FROM alerts
            WHERE raw LIKE ? OR description LIKE ? OR title LIKE ?
            ORDER BY COALESCE(ingested_at, timestamp) DESC
            """,
            (like, like, like),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()


def existing_cards(alert_ids: list[str]) -> list[dict[str, Any]]:
    if not alert_ids:
        return []
    con = connect_db()
    placeholders = ",".join("?" for _ in alert_ids)
    try:
        rows = con.execute(
            f"""
            SELECT id, alert_id, created_at, model, score, reasons,
                   context_facts, scout_note, status
            FROM scout_cards
            WHERE status = 'new' AND alert_id IN ({placeholders})
            ORDER BY created_at DESC
            """,
            alert_ids,
        ).fetchall()
        out = []
        for row in rows:
            d = dict(row)
            for key in ("reasons", "context_facts"):
                try:
                    d[key] = json.loads(d.get(key) or "[]")
                except (TypeError, json.JSONDecodeError):
                    pass
            out.append(d)
        return out
    finally:
        con.close()


def wait_for_rows(token: str, expected: int, timeout: float) -> list[dict[str, Any]]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = rows_for_token(token)
        if len(rows) >= expected:
            return rows
        time.sleep(0.5)
    return rows_for_token(token)


async def score_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cfg = load_config().scout
    db = CountOnlyDB(DB_PATH)
    worker = ScoutWorker(cfg, db, ROOT)
    try:
        out = []
        for alert in alerts:
            score, reasons = await worker._score_alert(alert)
            out.append(
                {
                    "alert_id": alert["id"],
                    "score": score,
                    "reasons": reasons,
                    "would_card": score >= cfg.min_score,
                    "min_score": cfg.min_score,
                }
            )
        return out
    finally:
        db.close()


def upstream_review(
    alerts: list[dict[str, Any]],
    scored: list[dict[str, Any]],
    model: str,
    *,
    mode: str,
) -> dict[str, Any]:
    if not model:
        return {"skipped": True}
    if mode == "raw":
        task = "Pick which alert IDs should remain visible for higher-tier review using raw alerts only. Do not decide benign/malicious."
        extra_constraints = ["No edge Scout scores or corpus context are available in this mode."]
    else:
        task = "Pick which alert IDs should remain visible for higher-tier review using edge Scout scores as downstream collator context. Do not decide benign/malicious."
        extra_constraints = ["Prefer alert IDs where edge_scout_scores.would_card is true and reasons are concrete."]
    prompt = {
        "task": task,
        "constraints": [
            "Return JSON only with selected_alert_ids and rationale.",
            "Select only if the alert has concrete local/contextual reason it may be missed.",
            "Synthetic canary status alone is not a reason to select.",
            *extra_constraints,
        ],
        "alerts": alerts,
        "edge_scout_scores": scored,
    }
    started = time.perf_counter()
    proc = subprocess.run(
        ["claude", "-p", "--model", model, "--output-format", "json"],
        input="You are an upstream Security Shallots reviewer. Return JSON only.\n\n"
        + json.dumps(prompt, indent=2, sort_keys=True),
        text=True,
        capture_output=True,
        timeout=240,
        check=True,
    )
    elapsed = time.perf_counter() - started
    outer = json.loads(proc.stdout)
    raw = str(outer.get("result", "{}")).strip()
    if raw.startswith("```"):
        raw = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = {"raw": raw}
    parsed["latency_sec"] = round(elapsed, 3)
    parsed["model"] = model
    parsed["mode"] = mode
    return parsed


def build_scenarios(run_id: str, src_ip: str, dst_ip: str, dst_port: int) -> list[Scenario]:
    is_mgmt = dst_port in MGMT_PORTS
    is_hidden_canary = bool(HIDDEN_CANARY_RE.search(run_id))
    session_name = "internal_management_port_positive" if is_mgmt else "ordinary_internal_port_control"
    return [
        Scenario(
            name="generic_low_state_control",
            event_type="state_change",
            title=f"Argus canary routine state note {run_id}",
            description=f"Synthetic fleet canary token={run_id} kind=generic-control state=unchanged",
            category="edge_canary/control",
            details={"ip_address": src_ip, "token": run_id},
            expected_card=False,
            expectation="Routine low-severity state note should ingest but not become a Scout card.",
        ),
        Scenario(
            name=session_name,
            event_type="session_alert",
            title=f"Argus canary internal session {run_id} port {dst_port}",
            description=(
                f"Synthetic fleet canary token={run_id} kind=internal-session "
                f"src={src_ip} dst={dst_ip}:{dst_port}"
            ),
            category="edge_canary/session",
            details={
                "ip_address": src_ip,
                "remote_ip": dst_ip,
                "remote_port": dst_port,
                "process": "curl",
                "token": run_id,
            },
            expected_card=False if is_hidden_canary else is_mgmt,
            expectation=(
                "Known synthetic canary should ingest but not become a Scout card, even on a management port."
                if is_hidden_canary and is_mgmt
                else "Internal management-port tuple should remain visible for higher-tier review."
                if is_mgmt
                else "Ordinary internal destination port should ingest but not become a Scout card solely from novelty."
            ),
        ),
    ]


def run(args: argparse.Namespace) -> dict[str, Any]:
    cfg = load_config()
    secret = cfg.argus.agent_secrets.get(args.agent, "")
    if not secret:
        raise SystemExit(f"No Argus secret configured for agent {args.agent!r}")

    run_id = args.run_id or f"argus-scout-canary-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    scenarios = build_scenarios(run_id, args.src_ip, args.dst_ip, args.dst_port)
    ts = datetime.now(timezone.utc).isoformat()
    events = [
        {
            "host": args.agent,
            "event_type": scenario.event_type,
            "severity": "low",
            "confidence": 0.3,
            "title": scenario.title,
            "description": scenario.description,
            "category": scenario.category,
            "timestamp": ts,
            "details": scenario.details,
        }
        for scenario in scenarios
    ]

    ingest = post_argus(events, args.url, secret)
    alerts = wait_for_rows(run_id, len(events), args.alert_timeout)
    scored = asyncio.run(score_alerts(alerts))
    cards = existing_cards([a["id"] for a in alerts])
    raw_review = upstream_review(alerts, [], args.upstream_model, mode="raw")
    collated_review = upstream_review(alerts, scored, args.upstream_model, mode="collated")

    scored_by_alert = {item["alert_id"]: item for item in scored}
    observations = []
    for scenario in scenarios:
        matches = [
            a
            for a in alerts
            if scenario.title == a.get("title") or scenario.description == a.get("description")
        ]
        would_card = any(scored_by_alert.get(a["id"], {}).get("would_card") for a in matches)
        observations.append(
            {
                "name": scenario.name,
                "expected_card": scenario.expected_card,
                "actual_would_card": would_card,
                "ingested": bool(matches),
                "expectation": scenario.expectation,
                "matched_alert_ids": [a["id"] for a in matches],
                "pass": bool(matches) and would_card == scenario.expected_card,
            }
        )

    result = {
        "run_id": run_id,
        "url": args.url,
        "agent": args.agent,
        "ingest": ingest,
        "alert_count": len(alerts),
        "scored_card_count": sum(1 for s in scored if s["would_card"]),
        "daemon_existing_card_count": len(cards),
        "observations": observations,
        "alerts": alerts,
        "edge_scout_scores": scored,
        "daemon_existing_cards": cards,
        "raw_review": raw_review,
        "collated_review": collated_review,
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / f"{run_id}.json"
    out.write_text(json.dumps(result, indent=2, sort_keys=True, default=str) + "\n")
    result["output_path"] = str(out)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="https://192.168.0.172:8844/api/ingest/argus")
    parser.add_argument("--agent", default="shallot-experiment-agent")
    parser.add_argument("--src-ip", default="192.168.0.204")
    parser.add_argument("--dst-ip", default="192.168.0.172")
    parser.add_argument("--dst-port", type=int, default=8844)
    parser.add_argument("--run-id", default="")
    parser.add_argument("--alert-timeout", type=float, default=20.0)
    parser.add_argument("--upstream-model", default="sonnet")
    args = parser.parse_args()
    result = run(args)
    print(
        json.dumps(
            {
                "run_id": result["run_id"],
                "alert_count": result["alert_count"],
                "scored_card_count": result["scored_card_count"],
                "daemon_existing_card_count": result["daemon_existing_card_count"],
                "observations": result["observations"],
                "raw_review": result["raw_review"],
                "collated_review": result["collated_review"],
                "output_path": result["output_path"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if all(obs["pass"] for obs in result["observations"]) else 2


if __name__ == "__main__":
    raise SystemExit(main())
