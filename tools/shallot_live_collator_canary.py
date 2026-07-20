#!/usr/bin/env python3
"""Run live, bounded canaries through Shallots ingest -> Scout cards.

This sends benign syslog events into the real local pipeline and records how the
edge scout/collator reacts. It does not run exploit payloads or network scans.
"""

from __future__ import annotations

import argparse
import json
import socket
import sqlite3
import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "shallots.db"
OUT_DIR = ROOT / "data" / "live_canaries"
SQLITE_TIMEOUT_SECONDS = 30.0


def connect_db() -> sqlite3.Connection:
    con = sqlite3.connect(DB, timeout=SQLITE_TIMEOUT_SECONDS)
    con.execute(f"PRAGMA busy_timeout={int(SQLITE_TIMEOUT_SECONDS * 1000)}")
    con.row_factory = sqlite3.Row
    return con


@dataclass(frozen=True)
class CanaryEvent:
    name: str
    hostname: str
    app: str
    message: str
    expected_card: bool
    expectation: str


def syslog_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%b %e %H:%M:%S")


def priority_for_token(token: str) -> int:
    # Vary facility like the native syslog canary so repeated test runs do not
    # accidentally share low-severity limiter buckets.
    suffix = sum(token.encode())
    facility = suffix % 24
    return (facility << 3) | 6


def send_syslog(hostname: str, app: str, message: str, host: str, port: int, token: str) -> None:
    payload = f"<{priority_for_token(token)}>{syslog_stamp()} {hostname} {app}: {message}".encode()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1.0)
        sock.sendto(payload, (host, port))


def rows_for_token(token: str) -> list[dict[str, Any]]:
    con = connect_db()
    like = f"%{token}%"
    try:
        rows = con.execute(
            """
            SELECT id, timestamp, ingested_at, source, severity, verdict, title,
                   description, src_ip, category, signature_id, ai_reasoning
            FROM alerts
            WHERE raw LIKE ? OR description LIKE ? OR title LIKE ?
            ORDER BY COALESCE(ingested_at, timestamp) DESC
            """,
            (like, like, like),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()


def scout_for_alerts(alert_ids: list[str]) -> list[dict[str, Any]]:
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
            WHERE alert_id IN ({placeholders})
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


def wait_for_alerts(token: str, timeout: float) -> list[dict[str, Any]]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = rows_for_token(token)
        if rows:
            return rows
        time.sleep(0.5)
    return rows_for_token(token)


def event_alerts(event: CanaryEvent, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        row for row in rows
        if event.app in str(row.get("title") or "")
        or event.message in str(row.get("description") or "")
        or event.message in str(row.get("raw") or "")
    ]


def send_until_ingested(event: CanaryEvent, token: str, args: argparse.Namespace) -> list[dict[str, Any]]:
    deadline = time.monotonic() + args.per_event_timeout
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        send_syslog(event.hostname, event.app, event.message, args.host, args.port, token)
        time.sleep(args.send_gap)
        rows = rows_for_token(token)
        matches = event_alerts(event, rows)
        if matches:
            for row in matches:
                row["_canary_send_attempts"] = attempts
            return matches
        time.sleep(args.resend_gap)
    return [{"_canary_send_attempts": attempts}]


def wait_for_scout(alert_ids: list[str], timeout: float) -> list[dict[str, Any]]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = scout_for_alerts(alert_ids)
        if rows:
            return rows
        time.sleep(2.0)
    return scout_for_alerts(alert_ids)


def upstream_review(
    alerts: list[dict[str, Any]],
    cards: list[dict[str, Any]],
    model: str,
    *,
    mode: str,
) -> dict[str, Any]:
    if not model:
        return {"skipped": True}
    if mode == "raw":
        task = (
            "Pick which live canary alert IDs should remain visible for higher-tier review "
            "using only the raw alert rows. Do not decide benign/malicious."
        )
        extra_constraints = [
            "No Scout cards or fleet-local corpus facts are available in this mode.",
        ]
    else:
        task = (
            "Pick which live canary alert IDs should remain visible for higher-tier review "
            "using the Scout cards as the distilled downstream context. Do not decide benign/malicious."
        )
        extra_constraints = [
            "Prefer alert IDs that have Scout cards with concrete mechanical reasons.",
            "Do not select raw alerts that lack Scout-card support unless the raw row alone gives a concrete local reason.",
        ]
    prompt = {
        "task": task,
        "constraints": [
            "Return JSON only with selected_alert_ids and rationale.",
            "Select only if the alert has concrete local/contextual reason it may be missed.",
            "Synthetic canary status alone is not a reason to select.",
            *extra_constraints,
        ],
        "alerts": alerts,
        "scout_cards": cards,
    }
    text = (
        "You are an upstream Security Shallots reviewer. Return JSON only.\n\n"
        + json.dumps(prompt, indent=2, sort_keys=True)
    )
    started = time.perf_counter()
    proc = subprocess.run(
        ["claude", "-p", "--model", model, "--output-format", "json"],
        input=text,
        text=True,
        capture_output=True,
        timeout=240,
        check=True,
    )
    elapsed = time.perf_counter() - started
    outer = json.loads(proc.stdout)
    raw = str(outer.get("result", "{}")).strip()
    if raw.startswith("```"):
        raw = raw.removeprefix("```json").removeprefix("```").strip()
        raw = raw.removesuffix("```").strip()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = {"raw": raw}
    parsed["latency_sec"] = round(elapsed, 3)
    parsed["model"] = model
    parsed["mode"] = mode
    return parsed


def run(args: argparse.Namespace) -> dict[str, Any]:
    run_id = args.run_id or f"livecollator-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    events = [
        CanaryEvent(
            name="router_source_mismatch_positive",
            hostname="live-canary",
            app=f"dlink-{run_id}",
            message=f"Syslog [user] routine gateway status token={run_id} kind=router-mismatch",
            expected_card=True,
            expectation="Should produce router_syslog_source_mismatch because app/title contains dlink but source IP is localhost, not 192.168.0.1.",
        ),
        CanaryEvent(
            name="generic_localhost_noise_control",
            hostname="live-canary",
            app=f"shallot-{run_id}",
            message=f"Routine localhost canary token={run_id} kind=generic-control",
            expected_card=False,
            expectation="Should ingest as low-severity syslog. A Scout card here indicates the rare/suppressed heuristic is too broad.",
        ),
    ]

    sent_at = datetime.now(timezone.utc).isoformat()
    before_alerts = rows_for_token(run_id)
    per_event_ingest = {}
    for event in events:
        per_event_ingest[event.name] = send_until_ingested(event, run_id, args)

    alerts = wait_for_alerts(run_id, args.alert_timeout)
    alert_ids = [a["id"] for a in alerts]
    cards = wait_for_scout(alert_ids, args.scout_timeout) if alert_ids else []
    raw_review = upstream_review(alerts, [], args.upstream_model, mode="raw")
    collated_review = upstream_review(alerts, cards, args.upstream_model, mode="collated")

    cards_by_alert = {c["alert_id"]: c for c in cards}
    observations = []
    for event in events:
        matching_alerts = event_alerts(event, alerts)
        matching_cards = [cards_by_alert[a["id"]] for a in matching_alerts if a["id"] in cards_by_alert]
        observations.append(
            {
                "name": event.name,
                "expected_card": event.expected_card,
                "expectation": event.expectation,
                "matched_alerts": matching_alerts,
                "matched_cards": matching_cards,
                "ingested": bool(matching_alerts),
                "send_attempts": max(
                    [int(a.get("_canary_send_attempts") or 0) for a in per_event_ingest[event.name]] or [0]
                ),
                "pass": bool(matching_alerts) and bool(matching_cards) == event.expected_card,
            }
        )

    result = {
        "run_id": run_id,
        "sent_at": sent_at,
        "host": args.host,
        "port": args.port,
        "before_alert_count": len(before_alerts),
        "alert_count": len(alerts),
        "card_count": len(cards),
        "observations": observations,
        "alerts": alerts,
        "scout_cards": cards,
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
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=514)
    parser.add_argument("--run-id", default="")
    parser.add_argument("--send-gap", type=float, default=0.5)
    parser.add_argument("--resend-gap", type=float, default=1.0)
    parser.add_argument("--per-event-timeout", type=float, default=8.0)
    parser.add_argument("--alert-timeout", type=float, default=15.0)
    parser.add_argument("--scout-timeout", type=float, default=140.0)
    parser.add_argument("--upstream-model", default="sonnet", help="claude model name, or empty to skip")
    args = parser.parse_args()

    result = run(args)
    print(json.dumps({
        "run_id": result["run_id"],
        "alert_count": result["alert_count"],
        "card_count": result["card_count"],
        "observations": [
            {
                "name": o["name"],
                "expected_card": o["expected_card"],
                "ingested": o["ingested"],
                "send_attempts": o["send_attempts"],
                "actual_cards": len(o["matched_cards"]),
                "pass": o["pass"],
            }
            for o in result["observations"]
        ],
        "raw_review": result["raw_review"],
        "collated_review": result["collated_review"],
        "output_path": result["output_path"],
    }, indent=2, sort_keys=True))
    return 0 if all(o["pass"] for o in result["observations"]) else 2


if __name__ == "__main__":
    raise SystemExit(main())
