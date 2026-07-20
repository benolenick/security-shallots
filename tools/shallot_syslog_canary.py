#!/usr/bin/env python3
"""Exercise localhost syslog ingest with a bounded self-cleaning canary."""

from __future__ import annotations

import argparse
import json
import socket
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shallots.config import load_config


DEFAULT_STATE = "docs/SYSLOG_CANARY_STATE.json"
TOKEN_PREFIX = "shallot-syslog-canary-test"
SQLITE_TIMEOUT_SECONDS = 30.0


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _syslog_stamp(now: datetime) -> str:
    return now.strftime("%b %e %H:%M:%S")


def priority_for_token(token: str) -> int:
    # Keep severity at informational (6) while varying facility for dedup.
    try:
        suffix = int(token.rsplit("-", 1)[-1])
    except ValueError:
        suffix = sum(token.encode())
    facility = suffix % 24
    return (facility << 3) | 6


def build_message(token: str, *, now: datetime | None = None) -> bytes:
    now = now or _now()
    pri = priority_for_token(token)
    return f"<{pri}>{_syslog_stamp(now)} shallot-canary test: {TOKEN_PREFIX} token={token}".encode()


def send_udp(host: str, port: int, payload: bytes) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1.0)
        sock.sendto(payload, (host, port))


def find_rows(db_path: str, token: str) -> list[dict[str, Any]]:
    like = f"%{token}%"
    con = sqlite3.connect(db_path, timeout=SQLITE_TIMEOUT_SECONDS)
    con.execute(f"PRAGMA busy_timeout={int(SQLITE_TIMEOUT_SECONDS * 1000)}")
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            """
            SELECT id, timestamp, source, src_ip, src_asset, title, description, verdict
            FROM alerts
            WHERE source = 'syslog'
              AND src_ip = '127.0.0.1'
              AND (description LIKE ? OR raw LIKE ?)
            ORDER BY timestamp DESC
            """,
            (like, like),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        con.close()


def wait_for_rows(db_path: str, token: str, *, timeout_seconds: float, interval_seconds: float = 0.2) -> list[dict[str, Any]]:
    deadline = time.monotonic() + timeout_seconds
    while True:
        rows = find_rows(db_path, token)
        if rows:
            return rows
        if time.monotonic() >= deadline:
            return []
        time.sleep(interval_seconds)


def cleanup_rows(db_path: str, token: str, *, mode: str) -> int:
    if mode == "keep":
        return 0
    like = f"%{token}%"
    con = sqlite3.connect(db_path, timeout=SQLITE_TIMEOUT_SECONDS)
    con.execute(f"PRAGMA busy_timeout={int(SQLITE_TIMEOUT_SECONDS * 1000)}")
    try:
        if mode == "suppress":
            cur = con.execute(
                """
                UPDATE alerts
                SET verdict = 'suppress',
                    confidence = 1.0,
                    ai_reasoning = 'native canary: localhost syslog ingest test'
                WHERE source = 'syslog'
                  AND src_ip = '127.0.0.1'
                  AND (description LIKE ? OR raw LIKE ?)
                """,
                (like, like),
            )
        elif mode == "delete":
            cur = con.execute(
                """
                DELETE FROM alerts
                WHERE source = 'syslog'
                  AND src_ip = '127.0.0.1'
                  AND (description LIKE ? OR raw LIKE ?)
                """,
                (like, like),
            )
        else:
            raise ValueError(f"unknown cleanup mode: {mode}")
        con.commit()
        return int(cur.rowcount or 0)
    finally:
        con.close()


def write_state(path: str, payload: dict[str, Any]) -> None:
    state_path = Path(path)
    if not state_path.is_absolute():
        state_path = ROOT / state_path
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = state_path.with_suffix(state_path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n")
    tmp.replace(state_path)


def _read_state(path: str) -> dict[str, Any]:
    state_path = Path(path)
    if not state_path.is_absolute():
        state_path = ROOT / state_path
    try:
        data = json.loads(state_path.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _with_history(result: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    status = str(result.get("status") or "")
    prev_failures = int(previous.get("consecutive_failures") or 0)
    prev_successes = int(previous.get("consecutive_successes") or 0)
    if status == "ok":
        result["consecutive_failures"] = 0
        result["consecutive_successes"] = prev_successes + 1
        result["last_ok_at"] = result.get("sent_at") or ""
        result["last_failure_at"] = previous.get("last_failure_at") or ""
    else:
        result["consecutive_failures"] = prev_failures + 1
        result["consecutive_successes"] = 0
        result["last_ok_at"] = previous.get("last_ok_at") or ""
        result["last_failure_at"] = result.get("sent_at") or ""
    return result


def run_canary(
    *,
    config: str = "config.yaml",
    db: str = "",
    host: str = "127.0.0.1",
    port: int | None = None,
    timeout_seconds: float = 5.0,
    attempts: int = 3,
    cleanup: str = "delete",
    state_path: str = DEFAULT_STATE,
) -> dict[str, Any]:
    cfg = load_config(config)
    db_path = db or cfg.storage.db_path
    target_port = int(port or cfg.syslog.udp_port)
    token = f"{TOKEN_PREFIX}-{int(time.time() * 1000)}"
    sent_at = _now().isoformat(timespec="seconds")
    payload = build_message(token)
    previous = _read_state(state_path)
    result: dict[str, Any] = {
        "status": "fail",
        "sent_at": sent_at,
        "host": host,
        "port": target_port,
        "token": token,
        "priority": priority_for_token(token),
        "matched": 0,
        "attempts": max(1, int(attempts)),
        "attempts_used": 0,
        "cleanup": cleanup,
        "cleaned": 0,
        "error": "",
        "rows": [],
    }
    try:
        rows: list[dict[str, Any]] = []
        attempt_count = max(1, int(attempts))
        per_attempt_timeout = max(0.2, timeout_seconds / attempt_count)
        for attempt_number in range(1, attempt_count + 1):
            result["attempts_used"] = attempt_number
            send_udp(host, target_port, payload)
            rows = wait_for_rows(db_path, token, timeout_seconds=per_attempt_timeout)
            if rows:
                break
        result["matched"] = len(rows)
        result["rows"] = rows[:3]
        if rows:
            result["status"] = "ok"
            result["cleaned"] = cleanup_rows(db_path, token, mode=cleanup)
        else:
            result["error"] = f"no matching syslog row within {timeout_seconds:g}s"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    result = _with_history(result, previous)
    write_state(state_path, result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-c", "--config", default="config.yaml")
    parser.add_argument("--db", default="")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--cleanup", choices=("delete", "suppress", "keep"), default="delete")
    parser.add_argument("--state", default=DEFAULT_STATE)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    result = run_canary(
        config=args.config,
        db=args.db,
        host=args.host,
        port=args.port,
        timeout_seconds=args.timeout,
        attempts=args.attempts,
        cleanup=args.cleanup,
        state_path=args.state,
    )
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(
            f"syslog canary: {result['status']} "
            f"target={result['host']}:{result['port']} "
            f"matched={result['matched']} cleaned={result['cleaned']} "
            f"attempts={result['attempts_used']}/{result['attempts']}"
        )
        if result.get("error"):
            print(f"error: {result['error']}")
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
