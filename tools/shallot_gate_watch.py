#!/usr/bin/env python3
"""Track production-gate blocker/warning drift between assessment passes."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.shallot_gate_eval import evaluate_gate
from tools.shallot_security_snapshot import load_snapshot

DEFAULT_STATE = ROOT / "docs" / "GATE_WATCH_STATE.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_time(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _age_seconds(first_seen: str, now: str) -> int | None:
    start = _parse_time(first_seen)
    end = _parse_time(now)
    if start is None or end is None:
        return None
    return max(0, int((end.astimezone(timezone.utc) - start.astimezone(timezone.utc)).total_seconds()))


def _load_state(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _write_state(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def build_gate_watch(
    current: dict[str, Any],
    previous: dict[str, Any] | None = None,
    *,
    now: str | None = None,
) -> dict[str, Any]:
    previous = previous or {}
    current_blockers = sorted(str(item) for item in current.get("blockers") or [])
    current_warnings = sorted(str(item) for item in current.get("warnings") or [])
    previous_blockers = sorted(str(item) for item in previous.get("blockers") or [])
    previous_warnings = sorted(str(item) for item in previous.get("warnings") or [])
    checked_at = now or _now()

    new_blockers = sorted(set(current_blockers) - set(previous_blockers))
    cleared_blockers = sorted(set(previous_blockers) - set(current_blockers))
    new_warnings = sorted(set(current_warnings) - set(previous_warnings))
    cleared_warnings = sorted(set(previous_warnings) - set(current_warnings))

    if not previous:
        status = "initialized"
    elif new_blockers:
        status = "new_blockers"
    elif cleared_blockers or new_warnings or cleared_warnings:
        status = "changed"
    else:
        status = "stable"

    previous_blocker_first_seen = previous.get("blocker_first_seen_at") or {}
    previous_warning_first_seen = previous.get("warning_first_seen_at") or {}
    previous_checked_at = str(previous.get("checked_at") or "")
    blocker_first_seen_at = {
        blocker: str(previous_blocker_first_seen.get(blocker) or previous_checked_at or checked_at)
        for blocker in current_blockers
    }
    warning_first_seen_at = {
        warning: str(previous_warning_first_seen.get(warning) or previous_checked_at or checked_at)
        for warning in current_warnings
    }
    blocker_age_sec = {
        blocker: _age_seconds(first_seen, checked_at)
        for blocker, first_seen in blocker_first_seen_at.items()
    }
    warning_age_sec = {
        warning: _age_seconds(first_seen, checked_at)
        for warning, first_seen in warning_first_seen_at.items()
    }

    return {
        "status": status,
        "checked_at": checked_at,
        "gate_status": current.get("status", "unknown"),
        "blockers": current_blockers,
        "warnings": current_warnings,
        "blocker_first_seen_at": blocker_first_seen_at,
        "warning_first_seen_at": warning_first_seen_at,
        "blocker_age_sec": blocker_age_sec,
        "warning_age_sec": warning_age_sec,
        "new_blockers": new_blockers,
        "cleared_blockers": cleared_blockers,
        "new_warnings": new_warnings,
        "cleared_warnings": cleared_warnings,
        "stable_blockers": sorted(set(current_blockers) & set(previous_blockers)),
        "stable_warnings": sorted(set(current_warnings) & set(previous_warnings)),
        "previous_checked_at": previous_checked_at,
    }


def _print_text(report: dict[str, Any]) -> None:
    print(f"gate watch: {report['status']} gate={report['gate_status']}")
    for label in ("new_blockers", "cleared_blockers", "new_warnings", "cleared_warnings"):
        values = report.get(label) or []
        print(f"{label.replace('_', ' ')}: {values if values else 'none'}")
    print(f"stable blockers: {report.get('stable_blockers') or []}")
    ages = report.get("blocker_age_sec") or {}
    if ages:
        print(f"blocker ages seconds: {ages}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-c", "--config", default="config.yaml")
    parser.add_argument("--hours", type=float, default=1.0)
    parser.add_argument("--expected-log-sources", default="docs/NETWORK_LOG_SOURCES.yaml")
    parser.add_argument("--state", default=str(DEFAULT_STATE))
    parser.add_argument("--no-write", action="store_true", help="Compare but do not update the state file")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    snapshot = load_snapshot(
        config=args.config,
        hours=args.hours,
        expected_log_sources=args.expected_log_sources,
    )
    current = evaluate_gate(snapshot)
    state_path = Path(args.state)
    previous = _load_state(state_path)
    report = build_gate_watch(current, previous)
    if not args.no_write:
        _write_state(state_path, report)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_text(report)
    return 1 if report["status"] == "new_blockers" else 0


if __name__ == "__main__":
    raise SystemExit(main())
