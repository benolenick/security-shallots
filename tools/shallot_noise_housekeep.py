#!/usr/bin/env python3
"""Suppress historical Shallots test/lifecycle noise with optional synthetic pruning."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shallots.config import load_config


NON_PROD_PREFIXES = ("shallot-load-", "shallot-experiment", "shallot-auth-boundary", "tls-smoke")
STARTUP_TITLES = (
    "State changed: DISARMED -> ARMED_HOME",
    "State changed: ARMED_HOME -> DISARMED",
)
SYNTHETIC_PRUNE_MIN_HOURS = 6.0
DEFAULT_SYNTHETIC_PRUNE_STATUS_HOURS = 24.0
ASSESSMENT_LOG_KEEP_SECTIONS = 96
ASSESSMENT_LOG_MAX_BYTES = 5 * 1024 * 1024
DEFAULT_STATE = "docs/NOISE_HOUSEKEEP_STATE.json"


@dataclass(frozen=True)
class Rule:
    name: str
    where: str
    params: tuple
    reason: str


def rules() -> list[Rule]:
    prefix_terms = []
    prefix_params = []
    for prefix in NON_PROD_PREFIXES:
        like = f"%{prefix}%"
        prefix_terms.append(
            "(title LIKE ? OR description LIKE ? OR src_asset LIKE ? OR dst_asset LIKE ? OR source_ref LIKE ?)"
        )
        prefix_params.extend([like, like, like, like, like])

    return [
        Rule(
            "non_prod_agents",
            " OR ".join(prefix_terms),
            tuple(prefix_params),
            "native housekeeping: historical synthetic/load/test agent noise",
        ),
        Rule(
            "startup_state_changes",
            "title IN (?, ?)",
            STARTUP_TITLES,
            "native housekeeping: routine Argus startup/shutdown lifecycle",
        ),
        Rule(
            "synthetic_titles",
            "(LOWER(title) LIKE ? OR LOWER(description) LIKE ? OR LOWER(category) LIKE ?)",
            ("%synthetic%", "%synthetic%", "%experiment%"),
            "native housekeeping: historical experiment/synthetic alert",
        ),
        Rule(
            "local_syslog_tests",
            "(source = ? AND src_ip = ? AND LOWER(description) LIKE ?)",
            ("syslog", "127.0.0.1", "%test%"),
            "native housekeeping: local syslog receiver test",
        ),
    ]


def synthetic_where() -> tuple[str, tuple]:
    prefix_terms = []
    prefix_params = []
    for prefix in NON_PROD_PREFIXES:
        like = f"%{prefix}%"
        prefix_terms.append(
            "(title LIKE ? OR description LIKE ? OR src_asset LIKE ? OR dst_asset LIKE ? OR source_ref LIKE ?)"
        )
        prefix_params.extend([like, like, like, like, like])
    terms = [
        *prefix_terms,
        "(LOWER(title) LIKE ? OR LOWER(description) LIKE ? OR LOWER(category) LIKE ?)",
    ]
    params = [*prefix_params, "%synthetic%", "%synthetic%", "%experiment%"]
    return " OR ".join(f"({term})" for term in terms), tuple(params)


def prune_synthetic(
    con: sqlite3.Connection,
    *,
    older_hours: float,
    apply: bool,
) -> int:
    if older_hours < SYNTHETIC_PRUNE_MIN_HOURS:
        raise ValueError(f"synthetic prune window must be at least {SYNTHETIC_PRUNE_MIN_HOURS:g}h")
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=older_hours)).isoformat(timespec="seconds")
    where, params = synthetic_where()
    count = int(
        con.execute(
            f"SELECT COUNT(*) FROM alerts WHERE timestamp < ? AND ({where})",
            (cutoff, *params),
        ).fetchone()[0]
    )
    if apply and count:
        con.execute(
            f"DELETE FROM alerts WHERE timestamp < ? AND ({where})",
            (cutoff, *params),
        )
    return count


def _parse_timestamp(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def synthetic_prune_status(con: sqlite3.Connection, *, older_hours: float) -> dict[str, float | int | None]:
    if older_hours < SYNTHETIC_PRUNE_MIN_HOURS:
        raise ValueError(f"synthetic prune window must be at least {SYNTHETIC_PRUNE_MIN_HOURS:g}h")
    where, params = synthetic_where()
    rows = con.execute(f"SELECT timestamp FROM alerts WHERE {where}", params).fetchall()
    now = datetime.now(timezone.utc)
    ages: list[float] = []
    eligible = 0
    for (timestamp,) in rows:
        ts = _parse_timestamp(timestamp)
        if ts is None:
            continue
        age = max(0.0, (now - ts).total_seconds() / 3600)
        ages.append(age)
        if age >= older_hours:
            eligible += 1
    next_eligible = None
    pending = [older_hours - age for age in ages if age < older_hours]
    if pending:
        next_eligible = round(max(0.0, min(pending)), 2)
    return {
        "total_synthetic": len(rows),
        "timestamped_synthetic": len(ages),
        "prune_eligible": eligible,
        "oldest_age_hours": round(max(ages), 2) if ages else None,
        "newest_age_hours": round(min(ages), 2) if ages else None,
        "next_eligible_in_hours": next_eligible,
    }


def online_agents(con: sqlite3.Connection, *, max_age_seconds: int = 900) -> set[str]:
    now = datetime.now(timezone.utc)
    out: set[str] = set()
    try:
        rows = con.execute("SELECT agent_name, last_seen FROM agent_heartbeats").fetchall()
    except sqlite3.OperationalError:
        return out
    for name, last_seen in rows:
        try:
            dt = datetime.fromisoformat(str(last_seen).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if (now - dt).total_seconds() <= max_age_seconds:
            out.add(str(name))
    return out


def trim_assessment_log(
    path: str | Path,
    *,
    keep_sections: int = ASSESSMENT_LOG_KEEP_SECTIONS,
    max_bytes: int = ASSESSMENT_LOG_MAX_BYTES,
    apply: bool,
) -> dict[str, int | bool]:
    log_path = Path(path)
    if not log_path.exists():
        return {
            "exists": False,
            "sections_before": 0,
            "sections_after": 0,
            "bytes_before": 0,
            "bytes_after": 0,
            "trimmed": False,
        }
    text = log_path.read_text(errors="ignore")
    bytes_before = len(text.encode())
    prefix = ""
    chunks: list[str] = []
    current: list[str] = []
    for line in text.splitlines(keepends=True):
        if line.startswith("## "):
            if current:
                chunks.append("".join(current))
            elif not chunks and not prefix:
                pass
            current = [line]
        elif current:
            current.append(line)
        else:
            prefix += line
    if current:
        chunks.append("".join(current))
    sections_before = len(chunks)
    kept = chunks[-max(1, keep_sections):] if chunks else []
    new_text = prefix + "".join(kept)
    while len(new_text.encode()) > max_bytes and len(kept) > 1:
        kept = kept[1:]
        new_text = prefix + "".join(kept)
    bytes_after = len(new_text.encode())
    trimmed = sections_before != len(kept) or bytes_after != bytes_before
    if trimmed and apply:
        tmp = log_path.with_suffix(log_path.suffix + ".tmp")
        tmp.write_text(new_text)
        tmp.replace(log_path)
    return {
        "exists": True,
        "sections_before": sections_before,
        "sections_after": len(kept),
        "bytes_before": bytes_before,
        "bytes_after": bytes_after,
        "trimmed": trimmed,
    }


def write_state(path: str | Path, payload: dict) -> None:
    state_path = Path(path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = state_path.with_suffix(state_path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    tmp.replace(state_path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-c", "--config", default="config.yaml")
    parser.add_argument("--db", default="")
    parser.add_argument("--apply", action="store_true", help="Apply updates; default is dry-run")
    parser.add_argument(
        "--prune-synthetic-older-hours",
        type=float,
        default=0.0,
        help="Optionally delete synthetic/load/experiment alerts older than this many hours; minimum 6h",
    )
    parser.add_argument(
        "--apply-prune",
        action="store_true",
        help="Actually delete synthetic prune matches; --apply alone never deletes",
    )
    parser.add_argument("--trim-assessment-log", default="")
    parser.add_argument("--keep-assessment-sections", type=int, default=ASSESSMENT_LOG_KEEP_SECTIONS)
    parser.add_argument("--max-assessment-log-bytes", type=int, default=ASSESSMENT_LOG_MAX_BYTES)
    parser.add_argument("--state", default=DEFAULT_STATE)
    parser.add_argument("--summary-json", action="store_true", help="Emit a machine-readable run summary")
    args = parser.parse_args()

    def emit(message: str) -> None:
        if not args.summary_json:
            print(message)

    db_path = args.db or load_config(args.config).storage.db_path
    con = sqlite3.connect(db_path)
    total = 0
    applied_total = 0
    rule_counts: dict[str, int] = {}
    prune_status: dict[str, float | int | None] | None = None
    prune_count = 0
    trim: dict[str, int | bool] | None = None
    try:
        for rule in rules():
            count = con.execute(
                f"SELECT COUNT(*) FROM alerts WHERE verdict != 'suppress' AND ({rule.where})",
                rule.params,
            ).fetchone()[0]
            rule_counts[rule.name] = int(count)
            emit(f"{rule.name}: {count}")
            total += int(count)
            if args.apply and count:
                con.execute(
                    f"""
                    UPDATE alerts
                    SET verdict = 'suppress',
                        confidence = 1.0,
                        ai_reasoning = ?
                    WHERE verdict != 'suppress' AND ({rule.where})
                    """,
                    (rule.reason, *rule.params),
                )
                applied_total += int(count)
        online = sorted(online_agents(con))
        if online:
            placeholders = ",".join("?" for _ in online)
            params = tuple(f"Agent offline: {name}" for name in online)
            count = con.execute(
                f"SELECT COUNT(*) FROM alerts WHERE verdict != 'suppress' AND title IN ({placeholders})",
                params,
            ).fetchone()[0]
            rule_counts["resolved_agent_offline"] = int(count)
            emit(f"resolved_agent_offline: {count}")
            total += int(count)
            if args.apply and count:
                con.execute(
                    f"""
                    UPDATE alerts
                    SET verdict = 'suppress',
                        confidence = 1.0,
                        ai_reasoning = ?
                    WHERE verdict != 'suppress' AND title IN ({placeholders})
                    """,
                    ("native housekeeping: agent has recovered and is currently online", *params),
                )
                applied_total += int(count)
        if args.apply:
            con.commit()
            emit(f"applied: up to {total} matches across rules")
        else:
            emit(f"dry_run_total: {total}")
        prune_status_hours = args.prune_synthetic_older_hours or DEFAULT_SYNTHETIC_PRUNE_STATUS_HOURS
        prune_status = synthetic_prune_status(con, older_hours=prune_status_hours)
        emit(
            "synthetic_prune_status: "
            f"total={prune_status['total_synthetic']} "
            f"timestamped={prune_status['timestamped_synthetic']} "
            f"eligible={prune_status['prune_eligible']} "
            f"oldest_h={prune_status['oldest_age_hours']} "
            f"newest_h={prune_status['newest_age_hours']} "
            f"next_eligible_h={prune_status['next_eligible_in_hours']}"
        )
        if args.prune_synthetic_older_hours:
            prune_count = prune_synthetic(
                con,
                older_hours=args.prune_synthetic_older_hours,
                apply=args.apply_prune,
            )
            emit(
                f"synthetic_prune_older_than_{args.prune_synthetic_older_hours:g}h: "
                f"{prune_count}"
            )
            if args.apply_prune:
                con.commit()
                emit(f"prune_applied: deleted {prune_count} synthetic/load/experiment alerts")
            else:
                emit("prune_dry_run: pass --apply-prune to delete synthetic/load/experiment matches")
        if args.trim_assessment_log:
            trim = trim_assessment_log(
                args.trim_assessment_log,
                keep_sections=args.keep_assessment_sections,
                max_bytes=args.max_assessment_log_bytes,
                apply=args.apply,
            )
            emit(
                "assessment_log_trim: "
                f"exists={trim['exists']} trimmed={trim['trimmed']} "
                f"sections={trim['sections_before']}->{trim['sections_after']} "
                f"bytes={trim['bytes_before']}->{trim['bytes_after']}"
            )
        state_payload = {
            "status": "ok",
            "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "db_path": db_path,
            "apply": bool(args.apply),
            "rule_counts": rule_counts,
            "suppression_candidates": total,
            "suppression_applied": applied_total if args.apply else 0,
            "synthetic_prune": {
                "older_hours": prune_status_hours,
                "prune_requested": bool(args.prune_synthetic_older_hours),
                "apply_prune": bool(args.apply_prune),
                "matched": prune_count if args.prune_synthetic_older_hours else int(prune_status["prune_eligible"] or 0),
                "deleted": prune_count if args.apply_prune else 0,
                "status": prune_status or {},
            },
            "assessment_log_trim": trim or {},
        }
        if args.state:
            write_state(args.state, state_payload)
        if args.summary_json:
            print(json.dumps(state_payload, sort_keys=True))
    finally:
        con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
