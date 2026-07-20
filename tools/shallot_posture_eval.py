#!/usr/bin/env python3
"""Evaluate the small-footprint posture layer against core scenario checks."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shallots.posture.engine import DB_PATH, status


def count(con: sqlite3.Connection, sql: str, params: tuple = ()) -> int:
    return int(con.execute(sql, params).fetchone()[0])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    checks = []
    con = sqlite3.connect(DB_PATH)
    try:
        checks.append({
            "name": "coverage_map_populated",
            "ok": count(con, "SELECT COUNT(*) FROM sensor_coverage") > 0,
        })
        checks.append({
            "name": "time_integrity_visible",
            "ok": count(con, "SELECT COUNT(*) FROM sensor_coverage WHERE sensor='time' AND state='visible'") > 0,
        })
        checks.append({
            "name": "service_baselines_populated",
            "ok": count(con, "SELECT COUNT(*) FROM service_baselines") > 0,
        })
        checks.append({
            "name": "drift_snapshots_populated",
            "ok": count(con, "SELECT COUNT(*) FROM drift_snapshots") > 0,
        })
        checks.append({
            "name": "execution_ledger_populated",
            "ok": count(con, "SELECT COUNT(*) FROM execution_ledger") > 0,
        })
        checks.append({
            "name": "dns_state_recorded",
            "ok": count(con, "SELECT COUNT(*) FROM dns_memory") > 0
            or count(con, "SELECT COUNT(*) FROM sensor_coverage WHERE sensor='dns'") > 0,
        })
        checks.append({
            "name": "alert_memory_populated",
            "ok": count(con, "SELECT COUNT(*) FROM alert_memory") > 0,
        })
        checks.append({
            "name": "suppression_hygiene_populated",
            "ok": count(con, "SELECT COUNT(*) FROM suppression_hygiene") > 0,
        })
        checks.append({
            "name": "canary_files_tracked",
            "ok": count(con, "SELECT COUNT(*) FROM drift_snapshots WHERE kind='canary'") >= 1,
        })
    finally:
        con.close()

    failed = [c for c in checks if not c["ok"]]
    payload = {
        "status": "ok" if not failed else "fail",
        "failed": len(failed),
        "checks": checks,
        "posture_status": status(),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())

