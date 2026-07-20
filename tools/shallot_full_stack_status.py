#!/usr/bin/env python3
"""Collect Security Shallots full-stack health and footprint telemetry."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "shallots.db"
CORPUS = ROOT / "data" / "fleet_context.db"
PCAP_RING = Path("/var/lib/shallots/pcap-ring")
EVIDENCE_DIR = Path("/var/lib/shallots/evidence")
POSTURE_DB = ROOT / "data" / "posture.db"
POSTURE_REPORT = ROOT / "docs" / "POSTURE_STATE.md"


def run(cmd: list[str], *, timeout: int = 10) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def du_mb(path: Path) -> float | None:
    if not path.exists():
        return None
    total = 0
    if path.is_file():
        total = path.stat().st_size
    else:
        for root, _dirs, files in os.walk(path):
            for name in files:
                try:
                    total += (Path(root) / name).stat().st_size
                except OSError:
                    pass
    return round(total / (1024 * 1024), 2)


def service_state(name: str) -> dict[str, str]:
    return {
        "active": run(["systemctl", "is-active", name]).stdout.strip(),
        "enabled": run(["systemctl", "is-enabled", name]).stdout.strip(),
    }


def db_summary() -> dict[str, Any]:
    if not DB.exists():
        return {"exists": False}
    con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=10)
    con.row_factory = sqlite3.Row
    try:
        tables = {
            row["name"]
            for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table','view')"
            )
        }
        out: dict[str, Any] = {"exists": True, "size_mb": du_mb(DB)}
        if "alerts" in tables:
            out["alerts_total"] = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            out["alerts_24h"] = con.execute(
                "SELECT COUNT(*) FROM alerts WHERE COALESCE(ingested_at,timestamp) > datetime('now','-24 hours')"
            ).fetchone()[0]
            out["by_source_24h"] = [
                dict(row) for row in con.execute(
                    """
                    SELECT source, COUNT(*) AS count
                    FROM alerts
                    WHERE COALESCE(ingested_at,timestamp) > datetime('now','-24 hours')
                    GROUP BY source ORDER BY count DESC
                    """
                )
            ]
            out["visible_24h"] = con.execute(
                """
                SELECT COUNT(*) FROM alerts
                WHERE COALESCE(ingested_at,timestamp) > datetime('now','-24 hours')
                  AND verdict NOT IN ('suppress')
                """
            ).fetchone()[0]
        if "scout_cards" in tables:
            out["scout_cards_24h"] = con.execute(
                "SELECT COUNT(*) FROM scout_cards WHERE created_at > datetime('now','-24 hours') AND status = 'new'"
            ).fetchone()[0]
        return out
    finally:
        con.close()


def corpus_summary() -> dict[str, Any]:
    if not CORPUS.exists():
        return {"exists": False}
    con = sqlite3.connect(f"file:{CORPUS}?mode=ro", uri=True, timeout=10)
    con.row_factory = sqlite3.Row
    try:
        return {
            "exists": True,
            "size_mb": du_mb(CORPUS),
            "documents": con.execute("SELECT COUNT(*) FROM documents").fetchone()[0],
            "by_category": [
                dict(row) for row in con.execute(
                    "SELECT category, COUNT(*) AS count FROM documents GROUP BY category ORDER BY count DESC"
                )
            ],
        }
    finally:
        con.close()


def pcap_summary() -> dict[str, Any]:
    files = sorted(PCAP_RING.glob("shallot-ring.pcap*"))
    total = sum(p.stat().st_size for p in files if p.exists())
    newest = max(files, key=lambda p: p.stat().st_mtime, default=None)
    return {
        "ring_dir": str(PCAP_RING),
        "ring_exists": PCAP_RING.exists(),
        "ring_file_count": len(files),
        "ring_mb": round(total / (1024 * 1024), 2),
        "newest": str(newest) if newest else "",
        "newest_mtime": (
            datetime.fromtimestamp(newest.stat().st_mtime, timezone.utc).isoformat()
            if newest else ""
        ),
        "evidence_dir": str(EVIDENCE_DIR),
        "evidence_mb": du_mb(EVIDENCE_DIR),
    }


def posture_summary() -> dict[str, Any]:
    if not POSTURE_DB.exists():
        return {"exists": False}
    con = sqlite3.connect(f"file:{POSTURE_DB}?mode=ro", uri=True, timeout=10)
    con.row_factory = sqlite3.Row
    try:
        tables = {
            row["name"]
            for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        counts = {}
        for name in (
            "posture_findings", "sensor_coverage", "service_baselines",
            "drift_snapshots", "execution_ledger", "dns_memory",
            "egress_memory", "rarity_counts", "alert_memory",
            "suppression_hygiene", "escalation_cards",
        ):
            if name in tables:
                counts[name] = con.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
        open_findings = []
        if "posture_findings" in tables:
            open_findings = [
                dict(row) for row in con.execute(
                    "SELECT category,severity,title,entity,ts FROM posture_findings WHERE status='open' ORDER BY ts DESC LIMIT 10"
                )
            ]
        return {
            "exists": True,
            "size_mb": du_mb(POSTURE_DB),
            "report": str(POSTURE_REPORT),
            "counts": counts,
            "open_findings": open_findings,
        }
    finally:
        con.close()


def gpu_summary() -> dict[str, Any]:
    if not shutil.which("nvidia-smi"):
        return {"available": False}
    proc = run([
        "nvidia-smi",
        "--query-gpu=temperature.gpu,power.draw,power.limit,utilization.gpu,memory.used",
        "--format=csv,noheader,nounits",
    ])
    vals = [v.strip() for v in proc.stdout.strip().split(",")]
    if len(vals) != 5:
        return {"available": True, "raw": proc.stdout.strip()}
    return {
        "available": True,
        "temp_c": float(vals[0]),
        "power_w": float(vals[1]),
        "power_limit_w": float(vals[2]),
        "util_pct": float(vals[3]),
        "memory_mib": float(vals[4]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    payload = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "host": run(["hostname"]).stdout.strip(),
        "services": {
            name: service_state(name)
            for name in (
                "shallotd.service",
                "suricata.service",
                "shallot-pcap-ring.service",
                "shallot-corpus-refresh.timer",
                "shallot-inventory-scan.timer",
                "shallot-ladder-build.timer",
                "shallot-ladder-haiku.timer",
                "shallot-ladder-sonnet.timer",
                "shallot-ladder-opus.timer",
                "shallot-posture-scan.timer",
                "shallot-honey-listener.service",
            )
        },
        "db": db_summary(),
        "corpus": corpus_summary(),
        "pcap": pcap_summary(),
        "posture": posture_summary(),
        "gpu": gpu_summary(),
        "disk": {
            "repo_mb": du_mb(ROOT),
            "suricata_log_mb": du_mb(Path("/var/log/suricata")),
        },
        "memory": run(["free", "-m"]).stdout.strip().splitlines(),
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
