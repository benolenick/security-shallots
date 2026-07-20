#!/usr/bin/env python3
"""Generate reviewed node-local invariants for Edge Scout.

The output is a small JSON file consumed by Scout. It is intentionally
conservative: it adds facts and watch terms, not malicious/benign judgments.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "shallots.db"
DEFAULT_OUT = ROOT / "data" / "scout_node_invariants.json"
DEFAULT_REPORT_DIR = ROOT / "data" / "elder_node_audit"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def query(con: sqlite3.Connection, sql: str, params: tuple[Any, ...] = (), limit: int = 200) -> list[dict[str, Any]]:
    return [dict(r) for r in con.execute(sql, params).fetchmany(limit)]


def collect_state(db: Path) -> dict[str, Any]:
    if not db.exists():
        return {
            "generated_at": utc_now(),
            "warning": f"database not found: {db}",
            "top_sources": [],
            "top_src_ports": [],
            "recent_scout_cards": [],
            "device_baselines": [],
        }
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        return {
            "generated_at": utc_now(),
            "top_sources": query(
                con,
                """
                SELECT source, severity, verdict, COUNT(*) AS count
                FROM alerts
                GROUP BY source, severity, verdict
                ORDER BY count DESC
                LIMIT 40
                """,
            ),
            "top_src_ports": query(
                con,
                """
                SELECT src_ip, dst_port, COUNT(*) AS count
                FROM alerts
                WHERE src_ip != '' AND dst_port > 0
                GROUP BY src_ip, dst_port
                ORDER BY count DESC
                LIMIT 80
                """,
            ),
            "recent_scout_cards": query(
                con,
                """
                SELECT sc.created_at, sc.score, sc.reasons, sc.context_facts,
                       a.source, a.title, a.category, a.src_ip, a.dst_ip, a.dst_port
                FROM scout_cards sc
                JOIN alerts a ON a.id = sc.alert_id
                WHERE sc.status = 'new'
                ORDER BY sc.created_at DESC
                LIMIT 40
                """,
            ),
            "device_baselines": query(
                con,
                """
                SELECT ip, asset_name, profile_json, baseline_updated
                FROM device_baselines
                ORDER BY baseline_updated DESC
                LIMIT 80
                """,
            ),
        }
    finally:
        con.close()


def default_invariants() -> dict[str, Any]:
    return {
        "version": 1,
        "created_at": utc_now(),
        "reviewer_model": "local_default",
        "status": "approved",
        "critical_hosts": ["192.168.0.172"],
        "host_roles": {
            "192.168.0.172": ["host01", "security_shallots_control_plane"],
            "192.168.0.1": ["router", "dlink_syslog_expected_source"],
        },
        "management_ports": [22, 3389, 445, 5985, 5986, 4000, 8844, 8855],
        "volume_anomaly_terms": [
            "large outbound transfer",
            "high-byte outbound",
            "exfil",
            "18gb",
            "gb to a first-seen",
            "sent 18",
        ],
        "suspicious_process_terms": [
            "powershell",
            "pwsh",
            "cmd.exe",
            "wscript",
            "cscript",
            "rundll32",
            "regsvr32",
            "mshta",
            "curl",
            "wget",
        ],
        "watched_dns_tlds": ["zip", "mov", "country", "kim", "gq", "tk", "top", "xyz"],
        "notes": [
            "These invariants only add candidate-card reasons. They do not mark events malicious or benign.",
            "Use process/volume/TLD terms as weak black-swan surfacing hooks when paired with rarity or control-plane context.",
        ],
    }


def call_elder(state: dict[str, Any], model: str, timeout: int) -> dict[str, Any]:
    prompt = {
        "task": (
            "Review live Security Shallots node state and propose a conservative "
            "Scout invariant JSON. Do not decide malicious/benign. Do not add broad "
            "suppression rules. Prefer facts and narrow watch terms that help catch "
            "black-swan-like invariant violations."
        ),
        "required_schema": {
            "critical_hosts": ["ip strings"],
            "host_roles": {"ip": ["role strings"]},
            "management_ports": [22],
            "volume_anomaly_terms": ["lowercase phrase"],
            "suspicious_process_terms": ["lowercase process or term"],
            "watched_dns_tlds": ["tld without dot"],
            "rationale": ["short strings"],
        },
        "live_state": state,
        "starter_invariants": default_invariants(),
    }
    proc = subprocess.run(
        ["claude", "-p", "--model", model, "--output-format", "json"],
        input="You are a skeptical elder audit model. Return JSON only.\n\n" + json.dumps(prompt, indent=2, sort_keys=True),
        text=True,
        capture_output=True,
        timeout=timeout,
        check=True,
    )
    outer = json.loads(proc.stdout)
    raw = str(outer.get("result", "{}")).strip()
    if raw.startswith("```"):
        raw = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    return json.loads(raw)


def normalize(elder: dict[str, Any] | None, model: str) -> dict[str, Any]:
    base = default_invariants()
    if elder:
        for key in (
            "critical_hosts",
            "host_roles",
            "management_ports",
            "volume_anomaly_terms",
            "suspicious_process_terms",
            "watched_dns_tlds",
        ):
            if key in elder:
                base[key] = elder[key]
        if elder.get("rationale"):
            base["elder_rationale"] = elder["rationale"]
    base["created_at"] = utc_now()
    base["reviewer_model"] = model
    base["status"] = "approved"
    return base


def run(args: argparse.Namespace) -> dict[str, Any]:
    state = collect_state(args.db)
    started = time.perf_counter()
    elder: dict[str, Any] | None = None
    error = ""
    if args.model:
        try:
            elder = call_elder(state, args.model, args.timeout)
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
    invariants = normalize(elder, args.model or "local_default")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(invariants, indent=2, sort_keys=True) + "\n")

    args.report_dir.mkdir(parents=True, exist_ok=True)
    report_path = args.report_dir / f"elder-node-audit-{int(time.time())}.json"
    report = {
        "status": "ok" if not error else "fallback_used",
        "latency_sec": round(time.perf_counter() - started, 3),
        "model": args.model,
        "error": error,
        "state": state,
        "elder_raw": elder,
        "invariants": invariants,
        "out": str(args.out),
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n")
    return {**report, "report_path": str(report_path)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR)
    parser.add_argument("--model", default="opus", help="claude model, or empty to use local defaults")
    parser.add_argument("--timeout", type=int, default=420)
    args = parser.parse_args()
    result = run(args)
    print(json.dumps({
        "status": result["status"],
        "latency_sec": result["latency_sec"],
        "model": result["model"],
        "error": result["error"],
        "out": result["out"],
        "report_path": result["report_path"],
        "invariants": result["invariants"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
