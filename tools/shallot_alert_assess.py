#!/usr/bin/env python3
"""Assess alert noise and incident-worthy signals for a recent window."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shallots.config import Config, load_config
from shallots.pipeline.network_rules import network_rule_hits


REAL_HOSTS = {"host02", "host01", "host03", "host04"}
SYNTH_PREFIXES = (
    "shallot-load-",
    "shallot-experiment",
    "shallot-auth-boundary",
    "shallot-syslog-canary-test",
    "argus-scout-canary",
    "livecollator-",
    "liveargus-",
    "codex-thorough-",
    "promptinj-",
    "tls-smoke",
)
RAW_RATE_WARN_PER_HOUR = 300.0
VISIBLE_RATE_WARN_PER_HOUR = 10.0
HOST_RAW_RATE_WARN_PER_DAY = 1000.0
HOST_VISIBLE_RATE_WARN_PER_DAY = 20.0
HOST_SUPPRESSED_REAL_RATE_WARN_PER_DAY = 20.0
SYNTHETIC_RESIDUE_WARN_PCT = 80.0
SYNTHETIC_RESIDUE_WARN_PER_DAY = 1000.0
SUPPRESSED_HIGH_RATE_WARN_PER_DAY = 5.0
DB_SIZE_WARN_BYTES = 1024 * 1024 * 1024
DB_FREELIST_WARN_BYTES = 50 * 1024 * 1024
DB_FREELIST_WARN_PCT = 20.0
ASSESSMENT_LOG_WARN_BYTES = 50 * 1024 * 1024
BASELINE_LOOKBACK_HOURS = 24
BASELINE_MIN_HISTORY_HOURS = 6
BASELINE_REAL_SPIKE_RATIO = 5.0
BASELINE_VISIBLE_SPIKE_RATIO = 3.0
TEXT_VOLUME_HOST_LIMIT = 30
JSON_VOLUME_HOST_LIMIT = 12


def _cutoff(hours: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")


def _asset(row: sqlite3.Row) -> str:
    if row["src_asset"]:
        return row["src_asset"]
    if str(row["source"] or "").lower() == "argus":
        try:
            raw = json.loads(str(row["raw"] or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            raw = {}
        host = str(raw.get("host") or "")
        if host:
            return host
    if row["src_ip"]:
        return row["src_ip"]
    source_ref = str(row["source_ref"] or "")
    if source_ref.startswith("watchdog:"):
        return source_ref.split(":", 1)[1] or "(blank)"
    title = str(row["title"] or "")
    if title.lower().startswith("agent offline:"):
        return title.split(":", 1)[1].strip() or "(blank)"
    return "(blank)"


def _is_synthetic(row: sqlite3.Row) -> bool:
    text = " ".join(
        str(row[k] or "")
        for k in ("title", "description", "category", "src_asset", "source_ref", "raw")
    )
    low = text.lower()
    return (
        "synthetic" in low
        or "experiment" in low
        or "edge_canary" in low
        or "edge_methodology/prompt_injection" in low
        or any(p in text for p in SYNTH_PREFIXES)
    )


def _visible(row: sqlite3.Row) -> bool:
    return row["verdict"] != "suppress" and not _is_synthetic(row)


def _incident_worthy(row: sqlite3.Row) -> bool:
    if not _visible(row):
        return False
    if network_rule_hits(row):
        return True
    title = (row["title"] or "").lower()
    category = (row["category"] or "").lower()
    sev = (row["severity"] or "").lower()
    if "agent offline" in title and _asset(row) in REAL_HOSTS:
        return True
    if sev == "critical" and "heartbeat overdue" not in title:
        return True
    if any(tok in category for tok in ("malware", "trojan", "exploit", "credential", "lateral")):
        return True
    if any(tok in title for tok in ("malware", "trojan", "exploit", "credential", "lateral", "known-bad")):
        return True
    return False


def _trusted_suppression(row: sqlite3.Row) -> bool:
    title = str(row["title"] or "").lower()
    description = str(row["description"] or "").lower()
    category = str(row["category"] or "").lower()
    source = str(row["source"] or "").lower()
    source_ref = str(row["source_ref"] or "").lower()
    reasoning = str(row["ai_reasoning"] or "").lower()
    severity = str(row["severity"] or "").lower()
    raw = str(row["raw"] or "").lower()
    if "operator classification: false positive" in reasoning:
        return True
    if "operator calibration: known false positive" in reasoning:
        return True
    if "operator-approved rollout repair:" in reasoning:
        return True
    if "operator broad-enable calibration:" in reasoning:
        return True
    if "operator maintenance" in reasoning:
        return True
    if "operator live test:" in reasoning:
        return True
    if "native housekeeping:" in reasoning:
        return True
    if "native suppression: title matched" in reasoning:
        return True
    if "native suppression: routine/undetailed persistence maintenance" in reasoning:
        return True
    if "native suppression: malformed argus session fields" in reasoning:
        return True
    if "egress_watcher loopback self-test" in reasoning:
        return True
    if source == "syslog" and title.startswith("syslog [user]") and row["src_ip"] == "192.168.0.1":
        return True
    if title.startswith("agent offline:") and (
        category == "agent_health" or source_ref.startswith("watchdog:")
    ):
        return True
    if "heartbeat overdue" in title and category == "agent_health":
        return True
    if (
        source == "argus"
        and source_ref == "state_change"
        and category == "state_management"
        and severity == "low"
        and title.startswith("state changed:")
    ):
        return True
    if source == "syslog" and "test codex" in f"{description} {raw}":
        return True
    return False


def _file_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _db_storage_stats(db_path: str) -> dict[str, int | float]:
    out: dict[str, int | float] = {
        "db_bytes": _file_size(db_path),
        "page_count": 0,
        "page_size": 0,
        "freelist_count": 0,
        "freelist_bytes": 0,
        "freelist_pct": 0.0,
    }
    if not db_path or not os.path.exists(db_path):
        return out
    try:
        with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as con:
            page_count = int(con.execute("PRAGMA page_count").fetchone()[0] or 0)
            page_size = int(con.execute("PRAGMA page_size").fetchone()[0] or 0)
            freelist_count = int(con.execute("PRAGMA freelist_count").fetchone()[0] or 0)
    except sqlite3.Error:
        return out
    freelist_bytes = freelist_count * page_size
    out.update(
        {
            "page_count": page_count,
            "page_size": page_size,
            "freelist_count": freelist_count,
            "freelist_bytes": freelist_bytes,
            "freelist_pct": round((freelist_count / page_count * 100.0) if page_count else 0.0, 2),
        }
    )
    return out


def _port_listening(port: int, proto: str) -> bool:
    path = Path("/proc/net/udp" if proto == "udp" else "/proc/net/tcp")
    try:
        lines = path.read_text().splitlines()[1:]
    except OSError:
        return False
    wanted = f"{int(port):04X}"
    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[1]
        state = parts[3]
        _, _, raw_port = local.rpartition(":")
        if raw_port.upper() != wanted:
            continue
        if proto == "udp" or state == "0A":
            return True
    return False


def _parse_time(raw: str) -> datetime | None:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _hour_key(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0).isoformat()


def _source_latest(con: sqlite3.Connection, source: str) -> tuple[int, str]:
    row = con.execute(
        "SELECT COUNT(*) AS n, MAX(timestamp) AS latest FROM alerts WHERE source = ?",
        (source,),
    ).fetchone()
    if row is None:
        return 0, ""
    return int(row["n"] or 0), str(row["latest"] or "")


def _source_assets(con: sqlite3.Connection, source: str, cutoff: str) -> list[dict[str, Any]]:
    rows = con.execute(
        """
        SELECT coalesce(nullif(src_asset,''), nullif(src_ip,''), '(blank)') AS asset,
               COUNT(*) AS count,
               MAX(timestamp) AS latest
        FROM alerts
        WHERE source = ? AND timestamp >= ?
        GROUP BY asset
        ORDER BY count DESC, latest DESC
        LIMIT 12
        """,
        (source, cutoff),
    ).fetchall()
    return [dict(r) for r in rows]


def _load_expected_log_sources(path: str) -> list[dict[str, Any]]:
    if not path:
        return []
    try:
        data = yaml.safe_load(Path(path).read_text()) or {}
    except OSError:
        return []
    sources = data.get("sources", []) if isinstance(data, dict) else []
    return [s for s in sources if isinstance(s, dict) and s.get("expected", True)]


def expected_log_source_health(
    con: sqlite3.Connection,
    *,
    path: str,
    cutoff: str,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for src in _load_expected_log_sources(path):
        source_type = str(src.get("type") or "syslog")
        src_ips = [str(ip) for ip in (src.get("src_ips") or []) if str(ip)]
        hostnames = [str(h) for h in (src.get("hostnames") or []) if str(h)]
        terms = []
        params: list[Any] = [source_type]
        if src_ips:
            terms.append(f"src_ip IN ({','.join('?' for _ in src_ips)})")
            params.extend(src_ips)
        if hostnames:
            terms.append(f"src_asset IN ({','.join('?' for _ in hostnames)})")
            params.extend(hostnames)
        if not terms:
            out.append(
                {
                    "name": src.get("name", "unnamed"),
                    "type": source_type,
                    "status": "unconfigured",
                    "warnings": ["no_match_terms"],
                    "note": src.get("note", ""),
                }
            )
            continue
        where = " OR ".join(f"({term})" for term in terms)
        total_row = con.execute(
            f"SELECT COUNT(*) AS n, MAX(timestamp) AS latest FROM alerts WHERE source = ? AND ({where})",
            tuple(params),
        ).fetchone()
        window_row = con.execute(
            f"SELECT COUNT(*) AS n, MAX(timestamp) AS latest FROM alerts WHERE source = ? AND ({where}) AND timestamp >= ?",
            tuple(params + [cutoff]),
        ).fetchone()
        total = int(total_row["n"] or 0) if total_row else 0
        count_window = int(window_row["n"] or 0) if window_row else 0
        latest = str((window_row["latest"] if count_window else total_row["latest"]) or "") if total_row else ""
        status = "ok" if count_window else ("stale" if total else "missing")
        warnings = [] if status == "ok" else [f"expected_source_{status}"]
        out.append(
            {
                "name": src.get("name", "unnamed"),
                "type": source_type,
                "status": status,
                "src_ips": src_ips,
                "hostnames": hostnames,
                "count_window": count_window,
                "total_seen": total,
                "latest": latest,
                "warnings": warnings,
                "note": src.get("note", ""),
            }
        )
    return out


def network_source_health(con: sqlite3.Connection, cfg: Config, *, cutoff: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)

    if cfg.components.syslog_receiver or cfg.syslog.enabled:
        udp_ok = _port_listening(cfg.syslog.udp_port, "udp")
        tcp_ok = _port_listening(cfg.syslog.tcp_port, "tcp")
        total, latest = _source_latest(con, "syslog")
        latest_dt = _parse_time(latest)
        age = int((now - latest_dt).total_seconds()) if latest_dt else None
        assets = _source_assets(con, "syslog", cutoff)
        status = "ok" if (udp_ok or tcp_ok) and assets else "idle" if (udp_ok or tcp_ok) else "warn"
        warnings = []
        if not udp_ok:
            warnings.append(f"udp:{cfg.syslog.udp_port}:not_listening")
        if not tcp_ok:
            warnings.append(f"tcp:{cfg.syslog.tcp_port}:not_listening")
        out.append(
            {
                "source": "syslog",
                "enabled": True,
                "status": status,
                "udp_port": cfg.syslog.udp_port,
                "tcp_port": cfg.syslog.tcp_port,
                "udp_listening": udp_ok,
                "tcp_listening": tcp_ok,
                "count_window": sum(int(a["count"]) for a in assets),
                "total_seen": total,
                "latest": latest,
                "age_sec": age,
                "assets_window": assets,
                "warnings": warnings,
            }
        )
    else:
        out.append({"source": "syslog", "enabled": False, "status": "disabled", "warnings": []})

    if cfg.components.suricata:
        eve = Path(cfg.suricata.eve_path)
        exists = eve.exists()
        age = int(now.timestamp() - eve.stat().st_mtime) if exists else None
        total, latest = _source_latest(con, "suricata")
        assets = _source_assets(con, "suricata", cutoff)
        warnings = []
        if not exists:
            warnings.append("eve_missing")
        elif age is not None and age > 3600:
            warnings.append("eve_stale>1h")
        out.append(
            {
                "source": "suricata",
                "enabled": True,
                "status": "ok" if exists and not warnings else "warn",
                "eve_path": str(eve),
                "eve_exists": exists,
                "eve_age_sec": age,
                "count_window": sum(int(a["count"]) for a in assets),
                "total_seen": total,
                "latest": latest,
                "assets_window": assets,
                "warnings": warnings,
            }
        )
    else:
        out.append({"source": "suricata", "enabled": False, "status": "disabled", "warnings": []})

    if cfg.pfsense.enabled:
        total, latest = _source_latest(con, "pfsense")
        assets = _source_assets(con, "pfsense", cutoff)
        out.append(
            {
                "source": "pfsense",
                "enabled": True,
                "status": "ok" if assets else "idle",
                "count_window": sum(int(a["count"]) for a in assets),
                "total_seen": total,
                "latest": latest,
                "assets_window": assets,
                "warnings": [],
            }
        )
    else:
        out.append({"source": "pfsense", "enabled": False, "status": "disabled", "warnings": []})
    return out


def network_coverage_summary(
    sources: list[dict[str, Any]],
    expected_sources: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    enabled = [s for s in sources if s.get("enabled")]
    active_window = [s for s in enabled if int(s.get("count_window") or 0) > 0]
    listening = [
        s for s in enabled
        if s.get("source") == "syslog" and (s.get("udp_listening") or s.get("tcp_listening"))
    ]
    source_by_name = {str(s.get("source")): s for s in sources}
    gaps: list[str] = []
    if not source_by_name.get("suricata", {}).get("enabled"):
        gaps.append("packet_ids_disabled")
    pfsense_expected = any(
        str(src.get("type") or "").lower() == "pfsense"
        or str(src.get("name") or "").lower().startswith("pfsense")
        for src in (expected_sources or [])
    )
    if pfsense_expected and not source_by_name.get("pfsense", {}).get("enabled"):
        gaps.append("pfsense_disabled")
    syslog = source_by_name.get("syslog", {})
    if syslog.get("enabled") and not (syslog.get("udp_listening") or syslog.get("tcp_listening")):
        gaps.append("syslog_not_listening")
    if syslog.get("enabled") and int(syslog.get("count_window") or 0) == 0:
        gaps.append("syslog_idle_in_window")
    if not active_window:
        gaps.append("no_network_source_events_in_window")
    for src in expected_sources or []:
        if src.get("status") in {"missing", "stale", "unconfigured"}:
            gaps.append(f"expected_{src.get('type', 'source')}_{src.get('status')}:{src.get('name')}")
    blocking_gaps = [
        gap for gap in gaps
        if gap == "syslog_not_listening"
        or (gap.startswith("expected_") and ("_missing:" in gap or "_unconfigured:" in gap))
    ]
    advisory_gaps = [gap for gap in gaps if gap not in blocking_gaps]
    hard_gap = bool(blocking_gaps)
    status = "ok" if active_window and not hard_gap else ("watch" if listening and not hard_gap else "gap")
    if hard_gap:
        status = "gap"
    summary = {
        "status": status,
        "enabled_sources": [s.get("source") for s in enabled],
        "active_sources_window": [s.get("source") for s in active_window],
        "listening_sources": [s.get("source") for s in listening],
        "gaps": gaps,
        "blocking_gaps": blocking_gaps,
        "advisory_gaps": advisory_gaps,
        "expected_sources": [
            {
                "name": s.get("name"),
                "type": s.get("type"),
                "status": s.get("status"),
            }
            for s in (expected_sources or [])
        ],
    }
    summary["actions"] = network_coverage_actions(summary, expected_sources or [])
    return summary


def network_coverage_actions(
    coverage: dict[str, Any],
    expected_sources: list[dict[str, Any]],
) -> list[dict[str, str]]:
    expected_by_name = {str(src.get("name")): src for src in expected_sources}
    actions: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(gap: str, action: str, detail: str, priority: str = "normal") -> None:
        if gap in seen:
            return
        seen.add(gap)
        actions.append({"gap": gap, "priority": priority, "action": action, "detail": detail})

    for gap in coverage.get("gaps") or []:
        if gap == "syslog_not_listening":
            add(
                gap,
                "Restore syslog listener on host01",
                "Check shallotd/syslog_receiver and confirm UDP/TCP 514 are listening before chasing router config.",
                "high",
            )
        elif gap == "syslog_idle_in_window":
            add(
                gap,
                "Generate or wait for router syslog",
                "Syslog is listening but produced no events in this window; this is acceptable only if every expected source is disabled or quiet by design.",
            )
        elif gap == "no_network_source_events_in_window":
            add(
                gap,
                "Confirm at least one network source emits events",
                "Send a router test log, trigger a harmless DHCP/admin event, or enable one packet/firewall log source.",
            )
        elif gap == "packet_ids_disabled":
            add(
                gap,
                "Decide whether packet IDS is in scope",
                "Suricata is disabled; leave it disabled if router/firewall syslog is the intended network sensor, otherwise enable and tune it before treating network coverage as production-grade.",
                "low",
            )
        elif gap == "pfsense_disabled":
            add(
                gap,
                "Remove or enable pfSense coverage expectation",
                "pfSense ingestion is disabled. This is fine if no pfSense firewall is present; keep the disabled state documented so it does not look like a silent failure.",
                "low",
            )
        elif gap.startswith("expected_"):
            name = gap.rsplit(":", 1)[-1]
            src = expected_by_name.get(name, {})
            src_type = src.get("type") or "source"
            ips = ", ".join(src.get("src_ips") or [])
            hostnames = ", ".join(src.get("hostnames") or [])
            detail_bits = []
            if ips:
                detail_bits.append(f"expected IPs: {ips}")
            if hostnames:
                detail_bits.append(f"hostnames: {hostnames}")
            if src.get("note"):
                detail_bits.append(str(src.get("note")))
            detail = "; ".join(detail_bits) or "Expected source has not produced matching events."
            add(
                gap,
                f"Configure or retire expected {src_type} source {name}",
                detail,
                "high",
            )
    priority_rank = {"high": 0, "normal": 1, "low": 2}
    return sorted(actions, key=lambda item: (priority_rank.get(item["priority"], 1), item["gap"]))


def _volume_by_host(rows: list[sqlite3.Row], visible: list[sqlite3.Row], synth: list[sqlite3.Row], hours: float) -> list[dict]:
    hours = max(float(hours), 0.01)
    visible_ids = {r["id"] for r in visible}
    synth_ids = {r["id"] for r in synth}
    by_host: dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        host = _asset(r)
        by_host[host]["raw"] += 1
        if r["id"] in visible_ids:
            by_host[host]["visible"] += 1
        if r["id"] in synth_ids:
            by_host[host]["synthetic_or_experiment"] += 1
        if r["verdict"] == "suppress":
            by_host[host]["suppressed"] += 1
            if r["id"] not in synth_ids and not _trusted_suppression(r):
                by_host[host]["suppressed_non_synthetic"] += 1
    out = []
    for host, counts in sorted(by_host.items()):
        raw = int(counts["raw"])
        visible_count = int(counts["visible"])
        out.append(
            {
                "host": host,
                "raw": raw,
                "visible": visible_count,
                "suppressed": int(counts["suppressed"]),
                "suppressed_non_synthetic": int(counts["suppressed_non_synthetic"]),
                "synthetic_or_experiment": int(counts["synthetic_or_experiment"]),
                "raw_per_day": round(raw / hours * 24, 2),
                "visible_per_day": round(visible_count / hours * 24, 2),
                "suppressed_non_synthetic_per_day": round(
                    int(counts["suppressed_non_synthetic"]) / hours * 24,
                    2,
                ),
            }
        )
    return out


def _synthetic_residue(rows: list[sqlite3.Row], synth: list[sqlite3.Row], hours: float) -> dict[str, Any]:
    hours = max(float(hours), 0.01)
    raw_count = len(rows)
    synth_count = len(synth)
    by_host = Counter(_asset(row) for row in synth)
    now = datetime.now(timezone.utc)
    ages: list[float] = []
    prune_eligible_24h = 0
    for row in synth:
        ts = _parse_time(str(row["timestamp"] or ""))
        if ts is None:
            continue
        age_hours = max(0.0, (now - ts.astimezone(timezone.utc)).total_seconds() / 3600)
        ages.append(age_hours)
        if age_hours >= 24:
            prune_eligible_24h += 1
    pending = [24.0 - age for age in ages if age < 24.0]
    return {
        "count": synth_count,
        "percent_raw": round((synth_count / raw_count * 100.0) if raw_count else 0.0, 2),
        "per_day": round(synth_count / hours * 24, 2),
        "prune_eligible_24h": prune_eligible_24h,
        "oldest_age_hours": round(max(ages), 2) if ages else 0.0,
        "newest_age_hours": round(min(ages), 2) if ages else 0.0,
        "next_eligible_in_hours": round(max(0.0, min(pending)), 2) if pending else 0.0,
        "top_hosts": [
            {"host": host, "count": count, "per_day": round(count / hours * 24, 2)}
            for host, count in by_host.most_common(8)
        ],
    }


def synthetic_residue_warnings(residue: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    if float(residue.get("percent_raw") or 0) >= SYNTHETIC_RESIDUE_WARN_PCT:
        warnings.append(f"synthetic_residue>={SYNTHETIC_RESIDUE_WARN_PCT:g}pct_raw")
    if float(residue.get("per_day") or 0) >= SYNTHETIC_RESIDUE_WARN_PER_DAY:
        warnings.append(f"synthetic_residue>={SYNTHETIC_RESIDUE_WARN_PER_DAY:g}/day")
    return warnings


def synthetic_residue_next_action(residue: dict[str, Any]) -> str:
    if not synthetic_residue_warnings(residue):
        return ""
    eligible = int(residue.get("prune_eligible_24h") or 0)
    if eligible > 0:
        return (
            f"Review synthetic residue; {eligible} rows are older than 24h and prune-eligible. "
            "Run shallot_noise_housekeep.py after confirming no active load test, or let shallot-alert-assess.timer prune them."
        )
    oldest = float(residue.get("oldest_age_hours") or 0)
    next_eligible = float(residue.get("next_eligible_in_hours") or max(0.0, 24.0 - oldest))
    return (
        "Review synthetic residue; current test rows are not yet 24h prune-eligible "
        f"(oldest {oldest:g}h; next eligible in ~{next_eligible:g}h). "
        "Let shallot-alert-assess.timer age/prune them, or confirm no active load test before manual cleanup."
    )


def synthetic_residue_text(residue: dict[str, Any]) -> str:
    top_hosts = ", ".join(f"{item['host']}={item['count']}" for item in residue.get("top_hosts", [])[:4])
    return (
        "synthetic residue: "
        f"count={residue['count']} "
        f"percent_raw={residue['percent_raw']} "
        f"per_day={residue['per_day']} "
        f"prune_eligible_24h={residue.get('prune_eligible_24h', 0)} "
        f"oldest_age_hours={residue.get('oldest_age_hours', 0)} "
        f"newest_age_hours={residue.get('newest_age_hours', 0)} "
        f"top_hosts={top_hosts or 'none'}"
    )


def volume_rows_for_text(rows: list[dict[str, Any]], *, limit: int = TEXT_VOLUME_HOST_LIMIT) -> tuple[list[dict[str, Any]], int]:
    """Return the most operator-relevant host rows for bounded text output."""
    if limit <= 0:
        return [], len(rows)
    ranked = sorted(
        rows,
        key=lambda item: (
            -int(item.get("visible") or 0),
            -int(item.get("suppressed_non_synthetic") or 0),
            -int(item.get("raw") or 0),
            str(item.get("host") or ""),
        ),
    )
    shown = ranked[:limit]
    return shown, max(0, len(ranked) - len(shown))


def summary_json(summary: dict[str, Any], *, max_host_rows: int = JSON_VOLUME_HOST_LIMIT) -> dict[str, Any]:
    """Return bounded JSON for dashboards, timers, and operator status checks."""
    volume_rows, omitted_volume_rows = volume_rows_for_text(
        summary.get("volume_by_host") or [],
        limit=max_host_rows,
    )
    coverage = summary.get("network_coverage") or {}
    readiness = summary.get("readiness") or {}
    return {
        "window_hours": summary.get("window_hours"),
        "raw_alerts": summary.get("raw_alerts", 0),
        "synthetic_or_experiment": summary.get("synthetic_or_experiment", 0),
        "visible_non_synthetic": summary.get("visible_non_synthetic", 0),
        "suppressed": summary.get("suppressed", 0),
        "suppressed_non_synthetic": summary.get("suppressed_non_synthetic", 0),
        "raw_by_severity": summary.get("raw_by_severity") or {},
        "readiness": {
            "status": readiness.get("status"),
            "blockers": readiness.get("blockers") or [],
            "warnings": readiness.get("warnings") or [],
            "strengths": readiness.get("strengths") or [],
            "next_actions": readiness.get("next_actions") or [],
        },
        "volume_guardrails": summary.get("volume_guardrails") or {},
        "alert_rate_baseline": summary.get("alert_rate_baseline") or {},
        "suppression_quality": summary.get("suppression_quality") or {},
        "synthetic_residue": summary.get("synthetic_residue") or {},
        "network_coverage": {
            "status": coverage.get("status"),
            "blocking_gaps": coverage.get("blocking_gaps") or [],
            "advisory_gaps": coverage.get("advisory_gaps") or [],
            "actions": (coverage.get("actions") or [])[:8],
        },
        "network_sources": summary.get("network_sources") or [],
        "expected_log_sources": summary.get("expected_log_sources") or [],
        "incident_candidates": summary.get("incident_candidates") or [],
        "top_visible_titles": summary.get("top_visible_titles") or [],
        "top_suppressed_non_synthetic_titles": summary.get("top_suppressed_non_synthetic_titles") or [],
        "volume_by_host_top": volume_rows,
        "volume_by_host_total": len(summary.get("volume_by_host") or []),
        "volume_by_host_omitted": omitted_volume_rows,
    }


def _volume_guardrails(
    *,
    hours: float,
    raw_alerts: int,
    synthetic_alerts: int,
    visible_alerts: int,
    incident_candidates: int,
    by_host: list[dict],
    db_path: str,
    assessment_log: str,
) -> dict:
    hours = max(float(hours), 0.01)
    raw_per_hour = raw_alerts / hours
    synthetic_per_hour = synthetic_alerts / hours
    real_raw_per_hour = max(0, raw_alerts - synthetic_alerts) / hours
    visible_per_hour = visible_alerts / hours
    db_storage = _db_storage_stats(db_path)
    db_bytes = int(db_storage["db_bytes"])
    log_bytes = _file_size(assessment_log) if assessment_log else 0
    warnings: list[str] = []
    if raw_per_hour >= RAW_RATE_WARN_PER_HOUR:
        warnings.append(f"raw_rate>={RAW_RATE_WARN_PER_HOUR:g}/h")
    if visible_per_hour >= VISIBLE_RATE_WARN_PER_HOUR:
        warnings.append(f"visible_rate>={VISIBLE_RATE_WARN_PER_HOUR:g}/h")
    if incident_candidates:
        warnings.append("incident_candidates_present")
    for item in by_host:
        if item["raw_per_day"] >= HOST_RAW_RATE_WARN_PER_DAY:
            warnings.append(f"{item['host']}:raw>={HOST_RAW_RATE_WARN_PER_DAY:g}/day")
        if item["visible_per_day"] >= HOST_VISIBLE_RATE_WARN_PER_DAY:
            warnings.append(f"{item['host']}:visible>={HOST_VISIBLE_RATE_WARN_PER_DAY:g}/day")
        if item.get("suppressed_non_synthetic_per_day", 0) >= HOST_SUPPRESSED_REAL_RATE_WARN_PER_DAY:
            warnings.append(
                f"{item['host']}:suppressed_non_synthetic>={HOST_SUPPRESSED_REAL_RATE_WARN_PER_DAY:g}/day"
            )
    if db_bytes >= DB_SIZE_WARN_BYTES:
        warnings.append("db_size>=1GiB")
    if (
        db_storage["freelist_bytes"] >= DB_FREELIST_WARN_BYTES
        and db_storage["freelist_pct"] >= DB_FREELIST_WARN_PCT
    ):
        warnings.append("db_freelist>=50MiB_and>=20pct")
    if log_bytes >= ASSESSMENT_LOG_WARN_BYTES:
        warnings.append("assessment_log>=50MiB")
    return {
        "raw_per_hour": round(raw_per_hour, 2),
        "real_raw_per_hour": round(real_raw_per_hour, 2),
        "synthetic_per_hour": round(synthetic_per_hour, 2),
        "visible_per_hour": round(visible_per_hour, 2),
        "db_bytes": db_bytes,
        "db_page_count": db_storage["page_count"],
        "db_page_size": db_storage["page_size"],
        "db_freelist_count": db_storage["freelist_count"],
        "db_freelist_bytes": db_storage["freelist_bytes"],
        "db_freelist_pct": db_storage["freelist_pct"],
        "assessment_log_bytes": log_bytes,
        "warnings": warnings,
    }


def alert_rate_baseline(rows: list[sqlite3.Row], *, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    current_hour = now.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
    buckets: dict[str, Counter] = defaultdict(Counter)
    host_buckets: dict[str, dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
    for row in rows:
        ts = _parse_time(str(row["timestamp"] or ""))
        if ts is None:
            continue
        bucket = buckets[_hour_key(ts)]
        bucket["raw"] += 1
        synthetic = _is_synthetic(row)
        host_bucket = None if synthetic else host_buckets[_asset(row)][_hour_key(ts)]
        if host_bucket is not None:
            host_bucket["raw"] += 1
        if not synthetic:
            bucket["real_raw"] += 1
            if host_bucket is not None:
                host_bucket["real_raw"] += 1
        if not synthetic and not _trusted_suppression(row):
            bucket["actionable"] += 1
            if host_bucket is not None:
                host_bucket["actionable"] += 1
        if _visible(row):
            bucket["visible"] += 1
            if host_bucket is not None:
                host_bucket["visible"] += 1

    current = buckets.get(current_hour.isoformat(), Counter())
    history = [
        buckets.get((current_hour - timedelta(hours=i)).isoformat(), Counter())
        for i in range(1, BASELINE_LOOKBACK_HOURS + 1)
    ]
    history_hours = len(history)
    streak_buckets = [
        buckets.get((current_hour - timedelta(hours=i)).isoformat(), Counter())
        for i in range(0, BASELINE_LOOKBACK_HOURS + 1)
    ]

    def avg(name: str) -> float:
        return round(sum(bucket.get(name, 0) for bucket in history) / max(1, history_hours), 2)

    def quiet_streak(name: str) -> int:
        total = 0
        for bucket in streak_buckets:
            if int(bucket.get(name, 0)) != 0:
                break
            total += 1
        return total

    def median(values: list[float]) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        mid = len(ordered) // 2
        if len(ordered) % 2:
            return float(ordered[mid])
        return (ordered[mid - 1] + ordered[mid]) / 2

    def adaptive_thresholds() -> dict[str, dict[str, Any]]:
        minimums = {"raw": 100, "real_raw": 5, "actionable": 3, "visible": 3}
        out: dict[str, dict[str, Any]] = {}
        for name in ("raw", "real_raw", "actionable", "visible"):
            values = [float(bucket.get(name, 0)) for bucket in history]
            med = median(values)
            deviations = [abs(value - med) for value in values]
            mad = median(deviations)
            robust_sigma = 1.4826 * mad
            floor = minimums[name]
            threshold = max(float(floor), med + max(3.0, 6.0 * robust_sigma))
            current_value = int(current.get(name, 0))
            out[name] = {
                "median": round(med, 2),
                "mad": round(mad, 2),
                "threshold": round(threshold, 2),
                "current": current_value,
                "exceeded": bool(current_value >= threshold and current_value > med),
            }
        return out

    def host_baselines() -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for host in REAL_HOSTS:
            host_buckets.setdefault(host, defaultdict(Counter))
        for host, by_hour in host_buckets.items():
            host_current = by_hour.get(current_hour.isoformat(), Counter())
            host_history = [
                by_hour.get((current_hour - timedelta(hours=i)).isoformat(), Counter())
                for i in range(1, BASELINE_LOOKBACK_HOURS + 1)
            ]
            host_streak = [
                by_hour.get((current_hour - timedelta(hours=i)).isoformat(), Counter())
                for i in range(0, BASELINE_LOOKBACK_HOURS + 1)
            ]

            def host_avg(name: str) -> float:
                return round(sum(bucket.get(name, 0) for bucket in host_history) / max(1, history_hours), 2)

            def host_quiet(name: str) -> int:
                total = 0
                for bucket in host_streak:
                    if int(bucket.get(name, 0)) != 0:
                        break
                    total += 1
                return total

            current_counts = {
                "raw": int(host_current.get("raw", 0)),
                "real_raw": int(host_current.get("real_raw", 0)),
                "actionable": int(host_current.get("actionable", 0)),
                "visible": int(host_current.get("visible", 0)),
            }
            previous = {
                "raw": host_avg("raw"),
                "real_raw": host_avg("real_raw"),
                "actionable": host_avg("actionable"),
                "visible": host_avg("visible"),
            }
            if not any(current_counts.values()) and not any(previous.values()):
                if host not in REAL_HOSTS:
                    continue
            host_warnings: list[str] = []
            prev_real = max(float(previous["real_raw"]), 0.2)
            prev_actionable = max(float(previous["actionable"]), 0.2)
            prev_visible = max(float(previous["visible"]), 0.2)
            if current_counts["real_raw"] >= 5 and current_counts["real_raw"] / prev_real >= BASELINE_REAL_SPIKE_RATIO:
                host_warnings.append(f"{host}:real_raw_spike>={BASELINE_REAL_SPIKE_RATIO:g}x")
            if current_counts["actionable"] >= 3 and current_counts["actionable"] / prev_actionable >= BASELINE_VISIBLE_SPIKE_RATIO:
                host_warnings.append(f"{host}:actionable_spike>={BASELINE_VISIBLE_SPIKE_RATIO:g}x")
            if current_counts["visible"] >= 3 and current_counts["visible"] / prev_visible >= BASELINE_VISIBLE_SPIKE_RATIO:
                host_warnings.append(f"{host}:visible_spike>={BASELINE_VISIBLE_SPIKE_RATIO:g}x")
            out.append(
                {
                    "host": host,
                    "current": current_counts,
                    "previous_hourly_avg": previous,
                    "quiet_streak_hours": {
                        "raw": host_quiet("raw"),
                        "real_raw": host_quiet("real_raw"),
                        "actionable": host_quiet("actionable"),
                        "visible": host_quiet("visible"),
                    },
                    "warnings": host_warnings,
                }
            )
        return sorted(
            out,
            key=lambda item: (
                -int(item["current"]["actionable"]),
                -int(item["current"]["visible"]),
                -int(item["current"]["real_raw"]),
                -int(item["current"]["raw"]),
                str(item["host"]),
            ),
        )[:JSON_VOLUME_HOST_LIMIT]

    adaptive = adaptive_thresholds()
    per_host = host_baselines()
    summary = {
        "window": "current_hour_vs_previous_24h",
        "history_hours": history_hours,
        "current": {
            "raw": int(current.get("raw", 0)),
            "real_raw": int(current.get("real_raw", 0)),
            "actionable": int(current.get("actionable", 0)),
            "visible": int(current.get("visible", 0)),
        },
        "previous_hourly_avg": {
            "raw": avg("raw"),
            "real_raw": avg("real_raw"),
            "actionable": avg("actionable"),
            "visible": avg("visible"),
        },
        "quiet_streak_hours": {
            "raw": quiet_streak("raw"),
            "real_raw": quiet_streak("real_raw"),
            "actionable": quiet_streak("actionable"),
            "visible": quiet_streak("visible"),
        },
        "adaptive_thresholds": adaptive,
        "per_host": per_host,
        "warnings": [],
    }
    warnings = summary["warnings"]
    if history_hours < BASELINE_MIN_HISTORY_HOURS:
        warnings.append("baseline_history_insufficient")

    prev_real = max(float(summary["previous_hourly_avg"]["real_raw"]), 0.2)
    prev_actionable = max(float(summary["previous_hourly_avg"]["actionable"]), 0.2)
    prev_visible = max(float(summary["previous_hourly_avg"]["visible"]), 0.2)
    current_real = float(summary["current"]["real_raw"])
    current_actionable = float(summary["current"]["actionable"])
    current_visible = float(summary["current"]["visible"])
    if current_real >= 5 and current_real / prev_real >= BASELINE_REAL_SPIKE_RATIO:
        warnings.append(f"real_raw_spike>={BASELINE_REAL_SPIKE_RATIO:g}x")
    if current_actionable >= 3 and current_actionable / prev_actionable >= BASELINE_VISIBLE_SPIKE_RATIO:
        warnings.append(f"actionable_spike>={BASELINE_VISIBLE_SPIKE_RATIO:g}x")
    if current_visible >= 3 and current_visible / prev_visible >= BASELINE_VISIBLE_SPIKE_RATIO:
        warnings.append(f"visible_spike>={BASELINE_VISIBLE_SPIKE_RATIO:g}x")
    for name, item in adaptive.items():
        if item.get("exceeded"):
            warnings.append(f"adaptive_{name}_spike")
    for item in per_host:
        warnings.extend(item.get("warnings") or [])
    return summary


def suppression_quality(rows: list[sqlite3.Row], *, hours: float) -> dict[str, Any]:
    """Summarize whether suppression is hiding meaningful real alerts."""
    hours = max(float(hours), 0.01)
    now = datetime.now(timezone.utc)
    suppressed = [
        row for row in rows
        if row["verdict"] == "suppress" and not _is_synthetic(row) and not _trusted_suppression(row)
    ]
    high_rows = [
        row for row in suppressed
        if str(row["severity"] or "").lower() in {"high", "critical"}
    ]
    critical_rows = [
        row for row in suppressed
        if str(row["severity"] or "").lower() == "critical"
    ]
    network_hit_rows = [
        row for row in suppressed
        if network_rule_hits(row)
    ]
    high_per_day = len(high_rows) / hours * 24
    warnings: list[str] = []
    if critical_rows:
        warnings.append("suppressed_critical_present")
    if high_per_day >= SUPPRESSED_HIGH_RATE_WARN_PER_DAY:
        warnings.append(f"suppressed_high_or_critical>={SUPPRESSED_HIGH_RATE_WARN_PER_DAY:g}/day")
    if network_hit_rows:
        warnings.append("suppressed_network_rule_hits_present")
    examples_by_key: dict[tuple[str, str, str, str, str, str], dict[str, Any]] = {}
    seen_example_row_ids: set[Any] = set()
    for row in [*critical_rows, *network_hit_rows, *high_rows]:
        row_id = row["id"]
        if row_id in seen_example_row_ids:
            continue
        seen_example_row_ids.add(row_id)
        key = (
            _asset(row),
            str(row["source"] or ""),
            str(row["source_ref"] or ""),
            str(row["category"] or ""),
            str(row["severity"] or ""),
            str(row["title"] or ""),
        )
        ts_text = str(row["timestamp"] or "")
        ts = _parse_time(ts_text)
        item = examples_by_key.setdefault(
            key,
            {
                "asset": key[0],
                "source": key[1],
                "source_ref": key[2],
                "category": key[3],
                "severity": key[4],
                "title": key[5],
                "count": 0,
                "first_seen": ts_text,
                "latest_seen": ts_text,
                "latest_age_hours": None,
            },
        )
        item["count"] += 1
        if ts is not None:
            age_hours = round(max(0.0, (now - ts.astimezone(timezone.utc)).total_seconds() / 3600), 2)
            if item["count"] == 1:
                item["latest_age_hours"] = age_hours
            if not item["first_seen"] or ts_text < str(item["first_seen"]):
                item["first_seen"] = ts_text
            if not item["latest_seen"] or ts_text > str(item["latest_seen"]):
                item["latest_seen"] = ts_text
                item["latest_age_hours"] = age_hours
        if len(examples_by_key) >= 10:
            break
    examples = list(examples_by_key.values())
    status = "review" if warnings else "ok"
    return {
        "status": status,
        "suppressed_non_synthetic": len(suppressed),
        "suppressed_high_or_critical": len(high_rows),
        "suppressed_critical": len(critical_rows),
        "suppressed_network_rule_hits": len(network_hit_rows),
        "suppressed_high_or_critical_per_day": round(high_per_day, 2),
        "warnings": warnings,
        "examples": examples,
    }


def readiness_summary(summary: dict[str, Any]) -> dict[str, Any]:
    blockers: list[str] = []
    warnings: list[str] = []
    strengths: list[str] = []
    next_actions: list[str] = []

    coverage = summary.get("network_coverage") or {}
    guardrails = summary.get("volume_guardrails") or {}
    baseline = summary.get("alert_rate_baseline") or {}
    suppression = summary.get("suppression_quality") or {}
    network_sources = summary.get("network_sources") or []
    expected_sources = summary.get("expected_log_sources") or []

    if summary.get("incident_candidates"):
        blockers.append("incident_candidates_present")
    else:
        strengths.append("no_incident_candidates")

    volume_warnings = guardrails.get("warnings") or []
    if volume_warnings:
        warnings.extend(f"volume:{item}" for item in volume_warnings)
        if any(str(item).startswith("synthetic_residue>=") for item in volume_warnings):
            next_actions.append(synthetic_residue_next_action(summary.get("synthetic_residue") or {}))
    else:
        strengths.append("alert_volume_within_guardrails")

    baseline_warnings = [
        item for item in (baseline.get("warnings") or [])
        if item != "baseline_history_insufficient"
    ]
    if baseline_warnings:
        warnings.extend(f"baseline:{item}" for item in baseline_warnings)
    elif baseline:
        strengths.append("alert_rate_baseline_clean")

    suppression_warnings = suppression.get("warnings") or []
    if suppression_warnings:
        warnings.extend(f"suppression:{item}" for item in suppression_warnings)
    elif suppression:
        strengths.append("suppression_quality_clean")

    if coverage.get("status") == "gap":
        blockers.append("network_coverage_gap")
    elif coverage.get("status") == "watch":
        warnings.append("network_coverage_watch")
    elif coverage.get("status") == "ok":
        strengths.append("network_coverage_ok")

    high_actions = [a for a in coverage.get("actions") or [] if a.get("priority") == "high"]
    if high_actions:
        next_actions.extend(str(a.get("action")) for a in high_actions[:4])

    source_warnings = [
        f"{src.get('source') or src.get('name')}:{warning}"
        for src in [*network_sources, *expected_sources]
        for warning in (src.get("warnings") or [])
    ]
    if source_warnings:
        warnings.extend(f"source:{item}" for item in source_warnings)

    enabled_sources = [src.get("source") for src in network_sources if src.get("enabled")]
    if "syslog" in enabled_sources:
        strengths.append("syslog_receiver_enabled")

    if summary.get("raw_alerts", 0) == 0:
        strengths.append("quiet_alert_window")

    status = "ready"
    if blockers:
        status = "not_ready"
    elif warnings:
        status = "watch"

    if not next_actions and warnings:
        next_actions.append("Review warnings and either tune, document, or clear them.")
    if not next_actions and status == "ready":
        next_actions.append("Continue monitoring and re-assess after the next timer window.")

    return {
        "status": status,
        "blockers": blockers,
        "warnings": warnings,
        "strengths": strengths,
        "next_actions": next_actions,
    }


def assess_rows(
    rows: list[sqlite3.Row],
    *,
    hours: float,
    db_path: str = "",
    assessment_log: str = "",
    network_sources: list[dict[str, Any]] | None = None,
    expected_log_sources: list[dict[str, Any]] | None = None,
    baseline_rows: list[sqlite3.Row] | None = None,
) -> dict:
    raw_by_sev = Counter(r["severity"] or "" for r in rows)
    visible = [r for r in rows if _visible(r)]
    synth = [r for r in rows if _is_synthetic(r)]
    synth_ids = {r["id"] for r in synth}
    suppressed_non_synthetic = [
        r for r in rows
        if r["verdict"] == "suppress" and r["id"] not in synth_ids and not _trusted_suppression(r)
    ]
    incident = [r for r in rows if _incident_worthy(r)]

    per_host: dict[str, Counter] = defaultdict(Counter)
    for r in visible:
        per_host[_asset(r)][r["severity"] or ""] += 1

    volume_by_host = _volume_by_host(rows, visible, synth, hours)
    summary = {
        "window_hours": hours,
        "raw_alerts": len(rows),
        "synthetic_or_experiment": len(synth),
        "visible_non_synthetic": len(visible),
        "suppressed": sum(1 for r in rows if r["verdict"] == "suppress"),
        "suppressed_non_synthetic": len(suppressed_non_synthetic),
        "raw_by_severity": dict(raw_by_sev),
        "visible_by_host": {host: dict(counts) for host, counts in sorted(per_host.items())},
        "volume_by_host": volume_by_host,
        "volume_guardrails": {},
        "alert_rate_baseline": {},
        "suppression_quality": {},
        "synthetic_residue": _synthetic_residue(rows, synth, hours),
        "network_sources": network_sources or [],
        "expected_log_sources": expected_log_sources or [],
        "network_coverage": network_coverage_summary(network_sources or [], expected_log_sources or []),
        "incident_candidates": [
            {
                "timestamp": r["timestamp"],
                "asset": _asset(r),
                "source": r["source"],
                "severity": r["severity"],
                "title": r["title"],
                "verdict": r["verdict"],
                "rule_hits": [
                    {"rule_id": h.rule_id, "severity": h.severity, "reason": h.reason}
                    for h in network_rule_hits(r)
                ],
            }
            for r in incident[:25]
        ],
        "top_visible_titles": [],
        "top_suppressed_non_synthetic_titles": [],
    }
    summary["volume_guardrails"] = _volume_guardrails(
        hours=hours,
        raw_alerts=summary["raw_alerts"],
        synthetic_alerts=summary["synthetic_or_experiment"],
        visible_alerts=summary["visible_non_synthetic"],
        incident_candidates=len(summary["incident_candidates"]),
        by_host=volume_by_host,
        db_path=db_path,
        assessment_log=assessment_log,
    )
    summary["volume_guardrails"]["warnings"].extend(
        synthetic_residue_warnings(summary["synthetic_residue"])
    )
    summary["alert_rate_baseline"] = alert_rate_baseline(
        baseline_rows if baseline_rows is not None else rows
    )
    summary["suppression_quality"] = suppression_quality(rows, hours=hours)
    title_counts = Counter((r["source"], r["severity"], r["title"]) for r in visible)
    summary["top_visible_titles"] = [
        {"source": source, "severity": sev, "title": title, "count": count}
        for (source, sev, title), count in title_counts.most_common(20)
    ]
    suppressed_title_counts = Counter(
        (r["source"], r["severity"], r["title"], _asset(r))
        for r in suppressed_non_synthetic
    )
    summary["top_suppressed_non_synthetic_titles"] = [
        {"source": source, "severity": sev, "title": title, "asset": asset, "count": count}
        for (source, sev, title, asset), count in suppressed_title_counts.most_common(20)
    ]
    summary["readiness"] = readiness_summary(summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-c", "--config", default="config.yaml")
    parser.add_argument("--db", default="")
    parser.add_argument("--hours", type=float, default=24)
    parser.add_argument("--assessment-log", default="docs/ALERT_ASSESSMENT_LOG.md")
    parser.add_argument("--expected-log-sources", default="docs/NETWORK_LOG_SOURCES.yaml")
    parser.add_argument(
        "--max-host-rows",
        type=int,
        default=TEXT_VOLUME_HOST_LIMIT,
        help="Maximum volume-by-host rows to print in text mode.",
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--summary-json",
        action="store_true",
        help="Emit bounded operator JSON; use --json for the full forensic report.",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    db_path = args.db or cfg.storage.db_path
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    cutoff = _cutoff(args.hours)
    rows = list(
        con.execute(
            "SELECT * FROM alerts WHERE timestamp >= ? ORDER BY timestamp DESC",
            (cutoff,),
        )
    )
    baseline_cutoff = _cutoff(max(args.hours, BASELINE_LOOKBACK_HOURS + 1))
    baseline_rows = list(
        con.execute(
            "SELECT * FROM alerts WHERE timestamp >= ? ORDER BY timestamp DESC",
            (baseline_cutoff,),
        )
    )
    sources = network_source_health(con, cfg, cutoff=cutoff)
    expected_sources = expected_log_source_health(con, path=args.expected_log_sources, cutoff=cutoff)
    con.close()

    summary = assess_rows(
        rows,
        hours=args.hours,
        db_path=db_path,
        assessment_log=args.assessment_log,
        network_sources=sources,
        expected_log_sources=expected_sources,
        baseline_rows=baseline_rows,
    )

    if args.json:
        print(json.dumps(summary, indent=2, default=str))
        return 0
    if args.summary_json:
        print(json.dumps(summary_json(summary), indent=2, default=str))
        return 0

    print(f"window: {args.hours:g}h")
    print(f"raw alerts: {summary['raw_alerts']}")
    print(f"synthetic/experiment: {summary['synthetic_or_experiment']}")
    print(f"visible non-synthetic: {summary['visible_non_synthetic']}")
    print(f"suppressed: {summary['suppressed']}")
    print(f"suppressed non-synthetic: {summary['suppressed_non_synthetic']}")
    print(f"raw severity: {summary['raw_by_severity']}")
    readiness = summary["readiness"]
    print(
        "readiness: "
        f"status={readiness['status']} blockers={readiness['blockers']} warnings={readiness['warnings']}"
    )
    print(f"readiness strengths: {readiness['strengths']}")
    print(f"readiness next actions: {readiness['next_actions']}")
    guardrails = summary["volume_guardrails"]
    print(
        "volume: "
        f"raw/h={guardrails['raw_per_hour']} visible/h={guardrails['visible_per_hour']} "
        f"db={guardrails['db_bytes']}B "
        f"db_free={guardrails['db_freelist_bytes']}B "
        f"db_free_pct={guardrails['db_freelist_pct']} "
        f"log={guardrails['assessment_log_bytes']}B"
    )
    print(f"volume warnings: {guardrails['warnings'] or []}")
    print(synthetic_residue_text(summary["synthetic_residue"]))
    baseline = summary["alert_rate_baseline"]
    print(
        "baseline: "
        f"current={baseline['current']} "
        f"prev_hourly_avg={baseline['previous_hourly_avg']} "
        f"quiet_streak_hours={baseline['quiet_streak_hours']} "
        f"warnings={baseline['warnings'] or []}"
    )
    suppression = summary["suppression_quality"]
    print(
        "suppression quality: "
        f"status={suppression['status']} "
        f"suppressed_real={suppression['suppressed_non_synthetic']} "
        f"high_or_critical={suppression['suppressed_high_or_critical']} "
        f"network_rule_hits={suppression['suppressed_network_rule_hits']} "
        f"warnings={suppression['warnings'] or []}"
    )
    if suppression["examples"]:
        print("suppression review examples:")
        for item in suppression["examples"]:
            source_ref = f"/{item.get('source_ref')}" if item.get("source_ref") else ""
            count = int(item.get("count") or 1)
            age = item.get("latest_age_hours")
            age_text = f" latest_age_h={age}" if age is not None else ""
            print(
                f"  {item['asset']} {item['severity']} "
                f"{item['source']}{source_ref} count={count}{age_text}: {item['title']}"
            )
    volume_rows, omitted_volume_rows = volume_rows_for_text(
        summary["volume_by_host"],
        limit=args.max_host_rows,
    )
    print(f"volume by host: showing={len(volume_rows)} total={len(summary['volume_by_host'])} omitted={omitted_volume_rows}")
    for item in volume_rows:
        print(
            f"  {item['host']}: raw={item['raw']} visible={item['visible']} "
            f"suppressed={item['suppressed']} suppressed-real={item['suppressed_non_synthetic']} "
            f"raw/day={item['raw_per_day']} visible/day={item['visible_per_day']} "
            f"suppressed-real/day={item['suppressed_non_synthetic_per_day']}"
        )
    if summary["top_suppressed_non_synthetic_titles"]:
        print("top suppressed non-synthetic titles:")
        for item in summary["top_suppressed_non_synthetic_titles"]:
            print(
                f"  {item['count']}x {item['asset']} {item['severity']} "
                f"{item['source']}: {item['title']}"
            )
    print("network sources:")
    for src in summary["network_sources"]:
        if not src.get("enabled"):
            print(f"  {src['source']}: disabled")
            continue
        bits = [f"status={src.get('status')}", f"count_window={src.get('count_window', 0)}"]
        if src.get("source") == "syslog":
            bits.append(f"udp={src.get('udp_listening')}")
            bits.append(f"tcp={src.get('tcp_listening')}")
        if src.get("latest"):
            bits.append(f"latest={src.get('latest')}")
        if src.get("warnings"):
            bits.append(f"warnings={src.get('warnings')}")
        print(f"  {src['source']}: " + " ".join(bits))
    coverage = summary["network_coverage"]
    print(
        "network coverage: "
        f"status={coverage['status']} active={coverage['active_sources_window']} "
        f"listening={coverage['listening_sources']} gaps={coverage['gaps']}"
    )
    print(f"coverage blocking gaps: {coverage.get('blocking_gaps', [])}")
    print(f"coverage advisory gaps: {coverage.get('advisory_gaps', [])}")
    print("coverage actions:")
    for action in coverage.get("actions") or []:
        print(
            f"  {action.get('priority', 'normal')} {action.get('gap')}: "
            f"{action.get('action')} - {action.get('detail')}"
        )
    if not coverage.get("actions"):
        print("  none")
    print("expected log sources:")
    for src in summary["expected_log_sources"]:
        bits = [
            f"status={src.get('status')}",
            f"count_window={src.get('count_window', 0)}",
            f"total_seen={src.get('total_seen', 0)}",
        ]
        if src.get("latest"):
            bits.append(f"latest={src.get('latest')}")
        if src.get("warnings"):
            bits.append(f"warnings={src.get('warnings')}")
        print(f"  {src.get('name')}: " + " ".join(bits))
    print("visible by host:")
    for host, counts in summary["visible_by_host"].items():
        print(f"  {host}: {counts}")
    print("incident candidates:")
    for item in summary["incident_candidates"]:
        rules = ",".join(h["rule_id"] for h in item.get("rule_hits", [])) or "legacy"
        print(f"  {item['timestamp']} {item['severity']} {item['asset']} {item['title']} [{rules}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
