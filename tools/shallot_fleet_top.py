#!/usr/bin/env python3
"""Top-like fleet status view from central Shallots heartbeats."""

from __future__ import annotations

import argparse
import asyncio
import json
import socket
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shallots.config import load_config
from shallots.store.db import AlertDB

SYNTH_PREFIXES = ("shallot-load-", "shallot-experiment", "shallot-auth-boundary", "tls-smoke")
EXPECTED_AGENTS = ("host01", "host03", "host04", "host02")
REQUIRED_MONITORS = ("anti_tamper", "session")
CANARY_MONITORS = {"network_egress": ("host01", "host03", "host04", "host02")}
CANARY_PROMOTION_MIN_EVENTS = 10
CANARY_ESTIMATED_EVENT_SECONDS = 180
CANARY_SIGNAL_QUIET_SECONDS = 3600


def _parse_ts(raw: str) -> datetime | None:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _health(row: dict) -> dict:
    try:
        parsed = json.loads(row.get("health") or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def _status_rows(db_path: str) -> dict[str, dict]:
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute("SELECT * FROM agent_status").fetchall()
        return {str(row["agent_name"]): dict(row) for row in rows}
    finally:
        con.close()


def _fmt_age(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    return f"{seconds // 3600}h{seconds % 3600 // 60:02d}m"


def _state(age: int, health: dict) -> str:
    mode = str(health.get("state") or "unknown")
    if age > 900:
        return "OFFLINE"
    if age > 360:
        return f"STALE/{mode}"
    return mode


def _warnings(row: dict) -> list[str]:
    warnings: list[str] = []
    if row["age_sec"] > 900:
        warnings.append("offline")
    elif row["age_sec"] > 360:
        warnings.append("stale")
    try:
        if row["disk_used_pct"] != "" and float(row["disk_used_pct"]) >= 85.0:
            warnings.append("disk>=85%")
        elif row["disk_used_pct"] != "" and float(row["disk_used_pct"]) >= 80.0:
            warnings.append("disk>=80%")
    except (TypeError, ValueError):
        pass
    try:
        if row["mem_used_pct"] != "" and float(row["mem_used_pct"]) >= 90.0:
            warnings.append("mem>=90%")
    except (TypeError, ValueError):
        pass
    try:
        if row["load_per_core"] != "" and float(row["load_per_core"]) >= 1.5:
            warnings.append("load/core>=1.5")
    except (TypeError, ValueError):
        pass
    if row.get("webhook_ok") is False:
        warnings.append("webhook_failed")
    return warnings


def _resource_detail(row: dict) -> str:
    parts: list[str] = [str(row.get("agent"))]
    disk = row.get("disk_used_pct")
    if disk not in ("", None):
        detail = f"disk={disk}%"
        free = row.get("disk_free_gb")
        if free not in ("", None):
            detail += f" free={free}GB"
        parts.append(detail)
    mem = row.get("mem_used_pct")
    if mem not in ("", None):
        parts.append(f"mem={mem}%")
    load = row.get("load_per_core")
    if load not in ("", None):
        parts.append(f"load/core={load}")
    return " ".join(parts)


def _top_cpu_processes(limit: int = 5) -> list[dict]:
    try:
        result = subprocess.run(
            ["ps", "-eo", "pid,comm,pcpu,args", "--sort=-pcpu"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except Exception:
        return []
    if result.returncode != 0:
        return []
    processes: list[dict] = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.strip().split(None, 3)
        if len(parts) < 3:
            continue
        pid, command, cpu = parts[:3]
        args = parts[3] if len(parts) > 3 else command
        try:
            cpu_float = round(float(cpu), 1)
        except ValueError:
            continue
        processes.append(
            {
                "pid": int(pid) if pid.isdigit() else pid,
                "command": command,
                "cpu_pct": cpu_float,
                "args": args[:180],
            }
        )
        if len(processes) >= limit:
            break
    return processes


def _local_load_diagnostics(load_warn: list[str]) -> dict[str, dict]:
    hostname = socket.gethostname().split(".", 1)[0]
    if hostname not in load_warn:
        return {}
    top = _top_cpu_processes()
    return {hostname: {"top_cpu_processes": top}} if top else {}


def _top_cpu_summary(processes: list[dict]) -> str:
    parts = []
    for proc in processes[:3]:
        command = str(proc.get("command") or "?")
        cpu = proc.get("cpu_pct")
        parts.append(f"{command}:{cpu}%")
    return ", ".join(parts)


def fleet_health_summary(
    rows: list[dict],
    expected_agents: tuple[str, ...] = EXPECTED_AGENTS,
    resource_diagnostics: dict[str, dict] | None = None,
) -> dict:
    by_agent = {str(row.get("agent")): row for row in rows}
    missing = [agent for agent in expected_agents if agent not in by_agent]
    stale = [
        str(row.get("agent"))
        for row in rows
        if "stale" in (row.get("warnings") or []) or str(row.get("state", "")).startswith("STALE/")
    ]
    offline = [
        str(row.get("agent"))
        for row in rows
        if "offline" in (row.get("warnings") or []) or str(row.get("state", "")).startswith("OFFLINE")
    ]
    webhook_failed = [str(row.get("agent")) for row in rows if "webhook_failed" in (row.get("warnings") or [])]
    disk_warn = [str(row.get("agent")) for row in rows if any(str(w).startswith("disk>=") for w in row.get("warnings") or [])]
    mem_warn = [str(row.get("agent")) for row in rows if "mem>=90%" in (row.get("warnings") or [])]
    load_warn = [str(row.get("agent")) for row in rows if "load/core>=1.5" in (row.get("warnings") or [])]
    warning_agents = [str(row.get("agent")) for row in rows if row.get("warnings")]

    blockers: list[str] = []
    warnings: list[str] = []
    strengths: list[str] = []
    next_actions: list[str] = []
    resource_diagnostics = resource_diagnostics or {}

    if missing:
        blockers.append("expected_agents_missing")
        next_actions.append("Install or restart Argus on missing expected agents: " + ", ".join(missing))
    if offline:
        blockers.append("agents_offline")
        next_actions.append("Restore offline agents: " + ", ".join(offline))
    if webhook_failed:
        blockers.append("agent_webhook_failed")
        next_actions.append("Fix agent webhook delivery: " + ", ".join(webhook_failed))
    if stale:
        warnings.append("agents_stale:" + ",".join(stale))
        next_actions.append("Check stale agent heartbeats: " + ", ".join(stale))
    if disk_warn:
        warnings.append("disk_pressure:" + ",".join(disk_warn))
        details = [_resource_detail(by_agent[agent]) for agent in disk_warn if agent in by_agent]
        next_actions.append("Free disk or move data on: " + "; ".join(details or disk_warn))
    if mem_warn:
        warnings.append("memory_pressure:" + ",".join(mem_warn))
        details = [_resource_detail(by_agent[agent]) for agent in mem_warn if agent in by_agent]
        next_actions.append("Reduce memory pressure on: " + "; ".join(details or mem_warn))
    if load_warn:
        warnings.append("load_pressure:" + ",".join(load_warn))
        details = [_resource_detail(by_agent[agent]) for agent in load_warn if agent in by_agent]
        diagnostic_bits = []
        for agent in load_warn:
            top = (resource_diagnostics.get(agent) or {}).get("top_cpu_processes") or []
            if top:
                diagnostic_bits.append(f"{agent} top_cpu={_top_cpu_summary(top)}")
        diagnostic = ("; " + "; ".join(diagnostic_bits)) if diagnostic_bits else ""
        next_actions.append("Check high load on: " + "; ".join(details or load_warn) + diagnostic)

    if not missing and len(rows) >= len(expected_agents):
        strengths.append("expected_agents_reporting")
    if not stale and not offline:
        strengths.append("heartbeats_current")
    if not webhook_failed:
        strengths.append("webhooks_healthy")
    if not warning_agents:
        strengths.append("no_agent_warnings")

    status = "ready"
    if blockers:
        status = "not_ready"
    elif warnings:
        status = "watch"
    if not next_actions and status == "ready":
        next_actions.append("Continue monitoring agent heartbeats and resource pressure.")
    monitor_coverage = fleet_monitor_coverage(rows, expected_agents)
    if monitor_coverage["blockers"]:
        blockers.extend(monitor_coverage["blockers"])
        status = "not_ready"
    if monitor_coverage["warnings"]:
        warnings.extend(monitor_coverage["warnings"])
        if status == "ready":
            status = "watch"
    for action in monitor_coverage["next_actions"]:
        if action not in next_actions:
            next_actions.append(action)

    return {
        "status": status,
        "expected_agents": list(expected_agents),
        "agent_count": len(rows),
        "online_count": len([row for row in rows if not str(row.get("state", "")).startswith("OFFLINE")]),
        "missing_agents": missing,
        "warning_agents": warning_agents,
        "blockers": blockers,
        "warnings": warnings,
        "strengths": strengths,
        "next_actions": next_actions,
        "resource_diagnostics": resource_diagnostics,
        "monitor_coverage": monitor_coverage,
    }


def compact_fleet_status(summary: dict, rows: list[dict]) -> dict:
    coverage = summary.get("monitor_coverage") or {}
    canary_monitors = {}
    for name, item in (coverage.get("canary_monitors") or {}).items():
        canary_monitors[name] = {
            "expected_agents": item.get("expected_agents") or [],
            "present_agents": item.get("present_agents") or [],
            "stable_agents": item.get("stable_agents") or [],
            "promotion_eligible_agents": item.get("promotion_eligible_agents") or [],
            "next_promotion_target": item.get("next_promotion_target"),
            "promotion_min_events": item.get("promotion_min_events"),
            "estimated_event_seconds": item.get("estimated_event_seconds"),
            "estimated_seconds_remaining": item.get("estimated_seconds_remaining"),
            "waiting_agents": item.get("waiting_agents") or [],
        }
    return {
        "status": summary.get("status"),
        "online_count": summary.get("online_count"),
        "expected_agents": summary.get("expected_agents") or [],
        "missing_agents": summary.get("missing_agents") or [],
        "warning_agents": summary.get("warning_agents") or [],
        "blockers": summary.get("blockers") or [],
        "warnings": summary.get("warnings") or [],
        "strengths": summary.get("strengths") or [],
        "next_actions": summary.get("next_actions") or [],
        "resource_diagnostics": {
            agent: {
                "top_cpu_processes": (detail.get("top_cpu_processes") or [])[:3],
            }
            for agent, detail in (summary.get("resource_diagnostics") or {}).items()
        },
        "monitor_coverage": {
            "status": coverage.get("status"),
            "required_monitors": coverage.get("required_monitors") or [],
            "blockers": coverage.get("blockers") or [],
            "warnings": coverage.get("warnings") or [],
            "next_actions": coverage.get("next_actions") or [],
            "canary_monitors": canary_monitors,
        },
        "agents": [
            {
                "agent": row.get("agent"),
                "state": row.get("state"),
                "age_sec": row.get("age_sec"),
                "ip": row.get("ip"),
                "webhook_ok": row.get("webhook_ok"),
                "load_per_core": row.get("load_per_core"),
                "mem_used_pct": row.get("mem_used_pct"),
                "disk_used_pct": row.get("disk_used_pct"),
                "disk_free_gb": row.get("disk_free_gb"),
                "events_emitted": row.get("events_emitted"),
                "non_heartbeat_events": row.get("non_heartbeat_events"),
                "monitors": row.get("monitors"),
                "warnings": row.get("warnings") or [],
            }
            for row in rows
        ],
    }


def _monitor_set(row: dict) -> set[str]:
    raw = row.get("monitors") or ""
    if isinstance(raw, str):
        return {item.strip() for item in raw.split(",") if item.strip()}
    return {str(item).strip() for item in raw if str(item).strip()}


def fleet_monitor_coverage(rows: list[dict], expected_agents: tuple[str, ...] = EXPECTED_AGENTS) -> dict:
    by_agent = {str(row.get("agent")): row for row in rows}
    per_agent: dict[str, dict] = {}
    blockers: list[str] = []
    warnings: list[str] = []
    next_actions: list[str] = []

    for agent in expected_agents:
        monitors = _monitor_set(by_agent.get(agent, {}))
        required_missing = [name for name in REQUIRED_MONITORS if name not in monitors]
        canary_expected = [name for name, agents in CANARY_MONITORS.items() if agent in agents]
        canary_present = [name for name in canary_expected if name in monitors]
        canary_missing = [name for name in canary_expected if name not in monitors]
        if required_missing:
            blockers.append(f"{agent}:required_monitors_missing:{','.join(required_missing)}")
            next_actions.append(f"Restore required Argus monitors on {agent}: {', '.join(required_missing)}")
        if canary_missing:
            warnings.append(f"{agent}:canary_monitors_missing:{','.join(canary_missing)}")
            next_actions.append(f"Complete or roll back canary monitors on {agent}: {', '.join(canary_missing)}")
        per_agent[agent] = {
            "monitors": sorted(monitors),
            "required_missing": required_missing,
            "canary_expected": canary_expected,
            "canary_present": canary_present,
            "canary_missing": canary_missing,
        }

    canaries = {}
    for name, agents in CANARY_MONITORS.items():
        states = {agent: _canary_agent_state(name, by_agent.get(agent, {})) for agent in agents}
        target = _canary_next_target(states)
        canaries[name] = {
            "expected_agents": list(agents),
            "present_agents": [agent for agent, state in states.items() if state["present"]],
            "stable_agents": [agent for agent, state in states.items() if state["stable"]],
            "promotion_min_events": CANARY_PROMOTION_MIN_EVENTS,
            "estimated_event_seconds": CANARY_ESTIMATED_EVENT_SECONDS,
            "promotion_eligible_agents": [
                agent for agent, state in states.items() if state["promotion_eligible"]
            ],
            "waiting_agents": _canary_waiting_agents(states),
            "estimated_seconds_remaining": _canary_estimated_seconds_remaining(states),
            "next_promotion_target": target,
            "agents": states,
        }
    status = "ok"
    if blockers:
        status = "gap"
    elif warnings:
        status = "watch"
    return {
        "status": status,
        "required_monitors": list(REQUIRED_MONITORS),
        "canary_monitors": canaries,
        "per_agent": per_agent,
        "blockers": blockers,
        "warnings": warnings,
        "next_actions": next_actions,
    }


def _canary_agent_state(name: str, row: dict) -> dict:
    monitors = _monitor_set(row)
    present = name in monitors
    try:
        non_heartbeat = int(row.get("non_heartbeat_events") or 0)
    except (TypeError, ValueError):
        non_heartbeat = 0
    try:
        events_emitted = int(row.get("events_emitted") or 0)
    except (TypeError, ValueError):
        events_emitted = 0
    webhook_ok = row.get("webhook_ok")
    heartbeat_age = row.get("age_sec")
    stable = present and _canary_stable(name, row)
    if not stable:
        promotion_reason = "not_stable"
    elif events_emitted < CANARY_PROMOTION_MIN_EVENTS:
        promotion_reason = f"needs_{CANARY_PROMOTION_MIN_EVENTS}_clean_events"
    else:
        promotion_reason = "eligible"
    events_remaining = max(0, CANARY_PROMOTION_MIN_EVENTS - events_emitted)
    estimated_seconds = _canary_agent_estimated_seconds_remaining(
        events_remaining=events_remaining,
        heartbeat_age=heartbeat_age,
        stable=stable,
    )
    return {
        "present": present,
        "stable": stable,
        "promotion_eligible": stable and events_emitted >= CANARY_PROMOTION_MIN_EVENTS,
        "promotion_reason": promotion_reason,
        "events_remaining": events_remaining,
        "estimated_seconds_remaining": estimated_seconds,
        "estimated_minutes_remaining": round(estimated_seconds / 60, 1) if estimated_seconds is not None else None,
        "heartbeat_age_sec": heartbeat_age,
        "webhook_ok": webhook_ok,
        "webhook_status": row.get("webhook_status"),
        "events_emitted": events_emitted,
        "non_heartbeat_events": non_heartbeat,
        "last_event_type": row.get("last_event_type") or "",
        "last_event_age_sec": row.get("event_age_sec"),
    }


def _canary_agent_estimated_seconds_remaining(
    *,
    events_remaining: int,
    heartbeat_age: object,
    stable: bool,
) -> int | None:
    if not stable or events_remaining <= 0:
        return 0 if stable else None
    try:
        age = max(0, int(heartbeat_age or 0))
    except (TypeError, ValueError):
        age = 0
    next_event_seconds = max(0, CANARY_ESTIMATED_EVENT_SECONDS - min(age, CANARY_ESTIMATED_EVENT_SECONDS))
    return next_event_seconds + ((events_remaining - 1) * CANARY_ESTIMATED_EVENT_SECONDS)


def _canary_waiting_agents(states: dict[str, dict]) -> list[dict]:
    waiting = [
        {
            "agent": agent,
            "events_remaining": int(state.get("events_remaining") or 0),
            "estimated_seconds_remaining": state.get("estimated_seconds_remaining"),
            "estimated_minutes_remaining": state.get("estimated_minutes_remaining"),
            "reason": state.get("promotion_reason", ""),
        }
        for agent, state in states.items()
        if state.get("stable") and not state.get("promotion_eligible")
    ]
    return sorted(waiting, key=lambda item: (item["events_remaining"], item["agent"]))


def _canary_estimated_seconds_remaining(states: dict[str, dict]) -> int | None:
    waiting = [
        state.get("estimated_seconds_remaining")
        for state in states.values()
        if state.get("stable") and not state.get("promotion_eligible")
    ]
    numeric = [int(value) for value in waiting if isinstance(value, int)]
    return max(numeric) if numeric else 0


def _canary_stable(name: str, row: dict) -> bool:
    if not row:
        return False
    try:
        age = int(row.get("age_sec") or 999999)
        non_heartbeat = int(row.get("non_heartbeat_events") or 0)
    except (TypeError, ValueError):
        return False
    if age > 360 or row.get("webhook_ok") is not True:
        return False
    if non_heartbeat == 0:
        return True
    last_event_type = str(row.get("last_event_type") or "")
    if name == "network_egress" and last_event_type != "network_egress_suspicious":
        return True
    try:
        event_age = int(row.get("event_age_sec"))
    except (TypeError, ValueError):
        return False
    return event_age >= CANARY_SIGNAL_QUIET_SECONDS


def _canary_next_target(states: dict[str, dict]) -> str:
    eligible = [agent for agent, state in states.items() if state["promotion_eligible"]]
    if eligible and len(eligible) == len(states):
        return "eligible:" + ",".join(eligible)
    stable = [
        (agent, int(state.get("events_remaining") or 0))
        for agent, state in states.items()
        if state.get("stable") and not state.get("promotion_eligible")
    ]
    if stable:
        agent, remaining = sorted(stable, key=lambda item: item[1])[0]
        return f"wait:{agent}:needs_{remaining}_more_clean_events"
    unstable_present = [
        agent for agent, state in states.items()
        if state.get("present") and not state.get("stable")
    ]
    if unstable_present:
        return "stabilize:" + ",".join(unstable_present)
    missing = [agent for agent, state in states.items() if not state.get("present")]
    if missing:
        return "enable_or_rollback_canary:" + ",".join(missing)
    return "enable_or_rollback_canary"


async def main_async() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-c", "--config", default="config.yaml")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of a table")
    parser.add_argument("--summary-json", action="store_true", help="Emit fleet health summary JSON")
    parser.add_argument("--compact-json", action="store_true", help="Emit bounded fleet health JSON for logs")
    parser.add_argument("--all", action="store_true", help="Include stale test/synthetic agents")
    args = parser.parse_args()

    cfg = load_config(args.config)
    status_by_agent = _status_rows(cfg.storage.db_path)
    db = AlertDB(cfg.storage.db_path)
    await db.connect()
    rows = await db.get_agent_heartbeats()
    await db.close()

    now = datetime.now(timezone.utc)
    out = []
    for row in rows:
        agent_name = row.get("agent_name", "")
        if not args.all and agent_name.startswith(SYNTH_PREFIXES):
            continue
        health = _health(row)
        status = status_by_agent.get(agent_name, {})
        metrics = health.get("host_metrics") if isinstance(health.get("host_metrics"), dict) else {}
        telemetry = health.get("telemetry") if isinstance(health.get("telemetry"), dict) else {}
        last = _parse_ts(row.get("last_seen", ""))
        last_alert = _parse_ts(status.get("last_alert", ""))
        last_event = _parse_ts(telemetry.get("last_non_heartbeat_sent_at", ""))
        age = int((now - last).total_seconds()) if last else 999999
        alert_age = int((now - last_alert).total_seconds()) if last_alert else None
        event_age = int((now - last_event).total_seconds()) if last_event else None
        item = {
            "agent": row.get("agent_name", ""),
            "type": row.get("agent_type", ""),
            "state": _state(age, health),
            "age_sec": age,
            "alert_age_sec": alert_age,
            "event_age_sec": event_age,
            "alerts": status.get("alert_count", 0),
            "events_emitted": telemetry.get("events_emitted", ""),
            "non_heartbeat_events": telemetry.get("non_heartbeat_events_emitted", ""),
            "last_event_type": telemetry.get("last_non_heartbeat_event_type", ""),
            "webhook_ok": telemetry.get("webhook_last_ok", ""),
            "webhook_status": telemetry.get("webhook_last_status", ""),
            "ip": row.get("ip", ""),
            "load1": metrics.get("load1", ""),
            "load5": metrics.get("load5", ""),
            "load15": metrics.get("load15", ""),
            "load_per_core": metrics.get("load_per_core", ""),
            "cpu_count": metrics.get("cpu_count", ""),
            "cpu_util_pct": metrics.get("cpu_util_pct", ""),
            "cpu_temp_c": metrics.get("cpu_temp_c", ""),
            "cpu_temp_label": metrics.get("cpu_temp_label", ""),
            "uptime_seconds": metrics.get("uptime_seconds", ""),
            "mem_used_pct": metrics.get("mem_used_pct", ""),
            "mem_total_mb": metrics.get("mem_total_mb", ""),
            "mem_available_mb": metrics.get("mem_available_mb", ""),
            "disk_used_pct": metrics.get("disk_used_pct", ""),
            "disk_free_gb": metrics.get("disk_free_gb", ""),
            "gpu_count": metrics.get("gpu_count", 0),
            "gpus": metrics.get("gpus", []),
            "monitors": ",".join(health.get("active_monitors") or []),
            "last_seen": row.get("last_seen", ""),
            "last_alert": status.get("last_alert", ""),
        }
        item["warnings"] = _warnings(item)
        out.append(item)
    out.sort(key=lambda r: (r["state"].startswith("OFFLINE"), r["agent"]))
    load_warn = [str(row.get("agent")) for row in out if "load/core>=1.5" in (row.get("warnings") or [])]
    summary = fleet_health_summary(out, resource_diagnostics=_local_load_diagnostics(load_warn))

    if args.summary_json:
        print(json.dumps({"summary": summary, "agents": out}, indent=2, default=str))
        return 0
    if args.compact_json:
        print(json.dumps(compact_fleet_status(summary, out), indent=2, default=str))
        return 0
    if args.json:
        print(json.dumps(out, indent=2, default=str))
        return 0

    print(
        "fleet health: "
        f"status={summary['status']} online={summary['online_count']}/{len(summary['expected_agents'])} "
        f"blockers={summary['blockers']} warnings={summary['warnings']}"
    )
    if summary["next_actions"]:
        print("fleet next actions:")
        for action in summary["next_actions"]:
            print(f"  {action}")
    coverage = summary["monitor_coverage"]
    print(
        "monitor coverage: "
        f"status={coverage['status']} required={coverage['required_monitors']} "
        f"warnings={coverage['warnings']} blockers={coverage['blockers']}"
    )
    for name, item in coverage["canary_monitors"].items():
        print(
            f"  canary {name}: expected={item['expected_agents']} "
            f"present={item['present_agents']} stable={item.get('stable_agents', [])} "
            f"promotion_eligible={item.get('promotion_eligible_agents', [])}/min_events={item.get('promotion_min_events')} "
            f"next={item.get('next_promotion_target')} eta={_fmt_age(int(item.get('estimated_seconds_remaining') or 0))}"
        )
        for waiting in item.get("waiting_agents") or []:
            print(
                f"    waiting {waiting.get('agent')}: "
                f"{waiting.get('events_remaining')} clean events, "
                f"eta={_fmt_age(int(waiting.get('estimated_seconds_remaining') or 0))}"
            )
    print()
    print(
        f"{'agent':<12} {'state':<16} {'age':>6} {'ip':<15} "
        f"{'load':>6} {'l/core':>7} {'mem%':>6} {'disk%':>6} {'events':>7} {'last_evt':>8} {'alerts':>6} {'lastal':>7} wh warnings"
    )
    print("-" * 138)
    for r in out:
        last_alert = _fmt_age(r["alert_age_sec"]) if r["alert_age_sec"] is not None else "-"
        last_event = _fmt_age(r["event_age_sec"]) if r["event_age_sec"] is not None else "-"
        webhook = "ok" if r["webhook_ok"] is True else ("bad" if r["webhook_ok"] is False else "?")
        print(
            f"{r['agent']:<12} {r['state']:<16} {_fmt_age(r['age_sec']):>6} {r['ip']:<15} "
            f"{str(r['load1']):>6} {str(r['load_per_core']):>7} {str(r['mem_used_pct']):>6} "
            f"{str(r['disk_used_pct']):>6} {str(r['events_emitted']):>7} {last_event:>8} "
            f"{str(r['alerts']):>6} {last_alert:>7} {webhook:>2} "
            f"{','.join(r['warnings']) or '-'}"
        )
    warned = [r for r in out if r["warnings"]]
    if warned:
        print("\nwarnings:")
        for r in warned:
            print(f"  {r['agent']}: {', '.join(r['warnings'])}")
    return 0


def main() -> int:
    return asyncio.run(main_async())


if __name__ == "__main__":
    raise SystemExit(main())
