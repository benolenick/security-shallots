#!/usr/bin/env python3
"""Compact Security Shallots status snapshot for dashboards."""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.shallot_gate_eval import evaluate_gate
from tools.shallot_ops_sanity import _check_central_api_health, _check_shallotd_service_active
from tools.shallot_router_syslog_plan import _fingerprint as _router_fingerprint


def _run_json(args: list[str]) -> dict[str, Any]:
    completed = subprocess.run(args, check=True, text=True, capture_output=True)
    return json.loads(completed.stdout)


def _project_python() -> str:
    venv_python = ROOT / ".venv" / "bin" / "python"
    if venv_python.exists():
        return str(venv_python)
    return sys.executable


def _parse_log_heading(line: str) -> datetime | None:
    prefix = "## "
    if not line.startswith(prefix):
        return None
    raw = line[len(prefix):].strip()
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def assessment_loop_summary(
    *,
    log_path: str = "docs/ALERT_ASSESSMENT_LOG.md",
    timer_name: str = "shallot-alert-assess.timer",
) -> dict[str, Any]:
    path = Path(log_path)
    if not path.is_absolute():
        path = ROOT / path
    latest: datetime | None = None
    try:
        for line in path.read_text(errors="ignore").splitlines():
            parsed = _parse_log_heading(line)
            if parsed is not None:
                latest = parsed
    except OSError:
        pass
    age_sec = None
    if latest is not None:
        age_sec = int((datetime.now(timezone.utc) - latest.astimezone(timezone.utc)).total_seconds())
    timer_active = None
    try:
        completed = subprocess.run(
            ["systemctl", "is-active", timer_name],
            text=True,
            capture_output=True,
            timeout=3,
        )
        timer_active = completed.stdout.strip() == "active"
    except Exception:
        timer_active = None
    status = "ok"
    warnings: list[str] = []
    if timer_active is not True:
        status = "warn"
        warnings.append("assessment_timer_inactive_or_unknown")
    if age_sec is None:
        status = "warn"
        warnings.append("assessment_log_missing")
    elif age_sec > 7200:
        status = "warn"
        warnings.append("assessment_log_stale")
    return {
        "status": status,
        "timer": timer_name,
        "timer_active": timer_active,
        "latest_log_at": latest.isoformat() if latest else "",
        "latest_log_age_sec": age_sec,
        "warnings": warnings,
    }


def syslog_canary_summary(*, state_path: str = "docs/SYSLOG_CANARY_STATE.json") -> dict[str, Any]:
    path = Path(state_path)
    if not path.is_absolute():
        path = ROOT / path
    try:
        data = json.loads(path.read_text())
    except OSError:
        return {"status": "missing", "warnings": ["syslog_canary_state_missing"]}
    except json.JSONDecodeError:
        return {"status": "warn", "warnings": ["syslog_canary_state_invalid"]}
    raw_status = str(data.get("status") or "unknown")
    status = raw_status
    warnings: list[str] = []
    sent_at = data.get("sent_at") or ""
    age_sec = None
    try:
        if sent_at:
            dt = datetime.fromisoformat(str(sent_at).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age_sec = int((datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).total_seconds())
    except ValueError:
        warnings.append("syslog_canary_timestamp_invalid")
    if age_sec is not None and age_sec > 7200:
        warnings.append("syslog_canary_stale")
    consecutive_failures = int(data.get("consecutive_failures") or 0)
    if raw_status == "fail":
        if consecutive_failures >= 2:
            warnings.append("syslog_canary_failed")
        else:
            status = "warn"
            warnings.append("syslog_canary_transient_failure")
    elif status not in {"ok", "missing"}:
        warnings.append(f"syslog_canary_status:{status}")
    out = dict(data)
    out["raw_status"] = raw_status
    out["status"] = status
    out["age_sec"] = age_sec
    out["warnings"] = warnings
    return out


def gate_watch_summary(*, state_path: str = "docs/GATE_WATCH_STATE.json") -> dict[str, Any]:
    path = Path(state_path)
    if not path.is_absolute():
        path = ROOT / path
    try:
        data = json.loads(path.read_text())
    except OSError:
        return {"status": "missing", "warnings": ["gate_watch_state_missing"]}
    except json.JSONDecodeError:
        return {"status": "warn", "warnings": ["gate_watch_state_invalid"]}
    status = str(data.get("status") or "unknown")
    warnings: list[str] = []
    if status == "new_blockers":
        warnings.append("gate_watch_new_blockers")
    elif status not in {"stable", "changed", "initialized"}:
        warnings.append(f"gate_watch_status:{status}")
    out = dict(data)
    out["status"] = status
    out["warnings"] = warnings
    return out


def noise_housekeep_summary(*, state_path: str = "docs/NOISE_HOUSEKEEP_STATE.json") -> dict[str, Any]:
    path = Path(state_path)
    if not path.is_absolute():
        path = ROOT / path
    try:
        data = json.loads(path.read_text())
    except OSError:
        return {"status": "missing", "warnings": ["noise_housekeep_state_missing"]}
    except json.JSONDecodeError:
        return {"status": "warn", "warnings": ["noise_housekeep_state_invalid"]}
    status = str(data.get("status") or "unknown")
    warnings: list[str] = []
    run_at = data.get("run_at") or ""
    age_sec = None
    try:
        if run_at:
            dt = datetime.fromisoformat(str(run_at).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age_sec = int((datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).total_seconds())
    except ValueError:
        warnings.append("noise_housekeep_timestamp_invalid")
    if age_sec is not None and age_sec > 7200:
        warnings.append("noise_housekeep_stale")
    elif age_sec is None:
        warnings.append("noise_housekeep_timestamp_missing")
    if status not in {"ok", "missing"}:
        warnings.append(f"noise_housekeep_status:{status}")
    out = dict(data)
    out["status"] = "warn" if warnings and status == "ok" else status
    out["age_sec"] = age_sec
    out["warnings"] = warnings
    return out


def central_health_summary(*, root: Path = ROOT, config: str = "config.yaml") -> dict[str, Any]:
    checks = [
        _check_shallotd_service_active(root),
        _check_central_api_health(root, config=config),
    ]
    blockers = [
        f"{check.name}:{check.detail}"
        for check in checks
        if check.status == "fail"
    ]
    warnings = [
        f"{check.name}:{check.detail}"
        for check in checks
        if check.status not in {"ok", "fail"}
    ]
    return {
        "status": "ok" if not blockers and not warnings else ("fail" if blockers else "warn"),
        "checks": [check.__dict__ for check in checks],
        "blockers": blockers,
        "warnings": warnings,
        "strengths": ["service_active", "api_health_ok"] if not blockers and not warnings else [],
    }


def _canary_summary(fleet: dict[str, Any]) -> dict[str, Any]:
    canaries = (
        fleet.get("summary", {})
        .get("monitor_coverage", {})
        .get("canary_monitors", {})
    )
    egress = canaries.get("network_egress") or {}
    agents = egress.get("agents") or {}
    waiting = [
        {
            "agent": str(agent),
            "events_remaining": int(state.get("events_remaining") or 0),
            "estimated_seconds_remaining": state.get("estimated_seconds_remaining"),
            "estimated_minutes_remaining": state.get("estimated_minutes_remaining"),
            "reason": state.get("promotion_reason", ""),
        }
        for agent, state in agents.items()
        if state.get("stable") and not state.get("promotion_eligible")
    ]
    unstable = [
        str(agent)
        for agent, state in agents.items()
        if state.get("present") and not state.get("stable")
    ]
    missing = [
        str(agent)
        for agent, state in agents.items()
        if not state.get("present")
    ]
    return {
        "name": "network_egress",
        "expected": egress.get("expected_agents", []),
        "present": egress.get("present_agents", []),
        "eligible": egress.get("promotion_eligible_agents", []),
        "waiting": sorted(waiting, key=lambda item: (item["events_remaining"], item["agent"])),
        "unstable": sorted(unstable),
        "missing": sorted(missing),
        "next": egress.get("next_promotion_target", "unknown"),
    }


def _agent_rollout_summary(
    fleet: dict[str, Any],
    rollout_access: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    summary = fleet.get("summary", {})
    canary = _canary_summary(fleet)
    expected_agents = [str(agent) for agent in summary.get("expected_agents", [])]
    canary_expected = {str(agent) for agent in canary.get("expected", [])}
    canary_eligible = {str(agent) for agent in canary.get("eligible", [])}
    canary_ready = bool(canary_expected) and canary_expected <= canary_eligible and not canary.get("waiting") and not canary.get("unstable") and not canary.get("missing")
    remaining = [agent for agent in expected_agents if agent not in canary_expected]
    by_agent = {str(agent.get("agent")): agent for agent in fleet.get("agents", [])}
    blockers: list[str] = []
    warnings: list[str] = []
    next_actions: list[str] = []
    rollout_access = rollout_access or {}
    for agent in remaining:
        agent_warnings = [str(item) for item in by_agent.get(agent, {}).get("warnings", [])]
        resource_warnings = [
            item for item in agent_warnings
            if item.startswith("disk>=") or item.startswith("mem>=") or item.startswith("load/")
        ]
        access = rollout_access.get(agent) or {}
        if resource_warnings:
            for item in resource_warnings:
                blockers.append(f"{agent}:{item}")
            detail = _agent_resource_detail(by_agent.get(agent, {"agent": agent}))
            next_actions.append(
                f"Clear resource warnings before promoting network_egress on {detail}: {', '.join(resource_warnings)}"
            )
        elif access and access.get("status") != "ok":
            status = str(access.get("status") or "unknown")
            blockers.append(f"target_access:{agent}:{status}")
            repair = "; ".join(str(cmd) for cmd in access.get("repair_commands") or [])
            detail = str(access.get("detail") or status)
            action = f"Restore SSH access before promoting network_egress on {agent}: {detail}"
            if repair:
                action += f"; repair={repair}"
            next_actions.append(action)
        elif agent_warnings:
            for item in agent_warnings:
                warnings.append(f"{agent}:{item}")
    if remaining and not next_actions:
        next_actions.append("Run tools/argus_network_egress_rollout.py for remaining agents before full-agent production.")
    if canary_ready and blockers:
        agent_side_next = "Canary cohort is promotion-ready; clear remaining agent blockers before expanding network_egress."
    elif canary_ready and remaining:
        agent_side_next = "Canary cohort is promotion-ready; plan the remaining agent rollout."
    elif not canary_ready:
        agent_side_next = "Wait for canary cohort to become promotion-ready before expanding network_egress."
    else:
        agent_side_next = "Network egress rollout is fully covered."
    status = "ok"
    if blockers:
        status = "blocked"
    elif remaining or warnings:
        status = "watch"
    return {
        "monitor": "network_egress",
        "status": status,
        "expected_agents": expected_agents,
        "covered_agents": sorted(canary_expected),
        "canary_ready": canary_ready,
        "remaining_agents": remaining,
        "blockers": blockers,
        "warnings": warnings,
        "target_access": rollout_access,
        "agent_side_next": agent_side_next,
        "next_actions": next_actions[:6],
    }


def _rollout_access_checks(fleet: dict[str, Any]) -> dict[str, dict[str, Any]]:
    preview = _agent_rollout_summary(fleet)
    if not preview.get("canary_ready"):
        return {}
    checks: dict[str, dict[str, Any]] = {}
    try:
        from tools.argus_network_egress_rollout import check_target_access
    except Exception:
        return checks
    for agent in preview.get("remaining_agents") or []:
        checks[str(agent)] = check_target_access(str(agent))
    return checks


def _agent_resource_detail(agent: dict[str, Any]) -> str:
    parts = [str(agent.get("agent") or "unknown")]
    disk = agent.get("disk_used_pct")
    if disk not in ("", None):
        detail = f"disk={disk}%"
        free = agent.get("disk_free_gb")
        if free not in ("", None):
            detail += f" free={free}GB"
        parts.append(detail)
    mem = agent.get("mem_used_pct")
    if mem not in ("", None):
        parts.append(f"mem={mem}%")
    load = agent.get("load_per_core")
    if load not in ("", None):
        parts.append(f"load/core={load}")
    return " ".join(parts)


def _fleet_agent_rows(agents: list[dict[str, Any]], *, limit: int = 8) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for agent in agents[:limit]:
        gpus = agent.get("gpus") if isinstance(agent.get("gpus"), list) else []
        rows.append(
            {
                "agent": agent.get("agent"),
                "state": agent.get("state", ""),
                "age_sec": agent.get("age_sec"),
                "ip": agent.get("ip", ""),
                "webhook_ok": agent.get("webhook_ok"),
                "cpu_count": agent.get("cpu_count", ""),
                "cpu_util_pct": agent.get("cpu_util_pct", ""),
                "cpu_temp_c": agent.get("cpu_temp_c", ""),
                "cpu_temp_label": agent.get("cpu_temp_label", ""),
                "load1": agent.get("load1", ""),
                "load5": agent.get("load5", ""),
                "load15": agent.get("load15", ""),
                "load_per_core": agent.get("load_per_core", ""),
                "uptime_seconds": agent.get("uptime_seconds", ""),
                "mem_used_pct": agent.get("mem_used_pct", ""),
                "mem_total_mb": agent.get("mem_total_mb", ""),
                "mem_available_mb": agent.get("mem_available_mb", ""),
                "disk_used_pct": agent.get("disk_used_pct", ""),
                "disk_free_gb": agent.get("disk_free_gb", ""),
                "gpu_count": agent.get("gpu_count", len(gpus)),
                "gpus": gpus[:4],
                "events_emitted": agent.get("events_emitted", ""),
                "non_heartbeat_events": agent.get("non_heartbeat_events", ""),
                "monitors": agent.get("monitors", ""),
                "warnings": agent.get("warnings", []),
            }
        )
    return rows


def _tcp_open(host: str, port: int, *, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _route_to(host: str) -> str:
    try:
        completed = subprocess.run(
            ["ip", "route", "get", host],
            text=True,
            capture_output=True,
            timeout=1,
        )
    except Exception:
        return ""
    if completed.returncode != 0:
        return ""
    return " ".join(completed.stdout.strip().split())


def expected_source_diagnostics(
    expected_sources: list[dict[str, Any]],
    *,
    probe: bool = False,
) -> list[dict[str, Any]]:
    diagnostics: list[dict[str, Any]] = []
    for src in expected_sources:
        src_ips = [str(item) for item in src.get("src_ips", []) if item]
        item = {
            "name": src.get("name", ""),
            "type": src.get("type", ""),
            "status": src.get("status", "unknown"),
            "src_ips": src_ips,
            "hostnames": src.get("hostnames", []),
            "count_window": src.get("count_window", 0),
            "total_seen": src.get("total_seen", 0),
            "latest": src.get("latest", ""),
            "warnings": src.get("warnings", []),
            "note": src.get("note", ""),
            "reachability": [],
            "fingerprints": {},
        }
        if probe:
            item["reachability"] = [
                {
                    "ip": ip,
                    "tcp80": _tcp_open(ip, 80),
                    "tcp443": _tcp_open(ip, 443),
                    "route": _route_to(ip),
                }
                for ip in src_ips
            ]
            item["fingerprints"] = {ip: _router_fingerprint(ip, probe=True) for ip in src_ips}
        item.update(_expected_source_diagnosis(item))
        diagnostics.append(item)
    return diagnostics


def _expected_source_diagnosis(src: dict[str, Any]) -> dict[str, str]:
    status = str(src.get("status") or "unknown")
    reach = src.get("reachability") or []
    ui_reachable = any(bool(probe.get("tcp80") or probe.get("tcp443")) for probe in reach)
    routed = any(bool(probe.get("route")) for probe in reach)
    if status == "ok":
        return {
            "diagnosis": "source_forwarding",
            "next_step": "Continue monitoring expected source volume and freshness.",
        }
    if status == "stale":
        return {
            "diagnosis": "source_stale",
            "next_step": "Trigger a harmless router event and verify fresh syslog arrives.",
        }
    if status == "missing" and ui_reachable:
        return {
            "diagnosis": "management_ui_reachable_syslog_not_forwarding",
            "next_step": "Log into the reachable router UI and enable remote syslog to 192.168.0.172:514.",
        }
    if status == "missing" and routed:
        return {
            "diagnosis": "host_routed_but_management_ui_unconfirmed",
            "next_step": "Verify router UI access or configure logging from another management path.",
        }
    if status == "missing":
        return {
            "diagnosis": "source_unreachable_or_unprobed",
            "next_step": "Confirm the expected source IP/route before configuring syslog forwarding.",
        }
    return {
        "diagnosis": f"source_{status}",
        "next_step": "Review the expected-source manifest and observed log source details.",
    }


def _volume_by_host_snapshot(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in rows:
        raw = int(item.get("raw") or 0)
        synthetic = int(item.get("synthetic_or_experiment") or 0)
        raw_per_day = float(item.get("raw_per_day") or 0)
        synthetic_per_day = raw_per_day * synthetic / raw if raw else 0.0
        compact = dict(item)
        compact["real_raw"] = max(0, raw - synthetic)
        compact["real_raw_per_day"] = round(max(0.0, raw_per_day - synthetic_per_day), 2)
        out.append(compact)
    return sorted(out, key=lambda row: float(row.get("raw_per_day") or 0), reverse=True)


def _network_for_snapshot(alert_hour: dict[str, Any], alert_day: dict[str, Any]) -> dict[str, Any]:
    network = dict(alert_hour.get("network_coverage") or alert_day.get("network_coverage") or {})
    day_network = alert_day.get("network_coverage") or {}
    day_active = bool(day_network.get("active_sources_window"))
    if day_active:
        transient_idle = {"syslog_idle_in_window", "no_network_source_events_in_window"}
        advisories = [
            item for item in network.get("advisory_gaps", [])
            if str(item) not in transient_idle
        ]
        gaps = [
            item for item in network.get("gaps", [])
            if str(item) not in transient_idle
        ]
        network["advisory_gaps"] = advisories
        network["gaps"] = gaps
        if day_network.get("active_sources_window"):
            network["active_sources_window_24h"] = day_network.get("active_sources_window")
    return network


def build_snapshot(
    fleet: dict[str, Any],
    alert_hour: dict[str, Any],
    alert_day: dict[str, Any],
    assessment_loop: dict[str, Any] | None = None,
    external_sources: list[dict[str, Any]] | None = None,
    rule_canary: dict[str, Any] | None = None,
    syslog_canary: dict[str, Any] | None = None,
    agent_services: dict[str, Any] | None = None,
    gate_watch: dict[str, Any] | None = None,
    central_health: dict[str, Any] | None = None,
    noise_housekeep: dict[str, Any] | None = None,
    rollout_access: dict[str, dict[str, Any]] | None = None,
    public_listeners: dict[str, Any] | None = None,
) -> dict[str, Any]:
    fleet_summary = fleet.get("summary", {})
    hour_readiness = alert_hour.get("readiness", {})
    day_guardrails = alert_day.get("volume_guardrails", {})
    assessment_loop = assessment_loop or {}
    rule_canary = rule_canary or {}
    syslog_canary = syslog_canary or {}
    agent_services = agent_services or {}
    gate_watch = gate_watch or {}
    central_health = central_health or {}
    noise_housekeep = noise_housekeep or {}
    public_listeners = public_listeners or {}
    network = _network_for_snapshot(alert_hour, alert_day)
    agents = fleet.get("agents", [])
    warning_agents = [
        {
            "agent": agent.get("agent"),
            "warnings": agent.get("warnings", []),
            "disk_used_pct": agent.get("disk_used_pct", ""),
            "disk_free_gb": agent.get("disk_free_gb", ""),
            "cpu_util_pct": agent.get("cpu_util_pct", ""),
            "cpu_temp_c": agent.get("cpu_temp_c", ""),
            "load_per_core": agent.get("load_per_core", ""),
            "mem_used_pct": agent.get("mem_used_pct", ""),
        }
        for agent in agents
        if agent.get("warnings")
    ]
    expected_agents = fleet_summary.get("expected_agents", [])
    online = int(fleet_summary.get("online_count", 0) or 0)
    expected_count = len(expected_agents)
    incident_candidates = alert_hour.get("incident_candidates", [])
    volume_by_host = _volume_by_host_snapshot(alert_day.get("volume_by_host") or [])
    external_sources = (
        external_sources
        if external_sources is not None
        else expected_source_diagnostics(alert_hour.get("expected_log_sources") or [])
    )
    pipeline_blockers: list[str] = []
    pipeline_warnings: list[str] = []
    if expected_count and online < expected_count:
        pipeline_blockers.append("agents_not_all_online")
    if fleet_summary.get("blockers"):
        pipeline_blockers.extend(str(item) for item in fleet_summary.get("blockers", []))
    if incident_candidates:
        pipeline_blockers.append("incident_candidates_present")
    if alert_hour.get("visible_non_synthetic", 0):
        pipeline_warnings.append("visible_alerts_present")
    if day_guardrails.get("warnings"):
        pipeline_warnings.extend(str(item) for item in day_guardrails.get("warnings", []))
    day_suppression = alert_day.get("suppression_quality") or {}
    if day_suppression.get("warnings"):
        pipeline_warnings.extend(f"suppression:{item}" for item in day_suppression.get("warnings", []))
    if assessment_loop.get("status") not in ("ok", None):
        pipeline_warnings.append("assessment_loop_not_ok")
    if rule_canary.get("status") == "fail":
        pipeline_blockers.append("rule_canary_failed")
    elif rule_canary and rule_canary.get("status") != "ok":
        pipeline_warnings.append("rule_canary_unknown")
    if syslog_canary.get("status") == "fail":
        pipeline_blockers.append("syslog_canary_failed")
    elif syslog_canary.get("warnings"):
        pipeline_warnings.extend(str(item) for item in syslog_canary.get("warnings", []))
    if agent_services.get("warnings"):
        pipeline_warnings.extend(f"agent_service:{item}" for item in agent_services.get("warnings", []))
    if public_listeners.get("warnings"):
        pipeline_warnings.extend(str(item) for item in public_listeners.get("warnings", []))
    if noise_housekeep.get("status") not in ("ok", None):
        pipeline_warnings.extend(str(item) for item in noise_housekeep.get("warnings", []))
    pipeline_status = "ok" if not pipeline_blockers and not pipeline_warnings else ("blocked" if pipeline_blockers else "watch")
    pipeline_strengths = [
        item
        for item in (
            "agents_online" if expected_count and online == expected_count else "",
            "no_visible_alerts" if not alert_hour.get("visible_non_synthetic", 0) else "",
            "no_incident_candidates" if not incident_candidates else "",
            "volume_guardrails_clean" if not day_guardrails.get("warnings") else "",
            "assessment_loop_ok" if assessment_loop.get("status") == "ok" else "",
            "rule_canary_ok" if rule_canary.get("status") == "ok" else "",
            "syslog_canary_ok" if syslog_canary.get("status") == "ok" else "",
            "central_health_ok" if central_health.get("status") == "ok" else "",
            "noise_housekeep_ok" if noise_housekeep.get("status") == "ok" else "",
        )
        if item
    ]
    snapshot = {
        "status": "ready" if fleet_summary.get("status") == "ok" and hour_readiness.get("status") == "ready" else "watch",
        "pipeline": {
            "status": pipeline_status,
            "blockers": pipeline_blockers,
            "warnings": pipeline_warnings,
            "strengths": pipeline_strengths,
        },
        "fleet": {
            "status": fleet_summary.get("status", "unknown"),
            "online": fleet_summary.get("online_count", 0),
            "expected": len(fleet_summary.get("expected_agents", [])),
            "warnings": fleet_summary.get("warnings", []),
            "blockers": fleet_summary.get("blockers", []),
            "strengths": fleet_summary.get("strengths", []),
            "next_actions": fleet_summary.get("next_actions", []),
            "warning_agents": warning_agents,
            "agents": _fleet_agent_rows(agents),
        },
        "alerts": {
            "last_hour_visible": alert_hour.get("visible_non_synthetic", 0),
            "last_hour_raw": alert_hour.get("raw_alerts", 0),
            "last_24h_visible": alert_day.get("visible_non_synthetic", 0),
            "last_24h_raw": alert_day.get("raw_alerts", 0),
            "last_24h_synthetic_or_experiment": alert_day.get("synthetic_or_experiment", 0),
            "last_24h_suppressed_non_synthetic": alert_day.get("suppressed_non_synthetic", 0),
            "raw_per_hour_24h": day_guardrails.get("raw_per_hour", 0),
            "real_raw_per_hour_24h": day_guardrails.get("real_raw_per_hour", 0),
            "synthetic_per_hour_24h": day_guardrails.get("synthetic_per_hour", 0),
            "visible_per_hour_24h": day_guardrails.get("visible_per_hour", 0),
            "storage": {
                "db_bytes": day_guardrails.get("db_bytes", 0),
                "db_freelist_bytes": day_guardrails.get("db_freelist_bytes", 0),
                "db_freelist_pct": day_guardrails.get("db_freelist_pct", 0),
                "assessment_log_bytes": day_guardrails.get("assessment_log_bytes", 0),
            },
            "synthetic_residue": alert_day.get("synthetic_residue", {}),
            "volume_by_host_24h": volume_by_host[:8],
            "guardrail_warnings": day_guardrails.get("warnings", []),
            "suppression_quality": day_suppression,
            "suppression_review_examples": (day_suppression.get("examples") or [])[:4],
            "suppression_warnings": day_suppression.get("warnings", []),
            "rate_baseline": alert_hour.get("alert_rate_baseline", {}),
            "incident_candidates": incident_candidates,
        },
        "network": {
            "status": network.get("status", "unknown"),
            "gaps": network.get("gaps", []),
            "blocking_gaps": network.get("blocking_gaps", []),
            "advisory_gaps": network.get("advisory_gaps", []),
            "active_sources_window_24h": network.get("active_sources_window_24h", []),
            "actions": network.get("actions", [])[:4],
        },
        "external_sources": external_sources,
        "canaries": {
            "network_egress": _canary_summary(fleet),
        },
        "agent_rollout": _agent_rollout_summary(fleet, rollout_access),
        "assessment_loop": assessment_loop or {},
        "rule_canary": rule_canary,
        "syslog_canary": syslog_canary,
        "agent_services": agent_services,
        "public_listeners": public_listeners,
        "gate_watch": gate_watch,
        "central_health": central_health,
        "noise_housekeep": noise_housekeep,
        "readiness": {
            "status": hour_readiness.get("status", "unknown"),
            "blockers": hour_readiness.get("blockers", []),
            "warnings": hour_readiness.get("warnings", []),
            "strengths": hour_readiness.get("strengths", []),
            "next_actions": (hour_readiness.get("next_actions") or fleet_summary.get("next_actions") or [])[:6],
        },
    }
    snapshot["production_gate"] = evaluate_gate(snapshot)
    from tools.shallot_self_assess import assess_snapshot

    snapshot["self_assessment"] = assess_snapshot(snapshot)
    return snapshot


def load_snapshot(*, config: str, hours: float, expected_log_sources: str) -> dict[str, Any]:
    py = _project_python()
    fleet = _run_json([py, str(ROOT / "tools" / "shallot_fleet_top.py"), "-c", config, "--summary-json"])
    alert_hour = _run_json(
        [
            py,
            str(ROOT / "tools" / "shallot_alert_assess.py"),
            "-c",
            config,
            "--hours",
            str(hours),
            "--expected-log-sources",
            expected_log_sources,
            "--json",
        ]
    )
    alert_day = _run_json(
        [
            py,
            str(ROOT / "tools" / "shallot_alert_assess.py"),
            "-c",
            config,
            "--hours",
            "24",
            "--expected-log-sources",
            expected_log_sources,
            "--json",
        ]
    )
    rule_canary = _run_json([py, str(ROOT / "tools" / "shallot_rule_canary.py"), "--json"])
    return build_snapshot(
        fleet,
        alert_hour,
        alert_day,
        assessment_loop_summary(),
        expected_source_diagnostics(alert_hour.get("expected_log_sources") or [], probe=True),
        rule_canary,
        syslog_canary_summary(),
        _run_json([py, str(ROOT / "tools" / "shallot_agent_service_check.py"), "--json"]),
        gate_watch_summary(),
        central_health_summary(config=config),
        noise_housekeep_summary(),
        _rollout_access_checks(fleet),
        _run_json([py, str(ROOT / "tools" / "shallot_public_listener_audit.py"), "--json"]),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-c", "--config", default="config.yaml")
    parser.add_argument("--hours", type=float, default=1.0)
    parser.add_argument("--expected-log-sources", default="docs/NETWORK_LOG_SOURCES.yaml")
    args = parser.parse_args()
    print(json.dumps(load_snapshot(config=args.config, hours=args.hours, expected_log_sources=args.expected_log_sources), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
