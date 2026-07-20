#!/usr/bin/env python3
"""Assess Security Shallots production posture from the current snapshot."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _metric_status(ok: bool, warn: bool = False) -> str:
    if not ok:
        return "blocked"
    if warn:
        return "watch"
    return "ok"


def _readiness_score(sections: list[dict[str, Any]]) -> int:
    if not sections:
        return 0
    weights = {"ok": 1.0, "watch": 0.55, "blocked": 0.0, "unknown": 0.25}
    score = sum(weights.get(str(item.get("status")), 0.25) for item in sections) / len(sections)
    return int(round(score * 100))


def _duration(seconds: Any) -> str:
    try:
        value = int(float(seconds))
    except (TypeError, ValueError):
        return "unknown"
    if value < 0:
        return "unknown"
    if value < 3600:
        return f"{max(1, value // 60)}m"
    if value < 172800:
        return f"{value / 3600:.1f}h"
    return f"{value / 86400:.1f}d"


def _longest_age(items: dict[str, Any]) -> tuple[str, int] | None:
    ages: list[tuple[str, int]] = []
    for name, age in items.items():
        try:
            ages.append((str(name), int(float(age))))
        except (TypeError, ValueError):
            continue
    if not ages:
        return None
    return max(ages, key=lambda item: item[1])


def _age_tier(seconds: int | None, *, kind: str) -> str:
    if seconds is None:
        return "unknown"
    if kind == "blocker":
        if seconds >= 86400:
            return "overdue"
        if seconds >= 14400:
            return "stale"
        if seconds >= 3600:
            return "aging"
        return "new"
    if seconds >= 86400:
        return "stale"
    if seconds >= 14400:
        return "aging"
    return "watch"


def _commands_for_gate_item(name: str, commands: list[str]) -> list[str]:
    if name.startswith("network:expected_syslog_missing:") or name == "readiness:network_coverage_gap":
        wanted = (
            "shallot_router_syslog_plan.py",
            "shallot_syslog_canary.py",
            "shallot_alert_assess.py --hours 1",
        )
    elif name.startswith("rollout:target_access:host03:"):
        wanted = (
            "argus_network_egress_rollout.py --target host03",
        )
    elif name.startswith("rollout:host03:") or name.startswith("agent:host03:"):
        wanted = (
            "shallot_fleet_top.py",
            "shallot_resource_cleanup_plan.py --agent host03",
            "argus_network_egress_rollout.py --target host03",
        )
    elif name == "alerts:synthetic_residue_review" or name.startswith("alerts:synthetic_residue"):
        wanted = (
            "shallot_noise_housekeep.py",
            "shallot_alert_assess.py --hours 24",
        )
    elif name.startswith("assessment_loop:"):
        wanted = ("shallot-alert-assess", "ALERT_ASSESSMENT_LOG.md")
    elif name.startswith("central:"):
        wanted = ("shallotd.service", "/api/health")
    else:
        wanted = ()
    if not wanted:
        return []
    return [command for command in commands if any(token in command for token in wanted)]


def _action_for_gate_item(name: str, action_items: list[Any]) -> dict[str, str]:
    source = name.removeprefix("network:expected_syslog_missing:") if name.startswith("network:expected_syslog_missing:") else ""
    agent = ""
    if name.startswith("rollout:") or name.startswith("agent:"):
        parts = name.split(":")
        if name.startswith("rollout:target_access:"):
            agent = parts[2] if len(parts) > 2 else ""
        else:
            agent = parts[1] if len(parts) > 1 else ""

    for item in action_items:
        if not isinstance(item, dict):
            continue
        action = str(item.get("action") or "")
        domain = str(item.get("domain") or "")
        if source and source in action:
            return {
                "domain": domain or "network_source",
                "owner": str(item.get("owner") or "operator"),
                "urgency": str(item.get("urgency") or "normal"),
                "action": action,
            }
        if agent and agent in action:
            return {
                "domain": domain or "agent_resource",
                "owner": str(item.get("owner") or "operator"),
                "urgency": str(item.get("urgency") or "normal"),
                "action": action,
            }
        if name.startswith("alerts:synthetic_residue") and domain == "alert_noise":
            return {
                "domain": domain,
                "owner": str(item.get("owner") or "operator"),
                "urgency": str(item.get("urgency") or "normal"),
                "action": action,
            }

    if source:
        return {
            "domain": "network_source",
            "owner": "manual_router_admin",
            "urgency": "high",
            "action": f"Configure or retire expected syslog source {source}.",
        }
    if agent:
        if name.startswith("rollout:target_access:"):
            return {
                "domain": "agent_rollout",
                "owner": "operator",
                "urgency": "high",
                "action": f"Restore SSH access before promoting network_egress on {agent}.",
            }
        return {
            "domain": "agent_resource",
            "owner": "manual_host_cleanup",
            "urgency": "high",
            "action": f"Clear resource warning on {agent}.",
        }
    if name == "alerts:synthetic_residue_review" or name.startswith("alerts:synthetic_residue"):
        return {
            "domain": "alert_noise",
            "owner": "timer_or_manual_review",
            "urgency": "normal",
            "action": "Review synthetic residue and let housekeeping prune after rows are 24h old.",
        }
    return {"domain": "general", "owner": "operator", "urgency": "normal", "action": "Review this gate item."}


def _gate_item_review(
    gate_watch: dict[str, Any],
    *,
    active_blockers: set[str],
    active_warnings: set[str],
    action_items: list[Any],
    remediation_commands: list[str],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for kind, field, active in (
        ("blocker", "blocker_age_sec", active_blockers),
        ("warning", "warning_age_sec", active_warnings),
    ):
        ages = gate_watch.get(field) or {}
        if not isinstance(ages, dict):
            continue
        for name, raw_age in ages.items():
            if str(name) not in active:
                continue
            age_sec: int | None
            try:
                age_sec = int(float(raw_age))
            except (TypeError, ValueError):
                age_sec = None
            tier = _age_tier(age_sec, kind=kind)
            action = _action_for_gate_item(str(name), action_items)
            rows.append(
                {
                    "kind": kind,
                    "name": str(name),
                    "age_sec": age_sec,
                    "age": _duration(age_sec),
                    "tier": tier,
                    "needs_operator": kind == "blocker" or tier in {"aging", "stale", "overdue"},
                    "domain": action["domain"],
                    "owner": action["owner"],
                    "urgency": action["urgency"],
                    "action": action["action"],
                    "commands": _commands_for_gate_item(str(name), remediation_commands),
                }
            )
    tier_order = {"overdue": 0, "stale": 1, "aging": 2, "new": 3, "watch": 4, "unknown": 5}
    return sorted(rows, key=lambda row: (tier_order.get(str(row.get("tier")), 9), -(row.get("age_sec") or 0), str(row.get("name"))))


def _rule_coverage_detail(rule_canary: dict[str, Any]) -> str:
    coverage = rule_canary.get("coverage") or {}
    guardrails = rule_canary.get("coverage_guardrails") or {}
    total = coverage.get("total_cases")
    sources = coverage.get("sources") or {}
    source_parts: list[str] = []
    if isinstance(sources, dict):
        for name in sorted(sources):
            item = sources.get(name) or {}
            source_parts.append(f"{name}={item.get('cases', 0)}")
    quiet_cases = coverage.get("quiet_cases")
    positive_cases = coverage.get("positive_cases")
    rules = coverage.get("covered_rule_ids") or []
    detail_parts = []
    if total is not None:
        detail_parts.append(f"{total} cases")
    if source_parts:
        detail_parts.append("sources " + ", ".join(source_parts))
    if positive_cases is not None and quiet_cases is not None:
        detail_parts.append(f"positive={positive_cases}, quiet={quiet_cases}")
    if rules:
        detail_parts.append(f"rules={len(rules)}")
    quiet_guard = _quiet_canary_guard(coverage, guardrails)
    if quiet_guard["known"]:
        detail_parts.append(
            f"quiet_guard={quiet_guard['status']} quiet_headroom={quiet_guard['headroom_cases']}"
        )
    source_guard = _source_canary_guard(coverage, guardrails)
    if source_guard["known"]:
        detail_parts.append(
            f"source_guard={source_guard['status']} source_headroom={source_guard['headroom_summary']}"
        )
    return "; ".join(detail_parts) if detail_parts else "coverage=unknown"


def _quiet_canary_guard(coverage: dict[str, Any], guardrails: dict[str, Any] | None = None) -> dict[str, Any]:
    """Keep rule growth paired with explicit noise/quiet examples."""
    try:
        total = int(coverage.get("total_cases"))
        positive = int(coverage.get("positive_cases"))
        quiet = int(coverage.get("quiet_cases"))
    except (TypeError, ValueError):
        return {
            "known": False,
            "ok": False,
            "status": "unknown",
            "detail": "Rule canary quiet-case coverage is unavailable.",
        }
    quiet_guardrail = (guardrails or {}).get("quiet") if isinstance(guardrails, dict) else None
    if isinstance(quiet_guardrail, dict):
        try:
            minimum_quiet = int(quiet_guardrail.get("minimum_cases"))
            headroom = int(quiet_guardrail.get("headroom_cases"))
        except (TypeError, ValueError):
            minimum_quiet = max(3, (total + 5) // 6)  # roughly 1 quiet case per 6 total cases.
            headroom = quiet - minimum_quiet
    else:
        minimum_quiet = max(3, (total + 5) // 6)
        headroom = quiet - minimum_quiet
    ok = positive > 0 and headroom >= 0
    return {
        "known": True,
        "ok": ok,
        "status": "ok" if ok else "thin",
        "quiet_cases": quiet,
        "minimum_quiet_cases": minimum_quiet,
        "headroom_cases": headroom,
        "detail": (
            f"Rule canary has {quiet} quiet cases; keep at least {minimum_quiet} "
            f"quiet/noise examples so added rules do not overfit to alert-positive fixtures; "
            f"headroom is {headroom} cases."
        ),
    }


def _source_canary_guard(coverage: dict[str, Any], guardrails: dict[str, Any] | None = None) -> dict[str, Any]:
    """Ensure each detection source family keeps meaningful canary coverage."""
    sources = coverage.get("sources")
    if not isinstance(sources, dict):
        return {
            "known": False,
            "ok": False,
            "status": "unknown",
            "detail": "Rule canary source-family coverage is unavailable.",
        }
    guardrail_sources = (guardrails or {}).get("sources") if isinstance(guardrails, dict) else None
    guardrail_minimums = guardrail_sources.get("minimum_cases") if isinstance(guardrail_sources, dict) else None
    guardrail_headroom = guardrail_sources.get("headroom_cases") if isinstance(guardrail_sources, dict) else None
    minimums = {"argus": 3, "suricata": 2, "syslog": 5}
    if isinstance(guardrail_minimums, dict):
        for source, value in guardrail_minimums.items():
            try:
                minimums[str(source)] = int(value)
            except (TypeError, ValueError):
                continue
    thin: list[str] = []
    headroom: dict[str, int] = {}
    for source, minimum in minimums.items():
        item = sources.get(source)
        cases = item.get("cases") if isinstance(item, dict) else 0
        try:
            count = int(cases)
        except (TypeError, ValueError):
            count = 0
        if isinstance(guardrail_headroom, dict) and source in guardrail_headroom:
            try:
                headroom[source] = int(guardrail_headroom[source])
            except (TypeError, ValueError):
                headroom[source] = count - minimum
        else:
            headroom[source] = count - minimum
        if count < minimum:
            thin.append(f"{source}={count}/{minimum}")
        elif headroom[source] < 0:
            thin.append(f"{source}={count}/{minimum}")
    ok = not thin
    headroom_summary = ",".join(f"{source}={headroom[source]}" for source in sorted(headroom))
    return {
        "known": True,
        "ok": ok,
        "status": "ok" if ok else "thin",
        "thin_sources": thin,
        "headroom": headroom,
        "headroom_summary": headroom_summary,
        "detail": (
            "Rule canary source-family coverage is thin: "
            + ", ".join(thin)
            + ". Keep argus, suricata, and syslog represented so source-specific regressions are visible."
            if thin
            else "Rule canary source-family coverage includes argus, suricata, and syslog."
        ),
    }


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _network_source_diagnoses(external_sources: list[Any]) -> list[str]:
    rows: list[str] = []
    for item in external_sources:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "unknown")
        if status not in {"missing", "stale"}:
            continue
        name = str(item.get("name") or "unknown")
        diagnosis = str(item.get("diagnosis") or "diagnosis_unknown")
        rows.append(f"{name}:{diagnosis}")
    return rows


def _agent_service_status(agent_services: dict[str, Any]) -> dict[str, Any]:
    status = str(agent_services.get("status") or "unknown")
    warnings = [str(item) for item in _as_list(agent_services.get("warnings"))]
    unchecked = [str(item) for item in _as_list(agent_services.get("unchecked_agents"))]
    corroborated = [str(item) for item in _as_list(agent_services.get("heartbeat_corroborated_agents"))]
    uncorroborated = [str(item) for item in _as_list(agent_services.get("unchecked_without_fresh_heartbeat"))]
    detail_parts = [f"status={status}"]
    if unchecked:
        detail_parts.append("unchecked=" + ",".join(unchecked))
    if corroborated:
        detail_parts.append("heartbeat_corroborated=" + ",".join(corroborated))
    if uncorroborated:
        detail_parts.append("uncorroborated=" + ",".join(uncorroborated))
    if warnings:
        detail_parts.append("warnings=" + ",".join(warnings))
    if status in {"ok", "missing"}:
        section_status = "ok"
    elif status == "ok_corroborated":
        section_status = "watch"
    elif status in {"warn", "partial"}:
        section_status = "watch" if not uncorroborated else "blocked"
    else:
        section_status = "watch"
    return {
        "status": status,
        "section_status": section_status,
        "warnings": warnings,
        "unchecked": unchecked,
        "corroborated": corroborated,
        "uncorroborated": uncorroborated,
        "detail": "; ".join(detail_parts),
    }


def assess_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    gate = snapshot.get("production_gate") or {}
    fleet = snapshot.get("fleet") or {}
    alerts = snapshot.get("alerts") or {}
    network = snapshot.get("network") or {}
    rollout = snapshot.get("agent_rollout") or {}
    agent_services = snapshot.get("agent_services") or {}
    public_listeners = snapshot.get("public_listeners") or {}
    assessment_loop = snapshot.get("assessment_loop") or {}
    gate_watch = snapshot.get("gate_watch") or {}
    noise_housekeep = snapshot.get("noise_housekeep") or {}
    central = snapshot.get("central_health") or {}
    syslog_canary = snapshot.get("syslog_canary") or {}
    rule_canary = snapshot.get("rule_canary") or {}
    rule_coverage = rule_canary.get("coverage") or {}
    rule_guardrails = rule_canary.get("coverage_guardrails") or {}
    rule_quiet_guard = _quiet_canary_guard(rule_coverage, rule_guardrails)
    rule_source_guard = _source_canary_guard(rule_coverage, rule_guardrails)

    blockers = [str(item) for item in _as_list(gate.get("blockers"))]
    warnings = [str(item) for item in _as_list(gate.get("warnings"))]
    action_items = _as_list(gate.get("action_items"))
    remediation_commands = [str(item) for item in _as_list(gate.get("remediation_commands"))]
    external_sources = _as_list(snapshot.get("external_sources"))
    agents = _as_list(fleet.get("agents"))

    missing_sources = [
        str(item.get("name") or "unknown")
        for item in external_sources
        if item.get("status") == "missing"
    ]
    stale_sources = [
        str(item.get("name") or "unknown")
        for item in external_sources
        if item.get("status") == "stale"
    ]
    source_diagnoses = _network_source_diagnoses(external_sources)
    warning_agents = [
        str(item.get("agent") or "unknown")
        for item in agents
        if item.get("warnings")
    ]
    rollout_blockers = [item for item in blockers if item.startswith("rollout:")]
    service_guard = _agent_service_status(agent_services)
    public_listener_warnings = [str(item) for item in _as_list(public_listeners.get("warnings"))]
    public_listener_unexpected = _as_list(public_listeners.get("unexpected"))
    public_listener_status = str(public_listeners.get("status") or "unknown")

    visible_24h = int(alerts.get("last_24h_visible") or 0)
    real_raw_per_hour = _as_float(alerts.get("real_raw_per_hour_24h"))
    synthetic_per_hour = _as_float(alerts.get("synthetic_per_hour_24h"))
    visible_per_hour = _as_float(alerts.get("visible_per_hour_24h"))
    incident_candidates = _as_list(alerts.get("incident_candidates"))
    suppression_quality = alerts.get("suppression_quality") or {}
    suppression_warnings = _as_list(alerts.get("suppression_warnings"))
    baseline = alerts.get("rate_baseline") or {}
    baseline_warnings = _as_list(baseline.get("warnings"))
    synthetic = alerts.get("synthetic_residue") or {}
    synthetic_count = int(synthetic.get("count") or 0)
    synthetic_pct = float(synthetic.get("percent_raw") or 0)
    synthetic_eligible = int(synthetic.get("prune_eligible_24h") or 0)
    synthetic_next_eligible = _as_float(synthetic.get("next_eligible_in_hours"))
    blocker_age_sec = gate_watch.get("blocker_age_sec") or {}
    warning_age_sec = gate_watch.get("warning_age_sec") or {}
    blocker_review = _gate_item_review(
        gate_watch,
        active_blockers=set(blockers),
        active_warnings=set(warnings),
        action_items=action_items,
        remediation_commands=remediation_commands,
    )
    blocker_review_attention = [
        item
        for item in blocker_review
        if item.get("kind") == "blocker" and item.get("tier") in {"aging", "stale", "overdue"}
    ]
    oldest_blocker = _longest_age(blocker_age_sec if isinstance(blocker_age_sec, dict) else {})
    oldest_warning = _longest_age(warning_age_sec if isinstance(warning_age_sec, dict) else {})
    oldest_blocker_detail = (
        f"; oldest_blocker={oldest_blocker[0]} age={_duration(oldest_blocker[1])}"
        if oldest_blocker
        else ""
    )
    oldest_warning_detail = (
        f"; oldest_warning={oldest_warning[0]} age={_duration(oldest_warning[1])}"
        if oldest_warning
        else ""
    )
    if synthetic_count and synthetic_eligible:
        synthetic_cleanup_detail = f"; cleanup=eligible_now:{synthetic_eligible}"
    elif synthetic_count and synthetic_next_eligible is not None:
        synthetic_cleanup_detail = f"; next_cleanup_in={synthetic_next_eligible:g}h"
    elif synthetic_count:
        synthetic_cleanup_detail = "; cleanup_age=unknown"
    else:
        synthetic_cleanup_detail = ""
    rate_parts = []
    if real_raw_per_hour is not None:
        rate_parts.append(f"real_raw/h={real_raw_per_hour:g}")
    if synthetic_per_hour is not None:
        rate_parts.append(f"synthetic/h={synthetic_per_hour:g}")
    if visible_per_hour is not None:
        rate_parts.append(f"visible/h={visible_per_hour:g}")
    rate_detail = "; " + "; ".join(rate_parts) if rate_parts else ""

    sections = [
        {
            "name": "production_gate",
            "status": "blocked" if blockers else ("watch" if warnings else "ok"),
            "detail": f"{len(blockers)} blockers, {len(warnings)} warnings{oldest_blocker_detail}{oldest_warning_detail}",
        },
        {
            "name": "agent_coverage",
            "status": _metric_status(
                int(fleet.get("online") or 0) >= int(fleet.get("expected") or 0) > 0,
                bool(warning_agents),
            ),
            "detail": f"{fleet.get('online', 0)}/{fleet.get('expected', 0)} agents online; warnings={','.join(warning_agents) or 'none'}",
        },
        {
            "name": "agent_service_check",
            "status": service_guard["section_status"],
            "detail": service_guard["detail"],
        },
        {
            "name": "network_visibility",
            "status": "blocked" if missing_sources else ("watch" if stale_sources else "ok"),
            "detail": (
                f"missing={','.join(missing_sources) or 'none'}; "
                f"stale={','.join(stale_sources) or 'none'}; "
                f"diagnosis={','.join(source_diagnoses) or 'none'}"
            ),
        },
        {
            "name": "alert_quality",
            "status": _metric_status(not incident_candidates and visible_24h == 0, bool(suppression_warnings or baseline_warnings)),
            "detail": (
                f"visible_24h={visible_24h}; incident_candidates={len(incident_candidates)}; "
                f"suppression={suppression_quality.get('status', 'unknown')}{rate_detail}"
            ),
        },
        {
            "name": "noise_control",
            "status": "watch" if synthetic_count else "ok",
            "detail": (
                f"synthetic={synthetic_count} ({synthetic_pct:g}% raw); "
                f"prune_eligible={synthetic_eligible}{synthetic_cleanup_detail}{rate_detail}"
            ),
        },
        {
            "name": "public_listener_exposure",
            "status": "watch" if public_listener_warnings or public_listener_unexpected else "ok",
            "detail": (
                f"status={public_listener_status}; "
                f"unexpected={len(public_listener_unexpected)}; "
                f"warnings={','.join(public_listener_warnings[:4]) or 'none'}"
            ),
        },
        {
            "name": "assessment_loop",
            "status": "ok" if assessment_loop.get("status") == "ok" and gate_watch.get("status") in {"stable", "changed", "initialized"} else "watch",
            "detail": (
                f"assessment={assessment_loop.get('status', 'unknown')}; "
                f"gate_watch={gate_watch.get('status', 'unknown')}; "
                f"aging_blockers={len(blocker_review_attention)}{oldest_blocker_detail}"
            ),
        },
        {
            "name": "canaries",
            "status": _metric_status(
                syslog_canary.get("status") == "ok" and rule_canary.get("status") == "ok",
                not rule_quiet_guard.get("ok", False) or not rule_source_guard.get("ok", False),
            ),
            "detail": (
                f"syslog={syslog_canary.get('status', 'unknown')}; "
                f"rules={rule_canary.get('status', 'unknown')} ({_rule_coverage_detail(rule_canary)})"
            ),
        },
        {
            "name": "central_service",
            "status": "ok" if central.get("status") == "ok" else "blocked",
            "detail": str(central.get("status") or "unknown"),
        },
    ]

    strengths: list[str] = []
    if int(fleet.get("online") or 0) == int(fleet.get("expected") or -1):
        strengths.append("all_expected_agents_reporting")
    if visible_24h == 0 and not incident_candidates:
        strengths.append("no_visible_alerts_or_incident_candidates_24h")
    if suppression_quality.get("status") == "ok" and not suppression_warnings:
        strengths.append("suppression_quality_ok")
    if baseline.get("warnings") == []:
        strengths.append("alert_rate_baseline_clean")
    if assessment_loop.get("status") == "ok" and gate_watch.get("status") == "stable":
        strengths.append("assessment_and_gate_watch_stable")
    if noise_housekeep.get("status") == "ok":
        strengths.append("noise_housekeeping_ok")
    if service_guard["status"] == "ok":
        strengths.append("agent_service_check_ok")
    if rule_quiet_guard.get("ok"):
        strengths.append("rule_canary_quiet_guard_ok")
    if rule_source_guard.get("ok"):
        strengths.append("rule_canary_source_guard_ok")

    risks: list[dict[str, str]] = []
    if missing_sources:
        age_text = f" Oldest blocker age: {_duration(oldest_blocker[1])}." if oldest_blocker else ""
        diagnosis_text = f" Diagnoses: {', '.join(source_diagnoses)}." if source_diagnoses else ""
        risks.append(
            {
                "severity": "high",
                "domain": "network_visibility",
                "risk": f"Expected router/syslog sources are missing, so network-side detection has blind spots.{age_text}{diagnosis_text}",
            }
        )
    if warning_agents:
        risks.append(
            {
                "severity": "high",
                "domain": "agent_resource",
                "risk": f"Agents with resource warnings can drop telemetry or block monitor rollout: {', '.join(warning_agents)}.",
            }
        )
    if rollout_blockers:
        risks.append(
            {
                "severity": "high",
                "domain": "agent_rollout",
                "risk": "Agent rollout cannot complete until blockers are cleared: " + ", ".join(rollout_blockers) + ".",
            }
        )
    if service_guard["warnings"] or service_guard["uncorroborated"]:
        risk_bits = []
        if service_guard["warnings"]:
            risk_bits.append("warnings=" + ", ".join(service_guard["warnings"]))
        if service_guard["uncorroborated"]:
            risk_bits.append("uncorroborated=" + ", ".join(service_guard["uncorroborated"]))
        risks.append(
            {
                "severity": "high" if service_guard["uncorroborated"] else "normal",
                "domain": "agent_service",
                "risk": "Agent service verification needs attention: " + "; ".join(risk_bits) + ".",
            }
        )
    elif service_guard["status"] == "ok_corroborated":
        risks.append(
            {
                "severity": "normal",
                "domain": "agent_service",
                "risk": "Some direct agent service checks are SSH-unchecked but corroborated by fresh heartbeats: "
                + ", ".join(service_guard["corroborated"])
                + ".",
            }
        )
    if synthetic_count:
        severity = "normal" if synthetic_eligible == 0 else "high"
        if synthetic_eligible:
            cleanup_context = f" {synthetic_eligible} rows are prune-eligible now."
        elif synthetic_next_eligible is not None:
            cleanup_context = f" Next rows become prune-eligible in about {synthetic_next_eligible:g}h."
        else:
            cleanup_context = ""
        risks.append(
            {
                "severity": severity,
                "domain": "alert_noise",
                "risk": f"Synthetic/test residue dominates raw alert volume; housekeeping must keep this bounded.{cleanup_context}",
            }
        )
    if public_listener_unexpected:
        exposed = []
        for item in public_listener_unexpected[:6]:
            process = str(item.get("process") or "unknown")
            port = str(item.get("port") or "?")
            reason = str(item.get("reason") or "unexpected_public_listener")
            exposed.append(f"{process}:0.0.0.0:{port} ({reason})")
        risks.append(
            {
                "severity": "high",
                "domain": "public_listener",
                "risk": "Unexpected public listeners are reachable on the controller host: " + "; ".join(exposed) + ".",
            }
        )
    if suppression_quality.get("suppressed_high_or_critical"):
        risks.append(
            {
                "severity": "normal",
                "domain": "suppression_review",
                "risk": "Suppressed high-severity non-synthetic examples exist and should remain reviewable.",
            }
        )
    if not rule_quiet_guard.get("ok"):
        risks.append(
            {
                "severity": "normal",
                "domain": "rule_quality",
                "risk": str(rule_quiet_guard.get("detail") or "Rule canary quiet-case coverage needs review."),
            }
        )
    if not rule_source_guard.get("ok"):
        risks.append(
            {
                "severity": "normal",
                "domain": "rule_quality",
                "risk": str(rule_source_guard.get("detail") or "Rule canary source-family coverage needs review."),
            }
        )

    next_steps: list[dict[str, str]] = []
    for item in action_items:
        if isinstance(item, dict):
            next_steps.append(
                {
                    "domain": str(item.get("domain") or "general"),
                    "owner": str(item.get("owner") or "operator"),
                    "urgency": str(item.get("urgency") or "normal"),
                    "action": str(item.get("action") or ""),
                }
            )
    if not next_steps:
        next_steps.append(
            {
                "domain": "monitoring",
                "owner": "operator",
                "urgency": "normal",
                "action": "Continue hourly assessment, review baseline drift, and promote canary monitors only after the gate stays clean.",
            }
        )

    return {
        "status": "blocked" if blockers else ("watch" if warnings else "ready"),
        "readiness_score": _readiness_score(sections),
        "production_ready": bool(gate.get("production_ready")),
        "sections": sections,
        "strengths": strengths,
        "risks": risks,
        "next_slow_steps": next_steps[:8],
        "blocker_review": blocker_review[:12],
        "rule_coverage": rule_coverage,
        "alert_rates": {
            "real_raw_per_hour_24h": real_raw_per_hour,
            "synthetic_per_hour_24h": synthetic_per_hour,
            "visible_per_hour_24h": visible_per_hour,
        },
        "verify_commands": [
            ".venv/bin/python tools/shallot_ops_sanity.py",
            ".venv/bin/python tools/shallot_security_snapshot.py",
            ".venv/bin/python tools/shallot_production_gate.py",
        ],
        "source": "shallot_security_snapshot",
    }


def _print_text(assessment: dict[str, Any]) -> None:
    print(f"self assessment: {assessment['status']} score={assessment['readiness_score']}/100")
    print("sections:")
    for item in assessment.get("sections") or []:
        print(f"  - {item['name']}: {item['status']} ({item['detail']})")
    print("strengths:")
    for item in assessment.get("strengths") or []:
        print(f"  - {item}")
    if not assessment.get("strengths"):
        print("  - none")
    print("risks:")
    for item in assessment.get("risks") or []:
        print(f"  - {item['severity']} {item['domain']}: {item['risk']}")
    if not assessment.get("risks"):
        print("  - none")
    print("blocker review:")
    for item in assessment.get("blocker_review") or []:
        operator = "operator" if item.get("needs_operator") else "watch"
        commands = [str(command) for command in item.get("commands") or []]
        command_detail = f"; verify={commands[0]}" if commands else ""
        print(
            f"  - [{item['tier']}/{operator}/{item['kind']}/{item.get('owner', 'operator')}] "
            f"{item['name']} age={item['age']}; {item.get('action', 'Review this gate item.')}{command_detail}"
        )
    if not assessment.get("blocker_review"):
        print("  - none")
    print("next slow steps:")
    for item in assessment.get("next_slow_steps") or []:
        print(f"  - [{item['urgency']}/{item['owner']}/{item['domain']}] {item['action']}")
    print("verify:")
    for command in assessment.get("verify_commands") or []:
        print(f"  $ {command}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-c", "--config", default="config.yaml")
    parser.add_argument("--hours", type=float, default=1.0)
    parser.add_argument("--expected-log-sources", default="docs/NETWORK_LOG_SOURCES.yaml")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    from tools.shallot_security_snapshot import load_snapshot

    snapshot = load_snapshot(
        config=args.config,
        hours=args.hours,
        expected_log_sources=args.expected_log_sources,
    )
    assessment = assess_snapshot(snapshot)
    if args.json:
        print(json.dumps(assessment, indent=2))
    else:
        _print_text(assessment)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
