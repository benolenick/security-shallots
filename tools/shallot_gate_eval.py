"""Shared production-gate evaluator for Security Shallots snapshots."""

from __future__ import annotations

from typing import Any


def _extend_unique(out: list[str], values: list[Any] | None, *, prefix: str = "") -> None:
    for value in values or []:
        text = f"{prefix}{value}" if prefix else str(value)
        if text not in out:
            out.append(text)


def _remediation_commands(blockers: list[str], warnings: list[str]) -> list[str]:
    commands: list[str] = []

    def add(command: str) -> None:
        if command not in commands:
            commands.append(command)

    joined = " ".join([*blockers, *warnings])
    if "expected_syslog_missing:" in joined or "readiness:network_coverage_gap" in blockers:
        add(".venv/bin/python tools/shallot_router_syslog_plan.py --probe")
        add(".venv/bin/python tools/shallot_syslog_canary.py --timeout 30")
        add(".venv/bin/python tools/shallot_alert_assess.py --hours 1 --summary-json --expected-log-sources docs/NETWORK_LOG_SOURCES.yaml")
    if "rollout:host03:disk>=" in joined or "agent:host03:disk>=" in joined:
        add(".venv/bin/python tools/shallot_fleet_top.py --summary-json")
        add(".venv/bin/python tools/shallot_resource_cleanup_plan.py --agent host03")
        add(".venv/bin/python tools/argus_network_egress_rollout.py --target host03 --action plan")
    if "rollout:target_access:host03:" in joined:
        add(".venv/bin/python tools/argus_network_egress_rollout.py --target host03 --action plan")
    if "alerts:synthetic_residue_review" in joined:
        add(".venv/bin/python tools/shallot_noise_housekeep.py --prune-synthetic-older-hours 24 --summary-json")
        add(".venv/bin/python tools/shallot_alert_assess.py --hours 24 --summary-json")
    if "assessment_loop:" in joined:
        add("systemctl status shallot-alert-assess.timer shallot-alert-assess.service --no-pager")
        add("tail -n 160 docs/ALERT_ASSESSMENT_LOG.md")
    if "central:" in joined:
        add("systemctl status shallotd.service --no-pager")
        add("curl -sk https://127.0.0.1:8844/api/health | python3 -m json.tool")
    if "public_listener:" in joined:
        add(".venv/bin/python tools/shallot_public_listener_audit.py --json")
    add(".venv/bin/python tools/shallot_production_gate.py")
    return commands[:10]


def _dedupe_warning_aliases(warnings: list[str]) -> list[str]:
    """Prefer the richer alert-assessment warning when sources overlap."""
    out: list[str] = []
    warning_set = set(warnings)
    for warning in warnings:
        if warning.startswith("pipeline:synthetic_residue") and warning.replace("pipeline:", "alerts:", 1) in warning_set:
            continue
        out.append(warning)
    return out


def _filter_accepted_network_advisories(blockers: list[str], warnings: list[str]) -> list[str]:
    joined = " ".join([*blockers, *warnings])
    router_syslog_expected = "expected_syslog_missing:" in joined or "readiness:network_coverage_gap" in blockers
    if not router_syslog_expected:
        return warnings
    accepted = {
        "network_advisory:packet_ids_disabled",
        "network_advisory:pfsense_disabled",
    }
    return [warning for warning in warnings if warning not in accepted]


def _filter_warning_blocker_duplicates(blockers: list[str], warnings: list[str]) -> list[str]:
    out: list[str] = []
    blocker_set = set(blockers)
    for warning in warnings:
        if warning.startswith("readiness:source:") and warning.endswith(":expected_source_missing"):
            source = warning.removeprefix("readiness:source:").removesuffix(":expected_source_missing")
            if f"network:expected_syslog_missing:{source}" in blocker_set:
                continue
        if warning.startswith("fleet:disk_pressure:"):
            agent = warning.rsplit(":", 1)[-1]
            if any(item.startswith(f"rollout:{agent}:disk>=") for item in blocker_set):
                continue
        out.append(warning)
    return out


def _filter_warning_aliases(blockers: list[str], warnings: list[str]) -> list[str]:
    out: list[str] = []
    warning_set = set(warnings)
    blocker_set = set(blockers)
    synthetic_residue_added = False
    for warning in warnings:
        if warning.startswith("agent:") and ":disk>=" in warning:
            agent = warning.split(":", 2)[1]
            if f"fleet:disk_pressure:{agent}" in warning_set or any(
                item.startswith(f"rollout:{agent}:disk>=") for item in blocker_set
            ):
                continue
        if warning.startswith("alerts:synthetic_residue>="):
            if synthetic_residue_added:
                continue
            out.append("alerts:synthetic_residue_review")
            synthetic_residue_added = True
            continue
        out.append(warning)
    return out


def _filter_blocker_aliases(blockers: list[str]) -> list[str]:
    blocker_set = set(blockers)
    has_specific_network_gap = any(item.startswith("network:expected_syslog_missing:") for item in blockers)
    out: list[str] = []
    for blocker in blockers:
        if blocker == "readiness:network_coverage_gap" and has_specific_network_gap:
            continue
        if blocker not in blocker_set:
            continue
        out.append(blocker)
    return out


def _synthetic_residue_next_action(alerts: dict[str, Any]) -> str:
    warnings = [str(item) for item in alerts.get("guardrail_warnings") or []]
    if not any(item.startswith("synthetic_residue>=") for item in warnings):
        return ""
    residue = alerts.get("synthetic_residue") or {}
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


def _next_actions(snapshot: dict[str, Any]) -> list[str]:
    readiness = snapshot.get("readiness") or {}
    agent_rollout = snapshot.get("agent_rollout") or {}
    alerts = snapshot.get("alerts") or {}
    public_listeners = snapshot.get("public_listeners") or {}
    actions: list[str] = []

    def add(action: Any) -> None:
        text = str(action or "").strip()
        if text and text not in actions:
            actions.append(text)

    for action in readiness.get("next_actions") or []:
        add(action)
    for source in snapshot.get("external_sources") or []:
        name = source.get("name") or "expected_source"
        diagnosis = source.get("diagnosis") or ""
        next_step = source.get("next_step") or ""
        if diagnosis and next_step and source.get("status") in {"missing", "stale", "unconfigured"}:
            add(f"{name}: {diagnosis}; {next_step}")
    add(_synthetic_residue_next_action(alerts))
    for item in public_listeners.get("unexpected") or []:
        port = item.get("port", "?")
        process = item.get("process") or item.get("service") or "unknown"
        reason = item.get("reason") or "unexpected_public_listener"
        clients = item.get("active_clients") or []
        client_text = f"; active clients={','.join(str(client) for client in clients[:6])}" if clients else ""
        action = item.get("action") or "bind to localhost/LAN, firewall it, stop it, or add it to the listener allowlist after review."
        add(
            f"Review public listener {process} on 0.0.0.0:{port} ({reason}); "
            f"{action}{client_text}"
        )
    for action in agent_rollout.get("next_actions") or []:
        add(action)
    return actions[:8]


def _action_item(action: str) -> dict[str, str]:
    text = str(action or "").strip()
    lowered = text.lower()
    if "router ui" in lowered or "expected syslog source" in lowered or "remote syslog" in lowered:
        return {
            "domain": "network_source",
            "owner": "manual_router_admin",
            "urgency": "high",
            "action": text,
        }
    if "host03" in lowered and ("disk" in lowered or "resource" in lowered):
        return {
            "domain": "agent_resource",
            "owner": "manual_host_cleanup",
            "urgency": "high",
            "action": text,
        }
    if "ssh access" in lowered or "ssh-copy-id" in lowered or "target_access" in lowered:
        return {
            "domain": "agent_rollout",
            "owner": "operator",
            "urgency": "high",
            "action": text,
        }
    if "synthetic residue" in lowered or "prune" in lowered or "housekeep" in lowered:
        owner = "timer_or_manual_review" if "not yet 24h" in lowered else "manual_review"
        return {
            "domain": "alert_noise",
            "owner": owner,
            "urgency": "normal",
            "action": text,
        }
    if "public listener" in lowered or "0.0.0.0:" in lowered:
        return {
            "domain": "public_listener",
            "owner": "operator",
            "urgency": "high",
            "action": text,
        }
    return {
        "domain": "general",
        "owner": "operator",
        "urgency": "normal",
        "action": text,
    }


def _action_items(actions: list[str]) -> list[dict[str, str]]:
    source_specific = set()
    for action in actions:
        text = str(action or "").strip()
        if ": " in text and "expected_source" not in text:
            source_specific.add(text.split(":", 1)[0])

    items: list[dict[str, str]] = []
    for action in actions:
        text = str(action or "").strip()
        if not text:
            continue
        lowered = text.lower()
        if lowered.startswith("configure or retire expected syslog source "):
            source = text.rsplit(" ", 1)[-1]
            if source in source_specific:
                continue
        items.append(_action_item(text))
    return items


def evaluate_gate(snapshot: dict[str, Any], *, strict_warnings: bool = False) -> dict[str, Any]:
    blockers: list[str] = []
    warnings: list[str] = []
    strengths: list[str] = []

    pipeline = snapshot.get("pipeline") or {}
    readiness = snapshot.get("readiness") or {}
    network = snapshot.get("network") or {}
    fleet = snapshot.get("fleet") or {}
    alerts = snapshot.get("alerts") or {}
    assessment_loop = snapshot.get("assessment_loop") or {}
    agent_rollout = snapshot.get("agent_rollout") or {}
    central_health = snapshot.get("central_health") or {}

    if pipeline.get("status") == "blocked":
        _extend_unique(blockers, pipeline.get("blockers"), prefix="pipeline:")
    elif pipeline.get("status") not in {"ok", None}:
        _extend_unique(warnings, pipeline.get("warnings"), prefix="pipeline:")

    _extend_unique(blockers, readiness.get("blockers"), prefix="readiness:")
    _extend_unique(blockers, network.get("blocking_gaps"), prefix="network:")
    _extend_unique(blockers, fleet.get("blockers"), prefix="fleet:")
    _extend_unique(blockers, agent_rollout.get("blockers"), prefix="rollout:")
    if assessment_loop.get("status") not in {"ok", None}:
        _extend_unique(blockers, assessment_loop.get("warnings"), prefix="assessment_loop:")
    if central_health.get("status") not in {"ok", None}:
        _extend_unique(blockers, central_health.get("blockers") or central_health.get("warnings"), prefix="central:")

    _extend_unique(warnings, readiness.get("warnings"), prefix="readiness:")
    _extend_unique(warnings, network.get("advisory_gaps"), prefix="network_advisory:")
    _extend_unique(warnings, fleet.get("warnings"), prefix="fleet:")
    _extend_unique(warnings, agent_rollout.get("warnings"), prefix="rollout:")
    _extend_unique(warnings, alerts.get("guardrail_warnings"), prefix="alerts:")
    _extend_unique(warnings, alerts.get("suppression_warnings"), prefix="suppression:")
    _extend_unique(warnings, (alerts.get("rate_baseline") or {}).get("warnings"), prefix="baseline:")
    for agent in fleet.get("warning_agents") or []:
        name = agent.get("agent", "unknown")
        _extend_unique(warnings, agent.get("warnings"), prefix=f"agent:{name}:")
    blockers = _filter_blocker_aliases(blockers)
    warnings = _dedupe_warning_aliases(warnings)
    warnings = _filter_accepted_network_advisories(blockers, warnings)
    warnings = _filter_warning_blocker_duplicates(blockers, warnings)
    warnings = _filter_warning_aliases(blockers, warnings)

    _extend_unique(strengths, pipeline.get("strengths"))
    _extend_unique(strengths, readiness.get("strengths"))
    _extend_unique(strengths, fleet.get("strengths"), prefix="fleet:")
    _extend_unique(strengths, central_health.get("strengths"), prefix="central:")

    status = "ready"
    if blockers:
        status = "blocked"
    elif strict_warnings and warnings:
        status = "watch"
    elif warnings:
        status = "ready_with_warnings"

    next_actions = _next_actions(snapshot)
    return {
        "status": status,
        "production_ready": status in {"ready", "ready_with_warnings"},
        "strict_warnings": strict_warnings,
        "blockers": blockers,
        "warnings": warnings,
        "strengths": strengths,
        "next_actions": next_actions,
        "action_items": _action_items(next_actions),
        "remediation_commands": _remediation_commands(blockers, warnings),
    }
