"""Production gate contract tests."""

from __future__ import annotations

from tools.shallot_gate_eval import evaluate_gate


def _snapshot() -> dict:
    return {
        "pipeline": {"status": "ok", "blockers": [], "warnings": [], "strengths": ["agents_online"]},
        "readiness": {
            "blockers": [],
            "warnings": [],
            "strengths": ["quiet_alert_window"],
            "next_actions": [],
        },
        "network": {
            "blocking_gaps": [],
            "advisory_gaps": ["packet_ids_disabled"],
        },
        "fleet": {"blockers": [], "warnings": [], "warning_agents": []},
        "alerts": {"guardrail_warnings": [], "suppression_warnings": [], "rate_baseline": {"warnings": []}},
        "assessment_loop": {"status": "ok", "warnings": []},
        "central_health": {"status": "ok", "blockers": [], "warnings": [], "strengths": ["api_health_ok"]},
    }


def test_gate_allows_advisory_only_gaps_by_default() -> None:
    result = evaluate_gate(_snapshot())

    assert result["status"] == "ready_with_warnings"
    assert result["production_ready"] is True
    assert result["blockers"] == []
    assert result["warnings"] == ["network_advisory:packet_ids_disabled"]


def test_gate_can_fail_on_warnings_in_strict_mode() -> None:
    result = evaluate_gate(_snapshot(), strict_warnings=True)

    assert result["status"] == "watch"
    assert result["production_ready"] is False
    assert result["blockers"] == []


def test_gate_blocks_on_expected_router_syslog_gap() -> None:
    snap = _snapshot()
    snap["readiness"]["blockers"] = ["network_coverage_gap"]
    snap["readiness"]["next_actions"] = ["Configure router syslog"]
    snap["network"]["blocking_gaps"] = ["expected_syslog_missing:main_gateway"]

    result = evaluate_gate(snap)

    assert result["status"] == "blocked"
    assert result["production_ready"] is False
    assert "readiness:network_coverage_gap" not in result["blockers"]
    assert "network:expected_syslog_missing:main_gateway" in result["blockers"]
    assert result["next_actions"] == ["Configure router syslog"]
    assert ".venv/bin/python tools/shallot_router_syslog_plan.py --probe" in result["remediation_commands"]
    assert ".venv/bin/python tools/shallot_syslog_canary.py --timeout 30" in result["remediation_commands"]


def test_gate_keeps_generic_network_coverage_blocker_without_specific_network_gap() -> None:
    snap = _snapshot()
    snap["readiness"]["blockers"] = ["network_coverage_gap"]

    result = evaluate_gate(snap)

    assert result["blockers"] == ["readiness:network_coverage_gap"]


def test_gate_suppresses_optional_packet_sensor_advisories_when_router_syslog_is_expected() -> None:
    snap = _snapshot()
    snap["readiness"]["blockers"] = ["network_coverage_gap"]
    snap["readiness"]["warnings"] = ["source:main_gateway:expected_source_missing"]
    snap["network"]["blocking_gaps"] = ["expected_syslog_missing:main_gateway"]
    snap["network"]["advisory_gaps"] = ["packet_ids_disabled", "pfsense_disabled"]

    result = evaluate_gate(snap)

    assert "network_advisory:packet_ids_disabled" not in result["warnings"]
    assert "network_advisory:pfsense_disabled" not in result["warnings"]
    assert result["warnings"] == []


def test_gate_suppresses_readiness_source_warning_when_matching_network_blocker_exists() -> None:
    snap = _snapshot()
    snap["readiness"]["blockers"] = ["network_coverage_gap"]
    snap["readiness"]["warnings"] = [
        "source:main_gateway:expected_source_missing",
        "source:isp_wifi_gateway:expected_source_missing",
    ]
    snap["network"]["blocking_gaps"] = [
        "expected_syslog_missing:main_gateway",
        "expected_syslog_missing:isp_wifi_gateway",
    ]
    snap["network"]["advisory_gaps"] = []

    result = evaluate_gate(snap)

    assert "network:expected_syslog_missing:main_gateway" in result["blockers"]
    assert "network:expected_syslog_missing:isp_wifi_gateway" in result["blockers"]
    assert result["warnings"] == []


def test_gate_next_actions_include_external_source_diagnosis() -> None:
    snap = _snapshot()
    snap["readiness"]["blockers"] = ["network_coverage_gap"]
    snap["readiness"]["next_actions"] = ["Configure router syslog"]
    snap["network"]["blocking_gaps"] = ["expected_syslog_missing:main_gateway"]
    snap["external_sources"] = [
        {
            "name": "main_gateway",
            "status": "missing",
            "diagnosis": "management_ui_reachable_syslog_not_forwarding",
            "next_step": "Log into the reachable router UI and enable remote syslog to 192.168.0.172:514.",
        }
    ]

    result = evaluate_gate(snap)

    assert result["next_actions"] == [
        "Configure router syslog",
        "main_gateway: management_ui_reachable_syslog_not_forwarding; Log into the reachable router UI and enable remote syslog to 192.168.0.172:514.",
    ]
    assert result["action_items"][1] == {
        "domain": "network_source",
        "owner": "manual_router_admin",
        "urgency": "high",
        "action": "main_gateway: management_ui_reachable_syslog_not_forwarding; Log into the reachable router UI and enable remote syslog to 192.168.0.172:514.",
    }


def test_gate_action_items_prefer_specific_external_source_steps() -> None:
    snap = _snapshot()
    snap["readiness"]["blockers"] = ["network_coverage_gap"]
    snap["readiness"]["next_actions"] = ["Configure or retire expected syslog source main_gateway"]
    snap["network"]["blocking_gaps"] = ["expected_syslog_missing:main_gateway"]
    snap["external_sources"] = [
        {
            "name": "main_gateway",
            "status": "missing",
            "diagnosis": "management_ui_reachable_syslog_not_forwarding",
            "next_step": "Log into the reachable router UI and enable remote syslog to 192.168.0.172:514.",
        }
    ]

    result = evaluate_gate(snap)

    assert result["next_actions"] == [
        "Configure or retire expected syslog source main_gateway",
        "main_gateway: management_ui_reachable_syslog_not_forwarding; Log into the reachable router UI and enable remote syslog to 192.168.0.172:514.",
    ]
    assert [item["action"] for item in result["action_items"]] == [
        "main_gateway: management_ui_reachable_syslog_not_forwarding; Log into the reachable router UI and enable remote syslog to 192.168.0.172:514."
    ]


def test_gate_blocks_on_assessment_loop_warning() -> None:
    snap = _snapshot()
    snap["assessment_loop"] = {"status": "warn", "warnings": ["assessment_log_stale"]}

    result = evaluate_gate(snap)

    assert result["status"] == "blocked"
    assert result["blockers"] == ["assessment_loop:assessment_log_stale"]


def test_gate_blocks_on_central_health_failure() -> None:
    snap = _snapshot()
    snap["central_health"] = {
        "status": "fail",
        "blockers": ["central_api_health:https://127.0.0.1:8844/api/health: status=degraded"],
        "warnings": [],
    }

    result = evaluate_gate(snap)

    assert result["status"] == "blocked"
    assert result["blockers"] == [
        "central:central_api_health:https://127.0.0.1:8844/api/health: status=degraded"
    ]
    assert "systemctl status shallotd.service --no-pager" in result["remediation_commands"]


def test_gate_blocks_on_agent_rollout_resource_blocker() -> None:
    snap = _snapshot()
    snap["agent_rollout"] = {
        "status": "blocked",
        "blockers": ["host03:disk>=85%"],
        "warnings": [],
        "next_actions": ["Clear disk on host03"],
    }

    result = evaluate_gate(snap)

    assert result["status"] == "blocked"
    assert "rollout:host03:disk>=85%" in result["blockers"]
    assert result["next_actions"] == ["Clear disk on host03"]
    assert result["action_items"] == [
        {
            "domain": "agent_resource",
            "owner": "manual_host_cleanup",
            "urgency": "high",
            "action": "Clear disk on host03",
        }
    ]
    assert ".venv/bin/python tools/shallot_fleet_top.py --summary-json" in result["remediation_commands"]
    assert ".venv/bin/python tools/shallot_resource_cleanup_plan.py --agent host03" in result["remediation_commands"]
    assert ".venv/bin/python tools/argus_network_egress_rollout.py --target host03 --action plan" in result["remediation_commands"]
    assert result["remediation_commands"].index(".venv/bin/python tools/shallot_fleet_top.py --summary-json") < result[
        "remediation_commands"
    ].index(".venv/bin/python tools/argus_network_egress_rollout.py --target host03 --action plan")


def test_gate_suppresses_agent_disk_warning_when_fleet_disk_pressure_exists() -> None:
    snap = _snapshot()
    snap["network"]["advisory_gaps"] = []
    snap["fleet"]["warnings"] = ["disk_pressure:host03"]
    snap["fleet"]["warning_agents"] = [{"agent": "host03", "warnings": ["disk>=80%"]}]

    result = evaluate_gate(snap)

    assert result["warnings"] == ["fleet:disk_pressure:host03"]


def test_gate_suppresses_agent_disk_warning_when_rollout_disk_blocker_exists() -> None:
    snap = _snapshot()
    snap["network"]["advisory_gaps"] = []
    snap["fleet"]["warning_agents"] = [{"agent": "host03", "warnings": ["disk>=80%"]}]
    snap["agent_rollout"] = {
        "status": "blocked",
        "blockers": ["host03:disk>=80%"],
        "warnings": [],
        "next_actions": [],
    }

    result = evaluate_gate(snap)

    assert "rollout:host03:disk>=80%" in result["blockers"]
    assert result["warnings"] == []


def test_gate_suppresses_fleet_disk_warning_when_rollout_disk_blocker_exists() -> None:
    snap = _snapshot()
    snap["network"]["advisory_gaps"] = []
    snap["fleet"]["warnings"] = ["disk_pressure:host03"]
    snap["agent_rollout"] = {
        "status": "blocked",
        "blockers": ["host03:disk>=80%"],
        "warnings": [],
        "next_actions": [],
    }

    result = evaluate_gate(snap)

    assert "rollout:host03:disk>=80%" in result["blockers"]
    assert result["warnings"] == []


def test_gate_warns_on_suppression_quality_without_blocking() -> None:
    snap = _snapshot()
    snap["network"]["advisory_gaps"] = []
    snap["alerts"]["suppression_warnings"] = ["suppressed_critical_present"]

    result = evaluate_gate(snap)

    assert result["status"] == "ready_with_warnings"
    assert result["production_ready"] is True
    assert "suppression:suppressed_critical_present" in result["warnings"]


def test_gate_prefers_alert_synthetic_residue_warning_over_pipeline_alias() -> None:
    snap = _snapshot()
    snap["network"]["advisory_gaps"] = []
    snap["pipeline"]["status"] = "warn"
    snap["pipeline"]["warnings"] = ["synthetic_residue>=80pct_raw", "synthetic_residue>=1000/day"]
    snap["alerts"]["guardrail_warnings"] = ["synthetic_residue>=80pct_raw", "synthetic_residue>=1000/day"]

    result = evaluate_gate(snap)

    assert result["warnings"] == ["alerts:synthetic_residue_review"]


def test_gate_collapses_multiple_alert_synthetic_residue_warnings() -> None:
    snap = _snapshot()
    snap["network"]["advisory_gaps"] = []
    snap["alerts"]["guardrail_warnings"] = ["synthetic_residue>=80pct_raw", "synthetic_residue>=1000/day"]

    result = evaluate_gate(snap)

    assert result["warnings"] == ["alerts:synthetic_residue_review"]


def test_gate_remediation_includes_synthetic_residue_dry_run() -> None:
    snap = _snapshot()
    snap["network"]["advisory_gaps"] = []
    snap["alerts"]["guardrail_warnings"] = ["synthetic_residue>=80pct_raw"]

    result = evaluate_gate(snap)

    assert ".venv/bin/python tools/shallot_noise_housekeep.py --prune-synthetic-older-hours 24 --summary-json" in result[
        "remediation_commands"
    ]
    assert ".venv/bin/python tools/shallot_alert_assess.py --hours 24 --summary-json" in result["remediation_commands"]
    assert not any("--apply-prune" in command for command in result["remediation_commands"])


def test_gate_remediation_keeps_final_gate_rerun_when_multiple_domains_need_checks() -> None:
    snap = _snapshot()
    snap["readiness"]["blockers"] = ["network_coverage_gap"]
    snap["network"]["blocking_gaps"] = ["expected_syslog_missing:main_gateway"]
    snap["network"]["advisory_gaps"] = []
    snap["agent_rollout"] = {
        "status": "blocked",
        "blockers": ["host03:disk>=80%"],
        "warnings": [],
        "next_actions": [],
    }
    snap["alerts"]["guardrail_warnings"] = ["synthetic_residue>=80pct_raw"]

    result = evaluate_gate(snap)

    assert ".venv/bin/python tools/shallot_noise_housekeep.py --prune-synthetic-older-hours 24 --summary-json" in result[
        "remediation_commands"
    ]
    assert result["remediation_commands"][-1] == ".venv/bin/python tools/shallot_production_gate.py"


def test_gate_routes_rollout_target_access_blocker_to_rollout_planner() -> None:
    snap = _snapshot()
    snap["agent_rollout"] = {
        "status": "blocked",
        "blockers": ["target_access:host03:ssh_publickey_denied"],
        "warnings": [],
        "next_actions": ["Restore SSH access before promoting network_egress on host03"],
    }

    result = evaluate_gate(snap)

    assert "rollout:target_access:host03:ssh_publickey_denied" in result["blockers"]
    assert ".venv/bin/python tools/argus_network_egress_rollout.py --target host03 --action plan" in result[
        "remediation_commands"
    ]
    assert result["action_items"][0]["domain"] == "agent_rollout"
    assert result["action_items"][0]["urgency"] == "high"


def test_gate_next_actions_include_synthetic_residue_wait_context() -> None:
    snap = _snapshot()
    snap["network"]["advisory_gaps"] = []
    snap["alerts"]["guardrail_warnings"] = ["synthetic_residue>=80pct_raw"]
    snap["alerts"]["synthetic_residue"] = {
        "count": 1000,
        "prune_eligible_24h": 0,
        "oldest_age_hours": 10.25,
        "next_eligible_in_hours": 13.75,
    }

    result = evaluate_gate(snap)

    assert result["next_actions"] == [
        "Review synthetic residue; current test rows are not yet 24h prune-eligible (oldest 10.25h; next eligible in ~13.75h). Let shallot-alert-assess.timer age/prune them, or confirm no active load test before manual cleanup."
    ]
    assert result["action_items"][0]["domain"] == "alert_noise"
    assert result["action_items"][0]["owner"] == "timer_or_manual_review"


def test_gate_next_actions_include_synthetic_residue_prune_context() -> None:
    snap = _snapshot()
    snap["network"]["advisory_gaps"] = []
    snap["alerts"]["guardrail_warnings"] = ["synthetic_residue>=1000/day"]
    snap["alerts"]["synthetic_residue"] = {
        "count": 1000,
        "prune_eligible_24h": 25,
        "oldest_age_hours": 30.0,
    }

    result = evaluate_gate(snap)

    assert result["next_actions"] == [
        "Review synthetic residue; 25 rows are older than 24h and prune-eligible. Run shallot_noise_housekeep.py after confirming no active load test, or let shallot-alert-assess.timer prune them."
    ]
