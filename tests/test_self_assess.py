"""Security Shallots self-assessment tests."""

from __future__ import annotations

from tools.shallot_self_assess import _print_text, assess_snapshot


def _snapshot() -> dict:
    return {
        "production_gate": {
            "status": "blocked",
            "production_ready": False,
            "blockers": [
                "network:expected_syslog_missing:main_gateway",
                "network:expected_syslog_missing:isp_wifi_gateway",
                "rollout:host03:disk>=80%",
            ],
            "warnings": ["alerts:synthetic_residue_review"],
            "remediation_commands": [
                ".venv/bin/python tools/shallot_router_syslog_plan.py --probe",
                ".venv/bin/python tools/shallot_syslog_canary.py --timeout 30",
                ".venv/bin/python tools/shallot_fleet_top.py --summary-json",
                ".venv/bin/python tools/shallot_resource_cleanup_plan.py --agent host03",
                ".venv/bin/python tools/shallot_noise_housekeep.py --prune-synthetic-older-hours 24 --summary-json",
            ],
            "action_items": [
                {
                    "domain": "network_source",
                    "owner": "manual_router_admin",
                    "urgency": "high",
                    "action": "main_gateway: Enable D-Link remote syslog.",
                },
                {
                    "domain": "network_source",
                    "owner": "manual_router_admin",
                    "urgency": "high",
                    "action": "isp_wifi_gateway: Enable Sagemcom remote syslog.",
                },
                {
                    "domain": "agent_resource",
                    "owner": "manual_host_cleanup",
                    "urgency": "high",
                    "action": "Clear host03 disk warning.",
                },
            ],
        },
        "fleet": {
            "online": 4,
            "expected": 4,
            "agents": [
                {"agent": "host01", "warnings": []},
                {"agent": "host03", "warnings": ["disk>=80%"]},
            ],
        },
        "alerts": {
            "last_24h_visible": 0,
            "real_raw_per_hour_24h": 0.42,
            "synthetic_per_hour_24h": 68.33,
            "visible_per_hour_24h": 0.0,
            "incident_candidates": [],
            "suppression_quality": {
                "status": "ok",
                "suppressed_high_or_critical": 2,
            },
            "suppression_warnings": [],
            "rate_baseline": {"warnings": []},
            "synthetic_residue": {
                "count": 1640,
                "percent_raw": 99.39,
                "prune_eligible_24h": 0,
                "next_eligible_in_hours": 11.37,
            },
        },
        "external_sources": [
            {
                "name": "main_gateway",
                "status": "missing",
                "diagnosis": "management_ui_reachable_syslog_not_forwarding",
            },
            {"name": "isp_wifi_gateway", "status": "ok"},
        ],
        "assessment_loop": {"status": "ok"},
        "agent_services": {
            "status": "ok",
            "warnings": [],
            "unchecked_agents": [],
            "heartbeat_corroborated_agents": [],
            "unchecked_without_fresh_heartbeat": [],
        },
        "public_listeners": {
            "status": "ok",
            "warnings": [],
            "unexpected": [],
        },
        "gate_watch": {
            "status": "stable",
            "blocker_age_sec": {
                "network:expected_syslog_missing:main_gateway": 5400,
                "network:expected_syslog_missing:isp_wifi_gateway": 4800,
                "rollout:host03:disk>=80%": 1200,
            },
            "warning_age_sec": {"alerts:synthetic_residue_review": 900},
        },
        "noise_housekeep": {"status": "ok"},
        "central_health": {"status": "ok"},
        "syslog_canary": {"status": "ok"},
        "rule_canary": {
            "status": "ok",
            "coverage": {
                "total_cases": 61,
                "positive_cases": 49,
                "quiet_cases": 12,
                "covered_rule_ids": [
                    "argus.anti_tamper",
                    "syslog.access_control_change",
                    "syslog.config_export",
                    "syslog.credential_change",
                    "syslog.dhcp_reservation_change",
                    "syslog.dmz_exposure_change",
                    "syslog.dns_change",
                    "syslog.exposure_change",
                    "syslog.firmware_change",
                    "syslog.guest_network_change",
                    "syslog.security_disabled",
                    "syslog.vpn_exposure_change",
                    "syslog.wifi_security_change",
                    "syslog.wps_change",
                ],
                "sources": {
                    "argus": {"cases": 31, "passed": 31, "failed": 0},
                    "suricata": {"cases": 3, "passed": 3, "failed": 0},
                    "syslog": {"cases": 27, "passed": 27, "failed": 0},
                },
            },
            "coverage_guardrails": {
                "quiet": {"minimum_cases": 11, "headroom_cases": 1},
                "sources": {
                    "minimum_cases": {"argus": 3, "suricata": 2, "syslog": 5},
                    "headroom_cases": {"argus": 28, "suricata": 1, "syslog": 22},
                },
            },
        },
        "agent_rollout": {"status": "blocked"},
        "network": {"status": "gap"},
    }


def test_assessment_summarizes_blocked_but_controlled_posture() -> None:
    assessment = assess_snapshot(_snapshot())

    assert assessment["status"] == "blocked"
    assert assessment["production_ready"] is False
    assert 0 < assessment["readiness_score"] < 100
    assert "all_expected_agents_reporting" in assessment["strengths"]
    assert "no_visible_alerts_or_incident_candidates_24h" in assessment["strengths"]
    assert "suppression_quality_ok" in assessment["strengths"]
    assert "agent_service_check_ok" in assessment["strengths"]
    assert "rule_canary_quiet_guard_ok" in assessment["strengths"]
    assert "rule_canary_source_guard_ok" in assessment["strengths"]
    assert any(item["domain"] == "network_visibility" for item in assessment["risks"])
    assert any(item["domain"] == "agent_resource" for item in assessment["risks"])
    assert any(item["domain"] == "agent_rollout" for item in assessment["risks"])
    assert any(item["domain"] == "alert_noise" and item["severity"] == "normal" for item in assessment["risks"])
    gate_section = next(item for item in assessment["sections"] if item["name"] == "production_gate")
    assert "oldest_blocker=network:expected_syslog_missing:main_gateway age=1.5h" in gate_section["detail"]
    assert "oldest_warning=alerts:synthetic_residue_review age=15m" in gate_section["detail"]
    network_section = next(item for item in assessment["sections"] if item["name"] == "network_visibility")
    assert "diagnosis=main_gateway:management_ui_reachable_syslog_not_forwarding" in network_section["detail"]
    service_section = next(item for item in assessment["sections"] if item["name"] == "agent_service_check")
    assert service_section["status"] == "ok"
    assert "status=ok" in service_section["detail"]
    assert any(
        "main_gateway:management_ui_reachable_syslog_not_forwarding" in item["risk"]
        for item in assessment["risks"]
    )
    noise_section = next(item for item in assessment["sections"] if item["name"] == "noise_control")
    assert "next_cleanup_in=11.37h" in noise_section["detail"]
    assert "real_raw/h=0.42" in noise_section["detail"]
    assert "synthetic/h=68.33" in noise_section["detail"]
    alert_section = next(item for item in assessment["sections"] if item["name"] == "alert_quality")
    assert "visible/h=0" in alert_section["detail"]
    assert "real_raw/h=0.42" in alert_section["detail"]
    canary_section = next(item for item in assessment["sections"] if item["name"] == "canaries")
    assert "61 cases" in canary_section["detail"]
    assert "sources argus=31, suricata=3, syslog=27" in canary_section["detail"]
    assert "quiet_guard=ok" in canary_section["detail"]
    assert "quiet_headroom=1" in canary_section["detail"]
    assert "source_guard=ok" in canary_section["detail"]
    assert "source_headroom=argus=28,suricata=1,syslog=22" in canary_section["detail"]
    loop_section = next(item for item in assessment["sections"] if item["name"] == "assessment_loop")
    assert "aging_blockers=2" in loop_section["detail"]
    assert assessment["blocker_review"][:4] == [
        {
            "kind": "blocker",
            "name": "network:expected_syslog_missing:main_gateway",
            "age_sec": 5400,
            "age": "1.5h",
            "tier": "aging",
            "needs_operator": True,
            "domain": "network_source",
            "owner": "manual_router_admin",
            "urgency": "high",
            "action": "main_gateway: Enable D-Link remote syslog.",
            "commands": [
                ".venv/bin/python tools/shallot_router_syslog_plan.py --probe",
                ".venv/bin/python tools/shallot_syslog_canary.py --timeout 30",
            ],
        },
        {
            "kind": "blocker",
            "name": "network:expected_syslog_missing:isp_wifi_gateway",
            "age_sec": 4800,
            "age": "1.3h",
            "tier": "aging",
            "needs_operator": True,
            "domain": "network_source",
            "owner": "manual_router_admin",
            "urgency": "high",
            "action": "isp_wifi_gateway: Enable Sagemcom remote syslog.",
            "commands": [
                ".venv/bin/python tools/shallot_router_syslog_plan.py --probe",
                ".venv/bin/python tools/shallot_syslog_canary.py --timeout 30",
            ],
        },
        {
            "kind": "blocker",
            "name": "rollout:host03:disk>=80%",
            "age_sec": 1200,
            "age": "20m",
            "tier": "new",
            "needs_operator": True,
            "domain": "agent_resource",
            "owner": "manual_host_cleanup",
            "urgency": "high",
            "action": "Clear host03 disk warning.",
            "commands": [
                ".venv/bin/python tools/shallot_fleet_top.py --summary-json",
                ".venv/bin/python tools/shallot_resource_cleanup_plan.py --agent host03",
            ],
        },
        {
            "kind": "warning",
            "name": "alerts:synthetic_residue_review",
            "age_sec": 900,
            "age": "15m",
            "tier": "watch",
            "needs_operator": False,
            "domain": "alert_noise",
            "owner": "timer_or_manual_review",
            "urgency": "normal",
            "action": "Review synthetic residue and let housekeeping prune after rows are 24h old.",
            "commands": [
                ".venv/bin/python tools/shallot_noise_housekeep.py --prune-synthetic-older-hours 24 --summary-json",
            ],
        },
    ]
    assert assessment["rule_coverage"]["total_cases"] == 61
    assert assessment["alert_rates"] == {
        "real_raw_per_hour_24h": 0.42,
        "synthetic_per_hour_24h": 68.33,
        "visible_per_hour_24h": 0.0,
    }
    assert any("Next rows become prune-eligible in about 11.37h." in item["risk"] for item in assessment["risks"])
    assert [item["domain"] for item in assessment["next_slow_steps"]] == [
        "network_source",
        "network_source",
        "agent_resource",
    ]
    assert ".venv/bin/python tools/shallot_ops_sanity.py" in assessment["verify_commands"]


def test_assessment_warns_when_rule_canary_quiet_coverage_is_thin() -> None:
    snap = _snapshot()
    snap["rule_canary"]["coverage"]["quiet_cases"] = 1
    snap["rule_canary"]["coverage"]["total_cases"] = 61
    snap["rule_canary"]["coverage_guardrails"]["quiet"]["headroom_cases"] = -10

    assessment = assess_snapshot(snap)

    canary_section = next(item for item in assessment["sections"] if item["name"] == "canaries")
    assert canary_section["status"] == "watch"
    assert "quiet_guard=thin" in canary_section["detail"]
    assert "quiet_headroom=-10" in canary_section["detail"]
    assert "rule_canary_quiet_guard_ok" not in assessment["strengths"]
    assert any(item["domain"] == "rule_quality" for item in assessment["risks"])


def test_assessment_warns_when_rule_canary_source_coverage_is_thin() -> None:
    snap = _snapshot()
    snap["rule_canary"]["coverage"]["sources"]["argus"]["cases"] = 1
    snap["rule_canary"]["coverage_guardrails"]["sources"]["headroom_cases"]["argus"] = -2

    assessment = assess_snapshot(snap)

    canary_section = next(item for item in assessment["sections"] if item["name"] == "canaries")
    assert canary_section["status"] == "watch"
    assert "source_guard=thin" in canary_section["detail"]
    assert "source_headroom=argus=-2,suricata=1,syslog=22" in canary_section["detail"]
    assert "rule_canary_source_guard_ok" not in assessment["strengths"]
    assert any("argus=1/3" in item["risk"] for item in assessment["risks"] if item["domain"] == "rule_quality")


def test_assessment_surfaces_heartbeat_corroborated_agent_service_checks() -> None:
    snap = _snapshot()
    snap["agent_services"] = {
        "status": "ok_corroborated",
        "warnings": [],
        "unchecked_agents": ["host03", "host04", "host02"],
        "heartbeat_corroborated_agents": ["host03", "host04", "host02"],
        "unchecked_without_fresh_heartbeat": [],
    }

    assessment = assess_snapshot(snap)

    service_section = next(item for item in assessment["sections"] if item["name"] == "agent_service_check")
    assert service_section["status"] == "watch"
    assert "unchecked=host03,host04,host02" in service_section["detail"]
    assert "heartbeat_corroborated=host03,host04,host02" in service_section["detail"]
    assert "agent_service_check_ok" not in assessment["strengths"]
    assert any(
        item["domain"] == "agent_service" and "fresh heartbeats" in item["risk"]
        for item in assessment["risks"]
    )


def test_assessment_blocks_on_uncorroborated_agent_service_check() -> None:
    snap = _snapshot()
    snap["agent_services"] = {
        "status": "partial",
        "warnings": [],
        "unchecked_agents": ["host02"],
        "heartbeat_corroborated_agents": [],
        "unchecked_without_fresh_heartbeat": ["host02"],
    }

    assessment = assess_snapshot(snap)

    service_section = next(item for item in assessment["sections"] if item["name"] == "agent_service_check")
    assert service_section["status"] == "blocked"
    assert "uncorroborated=host02" in service_section["detail"]
    assert any(
        item["domain"] == "agent_service" and item["severity"] == "high"
        for item in assessment["risks"]
    )


def test_assessment_surfaces_public_listener_exposure() -> None:
    snap = _snapshot()
    snap["production_gate"]["warnings"].append(
        "pipeline:public_listener:8770:python:dev_or_model_port_world_bound,dev_or_model_process_world_bound"
    )
    snap["production_gate"]["action_items"].append(
        {
            "domain": "public_listener",
            "owner": "operator",
            "urgency": "high",
            "action": "Review public listener python on 0.0.0.0:8770.",
        }
    )
    snap["public_listeners"] = {
        "status": "watch",
        "warnings": ["public_listener:8770:python:dev_or_model_port_world_bound,dev_or_model_process_world_bound"],
        "unexpected": [
            {
                "port": 8770,
                "process": "python",
                "reason": "dev_or_model_port_world_bound,dev_or_model_process_world_bound",
            }
        ],
    }

    assessment = assess_snapshot(snap)

    section = next(item for item in assessment["sections"] if item["name"] == "public_listener_exposure")
    assert section["status"] == "watch"
    assert "unexpected=1" in section["detail"]
    assert any(
        item["domain"] == "public_listener" and item["severity"] == "high" and "0.0.0.0:8770" in item["risk"]
        for item in assessment["risks"]
    )
    assert any(item["domain"] == "public_listener" for item in assessment["next_slow_steps"])


def test_assessment_prefers_rule_canary_quiet_guardrails_over_recomputed_threshold() -> None:
    snap = _snapshot()
    snap["rule_canary"]["coverage"]["quiet_cases"] = 12
    snap["rule_canary"]["coverage_guardrails"]["quiet"]["headroom_cases"] = -1

    assessment = assess_snapshot(snap)

    canary_section = next(item for item in assessment["sections"] if item["name"] == "canaries")
    assert canary_section["status"] == "watch"
    assert "quiet_guard=thin" in canary_section["detail"]
    assert "quiet_headroom=-1" in canary_section["detail"]


def test_assessment_prefers_rule_canary_source_guardrails_over_recomputed_threshold() -> None:
    snap = _snapshot()
    snap["rule_canary"]["coverage"]["sources"]["suricata"]["cases"] = 3
    snap["rule_canary"]["coverage_guardrails"]["sources"]["headroom_cases"]["suricata"] = -1

    assessment = assess_snapshot(snap)

    canary_section = next(item for item in assessment["sections"] if item["name"] == "canaries")
    assert canary_section["status"] == "watch"
    assert "source_guard=thin" in canary_section["detail"]
    assert "source_headroom=argus=28,suricata=-1,syslog=22" in canary_section["detail"]


def test_assessment_reports_ready_snapshot() -> None:
    snap = _snapshot()
    snap["production_gate"] = {
        "status": "ready",
        "production_ready": True,
        "blockers": [],
        "warnings": [],
        "action_items": [],
    }
    snap["fleet"]["agents"][1]["warnings"] = []
    snap["external_sources"][0]["status"] = "ok"
    snap["alerts"]["synthetic_residue"] = {"count": 0, "percent_raw": 0, "prune_eligible_24h": 0}
    snap["agent_rollout"] = {"status": "ok"}
    snap["network"] = {"status": "ok"}

    assessment = assess_snapshot(snap)

    assert assessment["status"] == "ready"
    assert assessment["production_ready"] is True
    assert assessment["readiness_score"] == 100
    assert assessment["risks"] == [
        {
            "severity": "normal",
            "domain": "suppression_review",
            "risk": "Suppressed high-severity non-synthetic examples exist and should remain reviewable.",
        }
    ]
    assert assessment["blocker_review"] == []
    assert assessment["next_slow_steps"][0]["domain"] == "monitoring"


def test_assessment_classifies_rollout_target_access_blocker() -> None:
    snap = _snapshot()
    snap["production_gate"]["blockers"] = ["rollout:target_access:host03:ssh_publickey_denied"]
    snap["production_gate"]["warnings"] = []
    snap["production_gate"]["remediation_commands"] = [
        ".venv/bin/python tools/argus_network_egress_rollout.py --target host03 --action plan",
        ".venv/bin/python tools/shallot_production_gate.py",
    ]
    snap["production_gate"]["action_items"] = [
        {
            "domain": "agent_rollout",
            "owner": "operator",
            "urgency": "high",
            "action": "Restore SSH access before promoting network_egress on host03.",
        }
    ]
    snap["gate_watch"]["blocker_age_sec"] = {"rollout:target_access:host03:ssh_publickey_denied": 90}
    snap["gate_watch"]["warning_age_sec"] = {}
    snap["fleet"]["agents"][1]["warnings"] = []

    assessment = assess_snapshot(snap)

    item = assessment["blocker_review"][0]
    assert item["name"] == "rollout:target_access:host03:ssh_publickey_denied"
    assert item["domain"] == "agent_rollout"
    assert item["owner"] == "operator"
    assert item["urgency"] == "high"
    assert item["action"] == "Restore SSH access before promoting network_egress on host03."
    assert item["commands"] == [
        ".venv/bin/python tools/argus_network_egress_rollout.py --target host03 --action plan"
    ]
    assert any(
        risk["domain"] == "agent_rollout"
        and "rollout:target_access:host03:ssh_publickey_denied" in risk["risk"]
        for risk in assessment["risks"]
    )


def test_assessment_text_prints_blocker_review_verify_command(capsys) -> None:
    assessment = assess_snapshot(_snapshot())

    _print_text(assessment)

    out = capsys.readouterr().out
    assert "blocker review:" in out
    assert "network:expected_syslog_missing:main_gateway" in out
    assert "verify=.venv/bin/python tools/shallot_router_syslog_plan.py --probe" in out
