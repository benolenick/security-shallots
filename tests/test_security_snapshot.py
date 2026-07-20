"""Security snapshot dashboard contract tests."""

from __future__ import annotations

from datetime import datetime, timezone

from tools.shallot_security_snapshot import (
    assessment_loop_summary,
    build_snapshot,
    central_health_summary,
    expected_source_diagnostics,
    gate_watch_summary,
    noise_housekeep_summary,
    syslog_canary_summary,
)


def test_snapshot_compacts_fleet_alert_and_network_state() -> None:
    fleet = {
        "summary": {
            "status": "watch",
            "online_count": 4,
            "expected_agents": ["host01", "host03", "host04", "host02"],
            "warnings": ["disk_pressure:host03"],
            "blockers": [],
            "next_actions": ["Free disk or move data on: host03 disk=84.6% free=339.7GB mem=29.9% load/core=0.63"],
            "monitor_coverage": {
                "canary_monitors": {
                    "network_egress": {
                        "expected_agents": ["host01", "host04", "host02"],
                        "present_agents": ["host01", "host04", "host02"],
                        "promotion_eligible_agents": ["host01", "host04", "host02"],
                        "next_promotion_target": "eligible:host01,host04,host02",
                    }
                }
            },
        },
        "agents": [
            {"agent": "host01", "warnings": []},
            {
                "agent": "host03",
                "warnings": ["disk>=80%"],
                "disk_used_pct": 84.6,
                "disk_free_gb": 339.7,
                "load_per_core": 0.63,
                "mem_used_pct": 29.9,
            },
        ],
    }
    hour = {
        "raw_alerts": 0,
        "visible_non_synthetic": 0,
        "incident_candidates": [],
        "network_coverage": {
            "status": "gap",
            "gaps": ["packet_ids_disabled", "expected_syslog_missing:main_gateway"],
            "blocking_gaps": ["expected_syslog_missing:main_gateway"],
            "advisory_gaps": ["packet_ids_disabled"],
            "actions": [{"priority": "high", "action": "Configure router syslog"}],
        },
        "expected_log_sources": [
            {
                "name": "main_gateway",
                "type": "syslog",
                "status": "missing",
                "src_ips": ["192.168.0.1"],
                "hostnames": ["dlink", "covr"],
                "count_window": 0,
                "total_seen": 0,
                "warnings": ["expected_source_missing"],
                "note": "Configure router syslog.",
            }
        ],
        "readiness": {
            "status": "not_ready",
            "blockers": ["network_coverage_gap"],
            "warnings": ["source:main_gateway:expected_source_missing"],
            "strengths": ["quiet_alert_window"],
            "next_actions": ["Configure router syslog"],
        },
        "alert_rate_baseline": {
            "window": "current_hour_vs_previous_24h",
            "current": {"raw": 0, "real_raw": 0, "visible": 0},
            "previous_hourly_avg": {"raw": 68.71, "real_raw": 0.38, "visible": 0},
            "warnings": [],
        },
    }
    day = {
        "raw_alerts": 1649,
        "synthetic_or_experiment": 1400,
        "visible_non_synthetic": 0,
        "suppressed_non_synthetic": 9,
        "synthetic_residue": {
            "count": 1400,
            "percent_raw": 84.9,
            "per_day": 1400.0,
            "top_hosts": [{"host": "host03", "count": 1400, "per_day": 1400.0}],
        },
        "volume_guardrails": {
            "raw_per_hour": 68.71,
            "real_raw_per_hour": 10.38,
            "synthetic_per_hour": 58.33,
            "visible_per_hour": 0,
            "db_bytes": 4128768,
            "db_freelist_bytes": 278528,
            "db_freelist_pct": 6.75,
            "assessment_log_bytes": 174588,
            "warnings": [],
        },
        "suppression_quality": {
            "status": "ok",
            "suppressed_non_synthetic": 2,
            "suppressed_high_or_critical": 2,
            "suppressed_network_rule_hits": 0,
            "warnings": [],
            "examples": [
                {
                    "asset": "host03",
                    "source": "argus",
                    "source_ref": "session_alert",
                    "category": "lateral_movement",
                    "severity": "high",
                    "title": "Session activity detected",
                    "count": 2,
                    "first_seen": "2026-07-15T01:00:00+00:00",
                    "latest_seen": "2026-07-15T01:30:00+00:00",
                    "latest_age_hours": 7.0,
                }
            ],
        },
        "volume_by_host": [
            {
                "host": "host03",
                "raw": 1400,
                "visible": 0,
                "suppressed": 0,
                "suppressed_non_synthetic": 0,
                "synthetic_or_experiment": 1400,
                "raw_per_day": 1400.0,
                "visible_per_day": 0.0,
                "suppressed_non_synthetic_per_day": 0.0,
            },
            {
                "host": "host01",
                "raw": 249,
                "visible": 0,
                "suppressed": 9,
                "suppressed_non_synthetic": 9,
                "synthetic_or_experiment": 0,
                "raw_per_day": 249.0,
                "visible_per_day": 0.0,
                "suppressed_non_synthetic_per_day": 9.0,
            },
        ],
    }

    snap = build_snapshot(
        fleet,
        hour,
        day,
        {"status": "ok", "timer_active": True, "latest_log_age_sec": 30, "warnings": []},
        rule_canary={"status": "ok", "passed": 7, "failed": 0, "cases": []},
        syslog_canary={"status": "ok", "matched": 1, "cleaned": 1, "warnings": []},
    )

    assert snap["status"] == "watch"
    assert snap["pipeline"]["status"] == "ok"
    assert snap["pipeline"]["blockers"] == []
    assert "agents_online" in snap["pipeline"]["strengths"]
    assert "rule_canary_ok" in snap["pipeline"]["strengths"]
    assert "syslog_canary_ok" in snap["pipeline"]["strengths"]
    assert snap["fleet"]["online"] == 4
    assert snap["fleet"]["expected"] == 4
    assert snap["fleet"]["strengths"] == []
    assert snap["fleet"]["warning_agents"][0]["agent"] == "host03"
    assert snap["fleet"]["agents"][1]["agent"] == "host03"
    assert snap["fleet"]["agents"][1]["disk_used_pct"] == 84.6
    assert snap["fleet"]["agents"][1]["warnings"] == ["disk>=80%"]
    assert snap["fleet"]["next_actions"] == [
        "Free disk or move data on: host03 disk=84.6% free=339.7GB mem=29.9% load/core=0.63"
    ]
    assert snap["alerts"]["last_hour_visible"] == 0
    assert snap["alerts"]["raw_per_hour_24h"] == 68.71
    assert snap["alerts"]["real_raw_per_hour_24h"] == 10.38
    assert snap["alerts"]["synthetic_per_hour_24h"] == 58.33
    assert snap["alerts"]["last_24h_synthetic_or_experiment"] == 1400
    assert snap["alerts"]["storage"] == {
        "db_bytes": 4128768,
        "db_freelist_bytes": 278528,
        "db_freelist_pct": 6.75,
        "assessment_log_bytes": 174588,
    }
    assert snap["alerts"]["synthetic_residue"]["count"] == 1400
    assert snap["alerts"]["synthetic_residue"]["top_hosts"][0]["host"] == "host03"
    assert snap["alerts"]["suppression_review_examples"][0]["asset"] == "host03"
    assert snap["alerts"]["suppression_review_examples"][0]["source_ref"] == "session_alert"
    assert snap["alerts"]["suppression_review_examples"][0]["count"] == 2
    assert snap["alerts"]["suppression_review_examples"][0]["latest_seen"] == "2026-07-15T01:30:00+00:00"
    assert snap["alerts"]["volume_by_host_24h"][0]["host"] == "host03"
    assert snap["alerts"]["volume_by_host_24h"][0]["raw_per_day"] == 1400.0
    assert snap["alerts"]["volume_by_host_24h"][0]["real_raw"] == 0
    assert snap["alerts"]["volume_by_host_24h"][1]["real_raw"] == 249
    assert snap["alerts"]["rate_baseline"]["current"]["visible"] == 0
    assert snap["network"]["status"] == "gap"
    assert snap["network"]["blocking_gaps"] == ["expected_syslog_missing:main_gateway"]
    assert snap["network"]["advisory_gaps"] == ["packet_ids_disabled"]
    assert snap["production_gate"]["status"] == "blocked"
    assert "network:expected_syslog_missing:main_gateway" in snap["production_gate"]["blockers"]
    assert snap["self_assessment"]["status"] == "blocked"
    assert 0 < snap["self_assessment"]["readiness_score"] < 100
    assert any(
        item["name"] == "network_visibility" and item["status"] == "blocked"
        for item in snap["self_assessment"]["sections"]
    )
    assert any(item["domain"] == "network_visibility" for item in snap["self_assessment"]["risks"])
    assert snap["external_sources"][0]["name"] == "main_gateway"
    assert snap["external_sources"][0]["status"] == "missing"
    assert snap["external_sources"][0]["src_ips"] == ["192.168.0.1"]
    assert snap["external_sources"][0]["reachability"] == []
    assert snap["external_sources"][0]["diagnosis"] == "source_unreachable_or_unprobed"
    assert snap["assessment_loop"]["status"] == "ok"
    assert snap["rule_canary"]["status"] == "ok"
    assert snap["syslog_canary"]["status"] == "ok"
    assert snap["central_health"] == {}
    assert snap["noise_housekeep"] == {}
    assert snap["gate_watch"] == {}
    assert snap["readiness"]["blockers"] == ["network_coverage_gap"]
    assert snap["canaries"]["network_egress"]["next"] == "eligible:host01,host04,host02"
    assert snap["canaries"]["network_egress"]["waiting"] == []
    assert snap["canaries"]["network_egress"]["unstable"] == []
    assert snap["canaries"]["network_egress"]["missing"] == []
    assert snap["agent_rollout"]["status"] == "blocked"
    assert snap["agent_rollout"]["remaining_agents"] == ["host03"]
    assert snap["agent_rollout"]["blockers"] == ["host03:disk>=80%"]
    assert snap["agent_rollout"]["next_actions"] == [
        "Clear resource warnings before promoting network_egress on host03 disk=84.6% free=339.7GB mem=29.9% load/core=0.63: disk>=80%"
    ]
    assert snap["agent_rollout"]["canary_ready"] is True
    assert "Canary cohort is promotion-ready" in snap["agent_rollout"]["agent_side_next"]
    assert "rollout:host03:disk>=80%" in snap["production_gate"]["blockers"]


def test_snapshot_blocks_remaining_rollout_on_target_ssh_access() -> None:
    fleet = {
        "summary": {
            "status": "ready",
            "online_count": 4,
            "expected_agents": ["host01", "host03", "host04", "host02"],
            "warnings": [],
            "blockers": [],
            "monitor_coverage": {
                "canary_monitors": {
                    "network_egress": {
                        "expected_agents": ["host01", "host04", "host02"],
                        "present_agents": ["host01", "host04", "host02"],
                        "promotion_eligible_agents": ["host01", "host04", "host02"],
                        "next_promotion_target": "eligible:host01,host04,host02",
                    }
                }
            },
        },
        "agents": [
            {"agent": "host01", "warnings": []},
            {"agent": "host03", "warnings": [], "webhook_ok": True, "monitors": "anti_tamper,session"},
            {"agent": "host04", "warnings": []},
            {"agent": "host02", "warnings": []},
        ],
    }
    hour = {
        "raw_alerts": 0,
        "visible_non_synthetic": 0,
        "incident_candidates": [],
        "network_coverage": {"status": "ok", "gaps": [], "blocking_gaps": [], "advisory_gaps": []},
        "readiness": {"status": "ready", "blockers": [], "warnings": [], "strengths": []},
    }
    day = {**hour, "volume_guardrails": {"status": "ok", "warnings": []}, "synthetic_residue": {"count": 0}}

    snap = build_snapshot(
        fleet,
        hour,
        day,
        {"status": "ok"},
        rollout_access={
            "host03": {
                "status": "ssh_publickey_denied",
                "detail": "om@192.168.0.224: Permission denied (publickey).",
                "repair_commands": ["On host03 console, run: sudo bash -lc 'install key'"],
            }
        },
    )

    assert snap["agent_rollout"]["status"] == "blocked"
    assert snap["agent_rollout"]["blockers"] == ["target_access:host03:ssh_publickey_denied"]
    assert "On host03 console" in snap["agent_rollout"]["next_actions"][0]
    assert "rollout:target_access:host03:ssh_publickey_denied" in snap["production_gate"]["blockers"]
    assert ".venv/bin/python tools/argus_network_egress_rollout.py --target host03 --action plan" in snap[
        "production_gate"
    ]["remediation_commands"]


def test_snapshot_carries_central_health_into_gate() -> None:
    fleet = {
        "summary": {
            "status": "ok",
            "online_count": 1,
            "expected_agents": ["host01"],
            "monitor_coverage": {"canary_monitors": {}},
        },
        "agents": [{"agent": "host01", "warnings": []}],
    }
    hour = {
        "raw_alerts": 0,
        "visible_non_synthetic": 0,
        "incident_candidates": [],
        "network_coverage": {"status": "ok", "blocking_gaps": [], "advisory_gaps": []},
        "readiness": {"status": "ready", "blockers": [], "warnings": [], "strengths": [], "next_actions": []},
    }
    day = {"volume_guardrails": {"warnings": []}, "volume_by_host": []}

    snap = build_snapshot(
        fleet,
        hour,
        day,
        {"status": "ok", "warnings": []},
        central_health={
            "status": "fail",
            "blockers": ["central_service:inactive"],
            "warnings": [],
            "strengths": [],
        },
    )

    assert snap["central_health"]["status"] == "fail"
    assert snap["production_gate"]["status"] == "blocked"
    assert snap["production_gate"]["blockers"] == ["central:central_service:inactive"]


def test_snapshot_carries_noise_housekeep_health_into_pipeline() -> None:
    fleet = {
        "summary": {
            "status": "ok",
            "online_count": 1,
            "expected_agents": ["host01"],
            "monitor_coverage": {"canary_monitors": {}},
        },
        "agents": [{"agent": "host01", "warnings": []}],
    }
    hour = {
        "raw_alerts": 0,
        "visible_non_synthetic": 0,
        "incident_candidates": [],
        "network_coverage": {"status": "ok", "blocking_gaps": [], "advisory_gaps": []},
        "readiness": {"status": "ready", "blockers": [], "warnings": [], "strengths": [], "next_actions": []},
    }
    day = {"volume_guardrails": {"warnings": []}, "volume_by_host": []}

    snap = build_snapshot(
        fleet,
        hour,
        day,
        {"status": "ok", "warnings": []},
        noise_housekeep={"status": "ok", "warnings": [], "suppression_applied": 0},
    )

    assert snap["noise_housekeep"]["status"] == "ok"
    assert "noise_housekeep_ok" in snap["pipeline"]["strengths"]


def test_snapshot_warns_on_stale_noise_housekeep_state() -> None:
    fleet = {
        "summary": {
            "status": "ok",
            "online_count": 1,
            "expected_agents": ["host01"],
            "monitor_coverage": {"canary_monitors": {}},
        },
        "agents": [{"agent": "host01", "warnings": []}],
    }
    hour = {
        "raw_alerts": 0,
        "visible_non_synthetic": 0,
        "incident_candidates": [],
        "network_coverage": {"status": "ok", "blocking_gaps": [], "advisory_gaps": []},
        "readiness": {"status": "ready", "blockers": [], "warnings": [], "strengths": [], "next_actions": []},
    }
    day = {"volume_guardrails": {"warnings": []}, "volume_by_host": []}

    snap = build_snapshot(
        fleet,
        hour,
        day,
        {"status": "ok", "warnings": []},
        noise_housekeep={"status": "warn", "warnings": ["noise_housekeep_stale"]},
    )

    assert "noise_housekeep_stale" in snap["pipeline"]["warnings"]


def test_noise_housekeep_summary_reads_state(tmp_path) -> None:
    state = tmp_path / "NOISE_HOUSEKEEP_STATE.json"
    state.write_text(
        '{"status":"ok","run_at":"2026-07-15T11:30:00+00:00","synthetic_prune":{"matched":0}}'
    )

    summary = noise_housekeep_summary(state_path=str(state))

    assert summary["status"] in {"ok", "warn"}
    assert summary["synthetic_prune"]["matched"] == 0


def test_central_health_summary_uses_ops_sanity_checks(monkeypatch, tmp_path) -> None:
    class ServiceCheck:
        name = "central_service"
        status = "ok"
        detail = "active"

    class ApiCheck:
        name = "central_api_health"
        status = "fail"
        detail = "status=degraded"

    monkeypatch.setattr("tools.shallot_security_snapshot._check_shallotd_service_active", lambda root: ServiceCheck())
    monkeypatch.setattr("tools.shallot_security_snapshot._check_central_api_health", lambda root, config: ApiCheck())

    summary = central_health_summary(root=tmp_path, config="config.yaml")

    assert summary["status"] == "fail"
    assert summary["blockers"] == ["central_api_health:status=degraded"]


def test_snapshot_carries_fleet_strengths_into_gate() -> None:
    fleet = {
        "summary": {
            "status": "ok",
            "online_count": 1,
            "expected_agents": ["host01"],
            "warnings": [],
            "blockers": [],
            "strengths": ["expected_agents_reporting", "heartbeats_current", "webhooks_healthy"],
            "monitor_coverage": {"canary_monitors": {}},
        },
        "agents": [{"agent": "host01", "warnings": []}],
    }
    hour = {
        "raw_alerts": 0,
        "visible_non_synthetic": 0,
        "incident_candidates": [],
        "network_coverage": {"status": "ok", "gaps": [], "actions": []},
        "readiness": {"status": "ready", "blockers": [], "warnings": [], "strengths": [], "next_actions": []},
    }
    day = {
        "raw_alerts": 0,
        "visible_non_synthetic": 0,
        "suppressed_non_synthetic": 0,
        "volume_guardrails": {"raw_per_hour": 0, "visible_per_hour": 0, "warnings": []},
    }

    snap = build_snapshot(fleet, hour, day, {"status": "ok"}, rule_canary={"status": "ok"})

    assert snap["fleet"]["strengths"] == ["expected_agents_reporting", "heartbeats_current", "webhooks_healthy"]
    assert "fleet:heartbeats_current" in snap["production_gate"]["strengths"]
    assert "fleet:webhooks_healthy" in snap["production_gate"]["strengths"]


def test_snapshot_drops_transient_network_idle_advisories_when_day_has_activity() -> None:
    fleet = {
        "summary": {
            "status": "ok",
            "online_count": 1,
            "expected_agents": ["host01"],
            "warnings": [],
            "blockers": [],
            "monitor_coverage": {"canary_monitors": {}},
        },
        "agents": [{"agent": "host01", "warnings": []}],
    }
    hour = {
        "raw_alerts": 0,
        "visible_non_synthetic": 0,
        "incident_candidates": [],
        "network_coverage": {
            "status": "gap",
            "gaps": [
                "packet_ids_disabled",
                "syslog_idle_in_window",
                "no_network_source_events_in_window",
                "expected_syslog_missing:main_gateway",
            ],
            "blocking_gaps": ["expected_syslog_missing:main_gateway"],
            "advisory_gaps": [
                "packet_ids_disabled",
                "syslog_idle_in_window",
                "no_network_source_events_in_window",
            ],
            "actions": [],
        },
        "readiness": {
            "status": "not_ready",
            "blockers": ["network_coverage_gap"],
            "warnings": [],
            "strengths": [],
            "next_actions": [],
        },
    }
    day = {
        "raw_alerts": 1,
        "visible_non_synthetic": 0,
        "suppressed_non_synthetic": 0,
        "volume_guardrails": {"raw_per_hour": 0.04, "visible_per_hour": 0, "warnings": []},
        "network_coverage": {
            "status": "gap",
            "active_sources_window": ["syslog"],
            "gaps": ["packet_ids_disabled", "expected_syslog_missing:main_gateway"],
            "blocking_gaps": ["expected_syslog_missing:main_gateway"],
            "advisory_gaps": ["packet_ids_disabled"],
        },
    }

    snap = build_snapshot(fleet, hour, day, {"status": "ok"})

    assert snap["network"]["blocking_gaps"] == ["expected_syslog_missing:main_gateway"]
    assert snap["network"]["advisory_gaps"] == ["packet_ids_disabled"]
    assert snap["network"]["active_sources_window_24h"] == ["syslog"]
    assert "network_advisory:syslog_idle_in_window" not in snap["production_gate"]["warnings"]
    assert "network_advisory:no_network_source_events_in_window" not in snap["production_gate"]["warnings"]


def test_snapshot_canary_summary_exposes_waiting_unstable_and_missing_agents() -> None:
    fleet = {
        "summary": {
            "status": "ok",
            "online_count": 3,
            "expected_agents": ["host01", "host04", "host02"],
            "warnings": [],
            "blockers": [],
            "monitor_coverage": {
                "canary_monitors": {
                    "network_egress": {
                        "expected_agents": ["host01", "host04", "host02"],
                        "present_agents": ["host01", "host04"],
                        "promotion_eligible_agents": ["host04"],
                        "next_promotion_target": "wait:host01:needs_2_more_clean_events",
                        "agents": {
                            "host01": {
                                "present": True,
                                "stable": True,
                                "promotion_eligible": False,
                                "events_remaining": 2,
                                "estimated_seconds_remaining": 300,
                                "estimated_minutes_remaining": 5.0,
                                "promotion_reason": "needs_10_clean_events",
                            },
                            "host04": {
                                "present": True,
                                "stable": False,
                                "promotion_eligible": True,
                                "events_remaining": 0,
                                "promotion_reason": "eligible",
                            },
                            "host02": {
                                "present": False,
                                "stable": False,
                                "promotion_eligible": False,
                                "events_remaining": 10,
                                "promotion_reason": "not_stable",
                            },
                        },
                    }
                }
            },
        },
        "agents": [{"agent": "host01", "warnings": []}],
    }
    hour = {
        "raw_alerts": 0,
        "visible_non_synthetic": 0,
        "incident_candidates": [],
        "network_coverage": {"status": "ok", "gaps": [], "actions": []},
        "readiness": {"status": "ready", "blockers": [], "warnings": [], "strengths": [], "next_actions": []},
    }
    day = {
        "raw_alerts": 0,
        "visible_non_synthetic": 0,
        "suppressed_non_synthetic": 0,
        "volume_guardrails": {"raw_per_hour": 0, "visible_per_hour": 0, "warnings": []},
    }

    snap = build_snapshot(fleet, hour, day, {"status": "ok"})

    canary = snap["canaries"]["network_egress"]
    assert canary["waiting"] == [
        {
            "agent": "host01",
            "events_remaining": 2,
            "estimated_seconds_remaining": 300,
            "estimated_minutes_remaining": 5.0,
            "reason": "needs_10_clean_events",
        }
    ]
    assert canary["unstable"] == ["host04"]
    assert canary["missing"] == ["host02"]


def test_snapshot_carries_agent_service_warnings_into_gate() -> None:
    fleet = {
        "summary": {
            "status": "ok",
            "online_count": 1,
            "expected_agents": ["host04"],
            "warnings": [],
            "blockers": [],
            "monitor_coverage": {"canary_monitors": {}},
        },
        "agents": [{"agent": "host04", "warnings": []}],
    }
    hour = {
        "raw_alerts": 0,
        "visible_non_synthetic": 0,
        "incident_candidates": [],
        "network_coverage": {"status": "ok", "gaps": [], "actions": []},
        "readiness": {"status": "ready", "blockers": [], "warnings": [], "strengths": [], "next_actions": []},
    }
    day = {
        "raw_alerts": 0,
        "visible_non_synthetic": 0,
        "suppressed_non_synthetic": 0,
        "volume_guardrails": {"raw_per_hour": 0, "visible_per_hour": 0, "warnings": []},
    }

    snap = build_snapshot(
        fleet,
        hour,
        day,
        {"status": "ok"},
        agent_services={"status": "warn", "warnings": ["host04:argus_service_inactive_process_running"]},
    )

    assert snap["pipeline"]["status"] == "watch"
    assert "agent_service:host04:argus_service_inactive_process_running" in snap["pipeline"]["warnings"]
    assert "pipeline:agent_service:host04:argus_service_inactive_process_running" in snap["production_gate"]["warnings"]


def test_snapshot_carries_public_listener_warnings_into_gate() -> None:
    fleet = {
        "summary": {
            "status": "ok",
            "online_count": 1,
            "expected_agents": ["host01"],
            "warnings": [],
            "blockers": [],
            "monitor_coverage": {"canary_monitors": {}},
        },
        "agents": [{"agent": "host01", "warnings": []}],
    }
    hour = {
        "raw_alerts": 0,
        "visible_non_synthetic": 0,
        "incident_candidates": [],
        "network_coverage": {"status": "ok", "gaps": [], "actions": []},
        "readiness": {"status": "ready", "blockers": [], "warnings": [], "strengths": [], "next_actions": []},
    }
    day = {
        "raw_alerts": 0,
        "visible_non_synthetic": 0,
        "suppressed_non_synthetic": 0,
        "volume_guardrails": {"raw_per_hour": 0, "visible_per_hour": 0, "warnings": []},
    }

    snap = build_snapshot(
        fleet,
        hour,
        day,
        {"status": "ok"},
        public_listeners={
            "status": "watch",
            "warnings": ["public_listener:11434:ollama:dev_or_model_port_world_bound"],
            "unexpected": [
                {
                    "port": 11434,
                    "service": "ollama",
                    "reason": "dev_or_model_port_world_bound",
                    "active_clients": ["192.168.0.212", "192.168.0.224"],
                    "action": (
                        "Review Ollama LAN exposure. If remote clients still need it, restrict 11434 to approved LAN clients "
                        "or put it behind an authenticated proxy; otherwise bind OLLAMA_HOST to 127.0.0.1:11434."
                    ),
                }
            ],
        },
    )

    assert snap["pipeline"]["status"] == "watch"
    assert "public_listener:11434:ollama:dev_or_model_port_world_bound" in snap["pipeline"]["warnings"]
    assert "pipeline:public_listener:11434:ollama:dev_or_model_port_world_bound" in snap["production_gate"]["warnings"]
    assert ".venv/bin/python tools/shallot_public_listener_audit.py --json" in snap["production_gate"]["remediation_commands"]
    assert any(item["domain"] == "public_listener" for item in snap["production_gate"]["action_items"])
    assert any(
        "authenticated proxy" in action and "active clients=192.168.0.212,192.168.0.224" in action
        for action in snap["production_gate"]["next_actions"]
    )


def test_snapshot_carries_gate_watch_context_without_changing_gate() -> None:
    fleet = {
        "summary": {
            "status": "ok",
            "online_count": 1,
            "expected_agents": ["host01"],
            "warnings": [],
            "blockers": [],
            "monitor_coverage": {"canary_monitors": {}},
        },
        "agents": [{"agent": "host01", "warnings": []}],
    }
    hour = {
        "raw_alerts": 0,
        "visible_non_synthetic": 0,
        "incident_candidates": [],
        "network_coverage": {"status": "ok", "gaps": [], "actions": []},
        "readiness": {"status": "ready", "blockers": [], "warnings": [], "strengths": [], "next_actions": []},
    }
    day = {
        "raw_alerts": 0,
        "visible_non_synthetic": 0,
        "suppressed_non_synthetic": 0,
        "volume_guardrails": {"raw_per_hour": 0, "visible_per_hour": 0, "warnings": []},
    }

    snap = build_snapshot(
        fleet,
        hour,
        day,
        {"status": "ok"},
        gate_watch={"status": "new_blockers", "new_blockers": ["network:new"], "warnings": ["gate_watch_new_blockers"]},
    )

    assert snap["gate_watch"]["status"] == "new_blockers"
    assert snap["gate_watch"]["new_blockers"] == ["network:new"]
    assert "gate_watch_new_blockers" not in snap["production_gate"]["warnings"]


def test_gate_watch_summary_reads_state_file(tmp_path) -> None:
    state = tmp_path / "watch.json"
    state.write_text('{"status":"stable","new_blockers":[],"stable_blockers":["b"]}')

    summary = gate_watch_summary(state_path=str(state))

    assert summary["status"] == "stable"
    assert summary["stable_blockers"] == ["b"]
    assert summary["warnings"] == []


def test_gate_watch_summary_warns_on_new_blockers(tmp_path) -> None:
    state = tmp_path / "watch.json"
    state.write_text('{"status":"new_blockers","new_blockers":["b"]}')

    summary = gate_watch_summary(state_path=str(state))

    assert summary["status"] == "new_blockers"
    assert summary["warnings"] == ["gate_watch_new_blockers"]


def test_snapshot_pipeline_warns_on_single_syslog_canary_failure() -> None:
    fleet = {
        "summary": {
            "status": "ok",
            "online_count": 1,
            "expected_agents": ["host01"],
            "warnings": [],
            "blockers": [],
            "monitor_coverage": {"canary_monitors": {}},
        },
        "agents": [{"agent": "host01", "warnings": []}],
    }
    hour = {
        "raw_alerts": 0,
        "visible_non_synthetic": 0,
        "incident_candidates": [],
        "network_coverage": {"status": "ok", "gaps": [], "actions": []},
        "readiness": {"status": "ready", "blockers": [], "warnings": [], "strengths": [], "next_actions": []},
    }
    day = {
        "raw_alerts": 0,
        "visible_non_synthetic": 0,
        "suppressed_non_synthetic": 0,
        "volume_guardrails": {"raw_per_hour": 0, "visible_per_hour": 0, "warnings": []},
    }

    snap = build_snapshot(
        fleet,
        hour,
        day,
        {"status": "ok"},
        syslog_canary={
            "status": "warn",
            "raw_status": "fail",
            "matched": 0,
            "consecutive_failures": 1,
            "warnings": ["syslog_canary_transient_failure"],
        },
    )

    assert snap["pipeline"]["status"] == "watch"
    assert snap["pipeline"]["blockers"] == []
    assert "syslog_canary_transient_failure" in snap["pipeline"]["warnings"]
    assert "pipeline:syslog_canary_transient_failure" in snap["production_gate"]["warnings"]


def test_snapshot_pipeline_blocks_on_repeated_syslog_canary_failure() -> None:
    fleet = {
        "summary": {
            "status": "ok",
            "online_count": 1,
            "expected_agents": ["host01"],
            "warnings": [],
            "blockers": [],
            "monitor_coverage": {"canary_monitors": {}},
        },
        "agents": [{"agent": "host01", "warnings": []}],
    }
    hour = {
        "raw_alerts": 0,
        "visible_non_synthetic": 0,
        "incident_candidates": [],
        "network_coverage": {"status": "ok", "gaps": [], "actions": []},
        "readiness": {"status": "ready", "blockers": [], "warnings": [], "strengths": [], "next_actions": []},
    }
    day = {
        "raw_alerts": 0,
        "visible_non_synthetic": 0,
        "suppressed_non_synthetic": 0,
        "volume_guardrails": {"raw_per_hour": 0, "visible_per_hour": 0, "warnings": []},
    }

    snap = build_snapshot(
        fleet,
        hour,
        day,
        {"status": "ok"},
        syslog_canary={"status": "fail", "matched": 0, "consecutive_failures": 2, "warnings": ["syslog_canary_failed"]},
    )

    assert snap["pipeline"]["status"] == "blocked"
    assert "syslog_canary_failed" in snap["pipeline"]["blockers"]
    assert "pipeline:syslog_canary_failed" in snap["production_gate"]["blockers"]


def test_snapshot_pipeline_blocks_on_incident_candidates() -> None:
    fleet = {
        "summary": {
            "status": "ok",
            "online_count": 1,
            "expected_agents": ["host01"],
            "warnings": [],
            "blockers": [],
            "monitor_coverage": {"canary_monitors": {}},
        },
        "agents": [{"agent": "host01", "warnings": []}],
    }
    hour = {
        "raw_alerts": 1,
        "visible_non_synthetic": 1,
        "incident_candidates": [{"title": "Known bad egress"}],
        "network_coverage": {"status": "ok", "gaps": [], "actions": []},
        "readiness": {"status": "watch", "blockers": [], "warnings": [], "strengths": [], "next_actions": []},
    }
    day = {
        "raw_alerts": 1,
        "visible_non_synthetic": 1,
        "suppressed_non_synthetic": 0,
        "volume_guardrails": {"raw_per_hour": 0.04, "visible_per_hour": 0.04, "warnings": []},
    }

    snap = build_snapshot(fleet, hour, day, {"status": "ok"})

    assert snap["pipeline"]["status"] == "blocked"
    assert "incident_candidates_present" in snap["pipeline"]["blockers"]


def test_snapshot_pipeline_blocks_on_rule_canary_failure() -> None:
    fleet = {
        "summary": {
            "status": "ok",
            "online_count": 1,
            "expected_agents": ["host01"],
            "warnings": [],
            "blockers": [],
            "monitor_coverage": {"canary_monitors": {}},
        },
        "agents": [{"agent": "host01", "warnings": []}],
    }
    hour = {
        "raw_alerts": 0,
        "visible_non_synthetic": 0,
        "incident_candidates": [],
        "network_coverage": {"status": "ok", "gaps": [], "actions": []},
        "readiness": {"status": "ready", "blockers": [], "warnings": [], "strengths": [], "next_actions": []},
    }
    day = {
        "raw_alerts": 0,
        "visible_non_synthetic": 0,
        "suppressed_non_synthetic": 0,
        "volume_guardrails": {"raw_per_hour": 0, "visible_per_hour": 0, "warnings": []},
    }

    snap = build_snapshot(
        fleet,
        hour,
        day,
        {"status": "ok"},
        rule_canary={"status": "fail", "passed": 6, "failed": 1, "cases": []},
    )

    assert snap["pipeline"]["status"] == "blocked"
    assert "rule_canary_failed" in snap["pipeline"]["blockers"]
    assert "pipeline:rule_canary_failed" in snap["production_gate"]["blockers"]


def test_assessment_loop_summary_reads_latest_log_timestamp(tmp_path, monkeypatch) -> None:
    log = tmp_path / "assessment.md"
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    log.write_text(f"old\n## 2026-01-01T00:00:00Z\nbody\n## {now}\n")

    class Completed:
        stdout = "active\n"

    monkeypatch.setattr("tools.shallot_security_snapshot.subprocess.run", lambda *a, **k: Completed())

    summary = assessment_loop_summary(log_path=str(log))

    assert summary["status"] == "ok"
    assert summary["timer_active"] is True
    assert summary["latest_log_age_sec"] is not None
    assert summary["latest_log_age_sec"] < 60


def test_syslog_canary_summary_reads_state(tmp_path) -> None:
    state = tmp_path / "syslog.json"
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    state.write_text('{"status":"ok","sent_at":"' + now + '","matched":1,"cleaned":1}')

    summary = syslog_canary_summary(state_path=str(state))

    assert summary["status"] == "ok"
    assert summary["matched"] == 1
    assert summary["warnings"] == []


def test_syslog_canary_summary_debounces_single_failure(tmp_path) -> None:
    state = tmp_path / "syslog.json"
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    state.write_text(
        '{"status":"fail","sent_at":"' + now + '","matched":0,"consecutive_failures":1}'
    )

    summary = syslog_canary_summary(state_path=str(state))

    assert summary["raw_status"] == "fail"
    assert summary["status"] == "warn"
    assert summary["warnings"] == ["syslog_canary_transient_failure"]


def test_syslog_canary_summary_blocks_repeated_failure(tmp_path) -> None:
    state = tmp_path / "syslog.json"
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    state.write_text(
        '{"status":"fail","sent_at":"' + now + '","matched":0,"consecutive_failures":2}'
    )

    summary = syslog_canary_summary(state_path=str(state))

    assert summary["raw_status"] == "fail"
    assert summary["status"] == "fail"
    assert summary["warnings"] == ["syslog_canary_failed"]


def test_expected_source_diagnosis_marks_reachable_ui_missing_syslog(monkeypatch) -> None:
    monkeypatch.setattr("tools.shallot_security_snapshot._tcp_open", lambda host, port: True)
    monkeypatch.setattr(
        "tools.shallot_security_snapshot._route_to",
        lambda host: f"{host} dev eth0 src 192.168.0.172",
    )
    monkeypatch.setattr(
        "tools.shallot_security_snapshot._router_fingerprint",
        lambda host, probe: {
            "title": "D-LINK",
            "template_version": "",
            "server": "",
            "cert_subject": "C = TW, O = D-Link Corporation",
        },
    )

    diagnostics = expected_source_diagnostics(
        [
            {
                "name": "main_gateway",
                "type": "syslog",
                "status": "missing",
                "src_ips": ["192.168.0.1"],
                "hostnames": ["dlink"],
            }
        ],
        probe=True,
    )

    assert diagnostics[0]["diagnosis"] == "management_ui_reachable_syslog_not_forwarding"
    assert "192.168.0.172:514" in diagnostics[0]["next_step"]
    assert diagnostics[0]["fingerprints"]["192.168.0.1"]["title"] == "D-LINK"
    assert "D-Link Corporation" in diagnostics[0]["fingerprints"]["192.168.0.1"]["cert_subject"]
