"""Fleet health summary tests."""

from __future__ import annotations

from tools.shallot_fleet_top import compact_fleet_status, fleet_health_summary, fleet_monitor_coverage


def _agent(
    name: str,
    *,
    state: str = "ARMED_HOME",
    warnings: list[str] | None = None,
    monitors: str = "anti_tamper,session",
    age_sec: int = 30,
    webhook_ok: bool = True,
    non_heartbeat_events: int = 0,
    event_age_sec: int | None = None,
    last_event_type: str = "",
    events_emitted: int = 10,
    disk_used_pct: float | str = "",
    disk_free_gb: float | str = "",
    mem_used_pct: float | str = "",
    load_per_core: float | str = "",
) -> dict:
    return {
        "agent": name,
        "state": state,
        "warnings": warnings or [],
        "monitors": monitors,
        "age_sec": age_sec,
        "webhook_ok": webhook_ok,
        "webhook_status": 200 if webhook_ok else 0,
        "events_emitted": events_emitted,
        "non_heartbeat_events": non_heartbeat_events,
        "last_event_type": last_event_type,
        "event_age_sec": event_age_sec,
        "disk_used_pct": disk_used_pct,
        "disk_free_gb": disk_free_gb,
        "mem_used_pct": mem_used_pct,
        "load_per_core": load_per_core,
    }


def test_fleet_health_summary_ready_when_expected_agents_report_cleanly() -> None:
    summary = fleet_health_summary(
        [
            _agent("host01", monitors="anti_tamper,network_egress,session"),
            _agent("host03", monitors="anti_tamper,network_egress,session"),
            _agent("host04", monitors="anti_tamper,network_egress,session"),
            _agent("host02", monitors="anti_tamper,network_egress,session"),
        ]
    )

    assert summary["status"] == "ready"
    assert summary["blockers"] == []
    assert "expected_agents_reporting" in summary["strengths"]
    assert "heartbeats_current" in summary["strengths"]


def test_fleet_health_summary_blocks_on_missing_expected_agent() -> None:
    summary = fleet_health_summary(
        [
            _agent("host01"),
            _agent("host03"),
            _agent("host02"),
        ]
    )

    assert summary["status"] == "not_ready"
    assert "expected_agents_missing" in summary["blockers"]
    assert summary["missing_agents"] == ["host04"]
    assert any("host04" in action for action in summary["next_actions"])


def test_fleet_health_summary_watches_disk_pressure() -> None:
    summary = fleet_health_summary(
        [
            _agent("host01", monitors="anti_tamper,network_egress,session"),
            _agent("host03", warnings=["disk>=80%"], disk_used_pct=84.3, disk_free_gb=350.9, load_per_core=0.58),
            _agent("host04", monitors="anti_tamper,network_egress,session"),
            _agent("host02", monitors="anti_tamper,network_egress,session"),
        ]
    )

    assert summary["status"] == "watch"
    assert "disk_pressure:host03" in summary["warnings"]
    assert summary["warning_agents"] == ["host03"]
    assert "host03 disk=84.3% free=350.9GB load/core=0.58" in summary["next_actions"][0]


def test_fleet_health_summary_resource_next_actions_include_memory_and_load_values() -> None:
    summary = fleet_health_summary(
        [
            _agent("host01", monitors="anti_tamper,network_egress,session"),
            _agent("host03", warnings=["mem>=90%", "load/core>=1.5"], mem_used_pct=91.2, load_per_core=1.9),
            _agent("host04", monitors="anti_tamper,network_egress,session"),
            _agent("host02", monitors="anti_tamper,network_egress,session"),
        ]
    )

    assert "memory_pressure:host03" in summary["warnings"]
    assert "load_pressure:host03" in summary["warnings"]
    assert any("host03 mem=91.2% load/core=1.9" in action for action in summary["next_actions"])


def test_fleet_health_summary_load_warning_includes_top_cpu_diagnostic() -> None:
    summary = fleet_health_summary(
        [
            _agent(
                "host01",
                monitors="anti_tamper,network_egress,session",
                warnings=["load/core>=1.5"],
                load_per_core=1.9,
            ),
            _agent("host03"),
            _agent("host04", monitors="anti_tamper,network_egress,session"),
            _agent("host02", monitors="anti_tamper,network_egress,session"),
        ],
        resource_diagnostics={
            "host01": {
                "top_cpu_processes": [
                    {"pid": 123, "command": "llama-server", "cpu_pct": 309.2, "args": "llama-server"},
                    {"pid": 456, "command": "ffmpeg", "cpu_pct": 79.4, "args": "ffmpeg"},
                ],
            }
        },
    )

    assert summary["resource_diagnostics"]["host01"]["top_cpu_processes"][0]["command"] == "llama-server"
    assert any("host01 top_cpu=llama-server:309.2%, ffmpeg:79.4%" in action for action in summary["next_actions"])


def test_compact_fleet_status_keeps_operator_fields_without_full_canary_agents() -> None:
    rows = [
        _agent("host01", monitors="anti_tamper,network_egress,session"),
        _agent("host03", warnings=["disk>=80%"], disk_used_pct=84.3, disk_free_gb=350.9),
        _agent("host04", monitors="anti_tamper,network_egress,session"),
        _agent("host02", monitors="anti_tamper,network_egress,session"),
    ]
    summary = fleet_health_summary(rows)

    compact = compact_fleet_status(summary, rows)

    assert compact["status"] == "watch"
    assert "disk_pressure:host03" in compact["warnings"]
    assert "host03:canary_monitors_missing:network_egress" in compact["warnings"]
    assert compact["resource_diagnostics"] == {}
    assert compact["agents"][1] == {
        "agent": "host03",
        "state": "ARMED_HOME",
        "age_sec": 30,
        "ip": None,
        "webhook_ok": True,
        "load_per_core": "",
        "mem_used_pct": "",
        "disk_used_pct": 84.3,
        "disk_free_gb": 350.9,
        "events_emitted": 10,
        "non_heartbeat_events": 0,
        "monitors": "anti_tamper,session",
        "warnings": ["disk>=80%"],
    }
    canary = compact["monitor_coverage"]["canary_monitors"]["network_egress"]
    assert canary["promotion_eligible_agents"] == ["host01", "host04", "host02"]
    assert canary["estimated_event_seconds"] == 180
    assert canary["waiting_agents"] == []
    assert "agents" not in canary
    assert "per_agent" not in compact["monitor_coverage"]


def test_fleet_health_summary_blocks_on_offline_or_webhook_failure() -> None:
    summary = fleet_health_summary(
        [
            _agent("host01", monitors="anti_tamper,network_egress,session"),
            _agent("host03", state="OFFLINE", warnings=["offline"]),
            _agent("host04", monitors="anti_tamper,network_egress,session", warnings=["webhook_failed"]),
            _agent("host02", monitors="anti_tamper,network_egress,session"),
        ]
    )

    assert summary["status"] == "not_ready"
    assert "agents_offline" in summary["blockers"]
    assert "agent_webhook_failed" in summary["blockers"]


def test_monitor_coverage_tracks_network_egress_canary_on_host01() -> None:
    coverage = fleet_monitor_coverage(
        [
            _agent("host01", monitors="anti_tamper,network_egress,session"),
            _agent("host03", monitors="anti_tamper,network_egress,session"),
            _agent("host04", monitors="anti_tamper,network_egress,session"),
            _agent("host02", monitors="anti_tamper,network_egress,session"),
        ]
    )

    assert coverage["status"] == "ok"
    assert coverage["canary_monitors"]["network_egress"]["expected_agents"] == ["host01", "host03", "host04", "host02"]
    assert coverage["canary_monitors"]["network_egress"]["present_agents"] == ["host01", "host03", "host04", "host02"]
    assert coverage["canary_monitors"]["network_egress"]["stable_agents"] == ["host01", "host03", "host04", "host02"]
    assert coverage["canary_monitors"]["network_egress"]["promotion_eligible_agents"] == ["host01", "host03", "host04", "host02"]
    assert coverage["canary_monitors"]["network_egress"]["next_promotion_target"] == "eligible:host01,host03,host04,host02"
    assert coverage["canary_monitors"]["network_egress"]["estimated_seconds_remaining"] == 0
    assert coverage["canary_monitors"]["network_egress"]["waiting_agents"] == []
    assert coverage["canary_monitors"]["network_egress"]["agents"]["host01"]["stable"] is True
    assert coverage["canary_monitors"]["network_egress"]["agents"]["host01"]["promotion_eligible"] is True
    assert coverage["canary_monitors"]["network_egress"]["agents"]["host01"]["events_remaining"] == 0
    assert coverage["canary_monitors"]["network_egress"]["agents"]["host03"]["stable"] is True
    assert coverage["canary_monitors"]["network_egress"]["agents"]["host04"]["stable"] is True
    assert coverage["canary_monitors"]["network_egress"]["agents"]["host02"]["stable"] is True


def test_monitor_coverage_blocks_when_required_monitor_missing() -> None:
    coverage = fleet_monitor_coverage(
        [
            _agent("host01", monitors="anti_tamper,network_egress,session"),
            _agent("host03", monitors="anti_tamper"),
            _agent("host04"),
            _agent("host02", monitors="anti_tamper,network_egress,session"),
        ]
    )

    assert coverage["status"] == "gap"
    assert "host03:required_monitors_missing:session" in coverage["blockers"]


def test_monitor_coverage_watches_when_canary_missing() -> None:
    coverage = fleet_monitor_coverage(
        [
            _agent("host01"),
            _agent("host03"),
            _agent("host04"),
            _agent("host02"),
        ]
    )

    assert coverage["status"] == "watch"
    assert "host01:canary_monitors_missing:network_egress" in coverage["warnings"]
    assert "host03:canary_monitors_missing:network_egress" in coverage["warnings"]
    assert "host04:canary_monitors_missing:network_egress" in coverage["warnings"]
    assert "host02:canary_monitors_missing:network_egress" in coverage["warnings"]
    assert coverage["canary_monitors"]["network_egress"]["next_promotion_target"] == (
        "enable_or_rollback_canary:host01,host03,host04,host02"
    )


def test_monitor_coverage_canary_present_but_unstable_after_signal() -> None:
    coverage = fleet_monitor_coverage(
        [
            _agent(
                "host01",
                monitors="anti_tamper,network_egress,session",
                non_heartbeat_events=1,
                last_event_type="network_egress_suspicious",
            ),
            _agent("host03"),
            _agent("host04", monitors="anti_tamper,network_egress,session"),
            _agent("host02", monitors="anti_tamper,network_egress,session"),
        ]
    )

    canary = coverage["canary_monitors"]["network_egress"]
    assert canary["present_agents"] == ["host01", "host04", "host02"]
    assert canary["stable_agents"] == ["host04", "host02"]
    assert canary["promotion_eligible_agents"] == ["host04", "host02"]
    assert canary["agents"]["host01"]["stable"] is False


def test_monitor_coverage_ignores_unrelated_events_for_network_egress_canary() -> None:
    coverage = fleet_monitor_coverage(
        [
            _agent(
                "host01",
                monitors="anti_tamper,network_egress,session",
                non_heartbeat_events=1,
                event_age_sec=60,
                last_event_type="file_sentinel",
            ),
            _agent("host03", monitors="anti_tamper,network_egress,session"),
            _agent("host04", monitors="anti_tamper,network_egress,session"),
            _agent("host02", monitors="anti_tamper,network_egress,session"),
        ]
    )

    canary = coverage["canary_monitors"]["network_egress"]
    assert canary["agents"]["host01"]["stable"] is True
    assert canary["agents"]["host01"]["promotion_eligible"] is True


def test_monitor_coverage_canary_recovers_after_quiet_signal_window() -> None:
    coverage = fleet_monitor_coverage(
        [
            _agent(
                "host01",
                monitors="anti_tamper,network_egress,session",
                non_heartbeat_events=1,
                event_age_sec=3700,
                last_event_type="network_egress_suspicious",
            ),
            _agent("host03", monitors="anti_tamper,network_egress,session"),
            _agent("host04", monitors="anti_tamper,network_egress,session"),
            _agent("host02", monitors="anti_tamper,network_egress,session"),
        ]
    )

    canary = coverage["canary_monitors"]["network_egress"]
    assert canary["agents"]["host01"]["stable"] is True
    assert canary["agents"]["host01"]["promotion_eligible"] is True


def test_monitor_coverage_canary_stable_but_not_promotion_eligible_yet() -> None:
    coverage = fleet_monitor_coverage(
        [
            _agent("host01", monitors="anti_tamper,network_egress,session", events_emitted=3),
            _agent("host03", monitors="anti_tamper,network_egress,session", events_emitted=3),
            _agent("host04", monitors="anti_tamper,network_egress,session", events_emitted=3),
            _agent("host02", monitors="anti_tamper,network_egress,session", events_emitted=3),
        ]
    )

    canary = coverage["canary_monitors"]["network_egress"]
    assert canary["stable_agents"] == ["host01", "host03", "host04", "host02"]
    assert canary["promotion_eligible_agents"] == []
    assert canary["agents"]["host01"]["promotion_reason"] == "needs_10_clean_events"
    assert canary["agents"]["host01"]["events_remaining"] == 7
    assert canary["agents"]["host01"]["estimated_seconds_remaining"] == 1230
    assert canary["agents"]["host01"]["estimated_minutes_remaining"] == 20.5
    assert canary["waiting_agents"][0] == {
        "agent": "host01",
        "events_remaining": 7,
        "estimated_seconds_remaining": 1230,
        "estimated_minutes_remaining": 20.5,
        "reason": "needs_10_clean_events",
    }
    assert canary["next_promotion_target"] == "wait:host01:needs_7_more_clean_events"


def test_monitor_coverage_blocks_next_promotion_until_second_canary_reports() -> None:
    coverage = fleet_monitor_coverage(
        [
            _agent("host01", monitors="anti_tamper,network_egress,session", events_emitted=12),
            _agent("host03"),
            _agent("host04", monitors="anti_tamper,network_egress,session", events_emitted=12),
            _agent("host02"),
        ]
    )

    canary = coverage["canary_monitors"]["network_egress"]
    assert canary["promotion_eligible_agents"] == ["host01", "host04"]
    assert canary["next_promotion_target"] == "enable_or_rollback_canary:host03,host02"
