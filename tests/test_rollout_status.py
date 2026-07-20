"""Rollout status gate tests."""

from __future__ import annotations

from datetime import datetime, timezone

import json

from tools import shallot_rollout_status
from tools.shallot_rollout_status import build_rollout_status, execute_rollback_commands, rollback_commands_for_state


NOW = datetime(2026, 7, 19, 0, 0, 0, tzinfo=timezone.utc)


def _state(started_at: str = "2026-07-18T22:08:00+00:00") -> dict:
    return {
        "active_component": "argus_network_egress",
        "next_component": "inventory_daemon",
        "soak_started_at": started_at,
        "soak_hours": 24,
    }


def _gate(blockers: list[str] | None = None, warnings: list[str] | None = None) -> dict:
    return {"status": "ready_with_warnings", "blockers": blockers or [], "warnings": warnings or []}


def _fleet(*, online: int = 4, network_ready: bool = True, blockers: list[str] | None = None) -> dict:
    expected = ["host01", "host03", "host04", "host02"]
    eligible = expected if network_ready else ["host01"]
    return {
        "summary": {
            "status": "ready",
            "expected_agents": expected,
            "online_count": online,
            "blockers": blockers or [],
            "warnings": [],
            "monitor_coverage": {
                "status": "ok",
                "canary_monitors": {
                    "network_egress": {
                        "expected_agents": expected,
                        "promotion_eligible_agents": eligible,
                    }
                },
            },
        }
    }


def _alerts(blockers: list[str] | None = None) -> dict:
    return {
        "raw_alerts": 12,
        "visible_non_synthetic": 0,
        "incident_candidates": [],
        "readiness": {"status": "watch", "blockers": blockers or [], "warnings": []},
    }


def _gpu(temp: float = 51.0) -> dict:
    return {"available": True, "gpus": [{"temp_c": temp}]}


def test_rollout_status_holds_until_soak_deadline() -> None:
    report = build_rollout_status(_state(), _gate(), _fleet(), _alerts(), _gpu(), now=NOW)

    assert report["decision"] == "hold_soak"
    assert report["soak"]["complete"] is False
    assert report["blockers"] == []


def test_rollout_status_allows_next_component_after_clean_soak() -> None:
    report = build_rollout_status(
        _state("2026-07-17T22:08:00+00:00"),
        _gate(warnings=["documented_noise"]),
        _fleet(),
        _alerts(),
        _gpu(),
        now=NOW,
    )

    assert report["decision"] == "eligible_next_component"
    assert report["soak"]["complete"] is True


def test_rollout_status_broad_assessment_does_not_block_on_canary_readiness() -> None:
    state = _state()
    state["active_component"] = "broad_enable_all"
    state["policy"] = "broad_enable_assess"

    report = build_rollout_status(state, _gate(), _fleet(network_ready=False), _alerts(), _gpu(), now=NOW)

    assert report["decision"] == "whole_system_watch"
    assert report["blockers"] == []
    assert report["fleet"]["network_egress_required"] is False


def test_rollout_status_blocks_on_gpu_temperature() -> None:
    report = build_rollout_status(_state("2026-07-17T22:08:00+00:00"), _gate(), _fleet(), _alerts(), _gpu(70.0), now=NOW)

    assert report["decision"] == "blocked"
    assert "gpu:temp>=70C" in report["blockers"]


def test_rollout_status_blocks_when_canary_not_ready() -> None:
    report = build_rollout_status(_state("2026-07-17T22:08:00+00:00"), _gate(), _fleet(network_ready=False), _alerts(), _gpu(), now=NOW)

    assert report["decision"] == "blocked"
    assert "canary:network_egress_not_promotion_ready" in report["blockers"]


def test_rollout_status_can_treat_warnings_as_strict_blockers() -> None:
    report = build_rollout_status(
        _state("2026-07-17T22:08:00+00:00"),
        _gate(warnings=["needs_review"]),
        _fleet(),
        _alerts(),
        _gpu(),
        now=NOW,
        strict_warnings=True,
    )

    assert report["decision"] == "blocked"
    assert "warnings_present" in report["blockers"]


def test_rollout_status_reports_collection_failures_explicitly() -> None:
    report = build_rollout_status(
        _state("2026-07-17T22:08:00+00:00"),
        {"status": "command_failed"},
        _fleet(),
        _alerts(),
        _gpu(),
        now=NOW,
    )

    assert report["decision"] == "blocked"
    assert "collector:production_gate:command_failed" in report["blockers"]
    assert report["rollback"]["eligible"] is False
    assert report["rollback"]["reason"] == "collector_failure"


def test_rollout_status_blocks_without_soak_start() -> None:
    report = build_rollout_status({}, _gate(), _fleet(), _alerts(), _gpu(), now=NOW)

    assert report["decision"] == "blocked"
    assert "soak:missing_start" in report["blockers"]


def test_rollout_status_includes_argus_rollback_commands_when_blocked() -> None:
    report = build_rollout_status(
        _state("2026-07-17T22:08:00+00:00"),
        _gate(blockers=["x"]),
        _fleet(),
        _alerts(),
        _gpu(),
        now=NOW,
    )

    commands = report["rollback"]["commands"]
    assert report["rollback"]["eligible"] is True
    assert len(commands) == 4
    assert commands[0]["target"] == "host01"
    assert "argus_network_egress_rollout.py --target host01 --action rollback --json" in commands[0]["command"]


def test_rollout_status_does_not_offer_rollback_for_clean_hold() -> None:
    report = build_rollout_status(_state(), _gate(), _fleet(), _alerts(), _gpu(), now=NOW)

    assert report["decision"] == "hold_soak"
    assert report["rollback"]["eligible"] is False
    assert report["rollback"]["commands"] == []


def test_rollback_commands_use_state_targets() -> None:
    commands = rollback_commands_for_state(
        {
            "active_component": "argus_network_egress",
            "rollback_targets": ["host03"],
        }
    )

    assert commands == [
        {
            "target": "host03",
            "component": "argus_network_egress",
            "command": (
                "cd /home/user/security-shallots && "
                ".venv/bin/python tools/argus_network_egress_rollout.py --target host03 --action rollback --json"
            ),
        }
    ]


def test_execute_rollback_commands_runs_planned_rollback_and_watch(monkeypatch) -> None:
    calls: list[str] = []
    plan = {
        "commands": [
            {"step": "rollback_target", "command": "rollback host03"},
            {"step": "watch_central", "command": "watch central"},
        ]
    }

    def fake_run(command: str) -> dict:
        calls.append(command)
        if command == "plan host03":
            return {"command": command, "returncode": 0, "stdout": json.dumps(plan), "stderr": "", "ok": True}
        return {"command": command, "returncode": 0, "stdout": "", "stderr": "", "ok": True}

    monkeypatch.setattr(shallot_rollout_status, "_run_shell", fake_run)

    result = execute_rollback_commands([{"target": "host03", "command": "plan host03"}])

    assert result["ok"] is True
    assert calls == ["plan host03", "rollback host03", "watch central"]


def test_execute_rollback_commands_fails_when_plan_has_no_rollback(monkeypatch) -> None:
    def fake_run(command: str) -> dict:
        return {"command": command, "returncode": 0, "stdout": json.dumps({"commands": []}), "stderr": "", "ok": True}

    monkeypatch.setattr(shallot_rollout_status, "_run_shell", fake_run)

    result = execute_rollback_commands([{"target": "host03", "command": "plan host03"}])

    assert result["ok"] is False
    assert result["results"][0]["missing_step"] == "rollback_target"
