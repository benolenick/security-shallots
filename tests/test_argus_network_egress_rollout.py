"""Network egress rollout planner tests."""

from __future__ import annotations

import pytest

from tools import argus_network_egress_rollout as rollout
from tools.argus_network_egress_rollout import build_plan


def _fleet(*, eligible: bool, events_remaining: int = 0) -> dict:
    return {
        "summary": {
            "monitor_coverage": {
                "canary_monitors": {
                    "network_egress": {
                        "expected_agents": ["host01"],
                        "present_agents": ["host01"],
                        "stable_agents": ["host01"],
                        "promotion_eligible_agents": ["host01"] if eligible else [],
                        "promotion_min_events": 10,
                        "next_promotion_target": (
                            "eligible:host01"
                            if eligible
                            else f"wait:host01:needs_{events_remaining}_more_clean_events"
                        ),
                        "agents": {
                            "host01": {
                                "present": True,
                                "stable": True,
                                "promotion_eligible": eligible,
                                "events_remaining": events_remaining,
                            }
                        },
                    }
                }
            }
        },
        "agents": [
            {
                "agent": "host01",
                "age_sec": 20,
                "webhook_ok": True,
                "monitors": "anti_tamper,network_egress,session",
                "warnings": [],
            },
            {
                "agent": "host03",
                "age_sec": 40,
                "webhook_ok": True,
                "monitors": "anti_tamper,session",
                "warnings": [],
            },
            {
                "agent": "host04",
                "age_sec": 50,
                "webhook_ok": True,
                "monitors": "anti_tamper,session",
                "warnings": [],
            },
            {
                "agent": "host02",
                "age_sec": 60,
                "webhook_ok": True,
                "monitors": "anti_tamper,session",
                "warnings": [],
            },
        ],
    }


def test_plan_blocks_enable_until_canary_is_promotion_ready() -> None:
    plan = build_plan(_fleet(eligible=False, events_remaining=4), "host03", "enable")

    assert plan["allowed"] is False
    assert plan["dry_run_only"] is True
    assert "canary_not_promotion_ready:wait:host01:needs_4_more_clean_events" in plan["blockers"]
    assert [item["step"] for item in plan["commands"]] == [
        "dry_run_target",
        "watch_central",
    ]
    assert all(item["step"] != "enable_target" for item in plan["commands"])


def test_plan_allows_enable_when_canary_is_promotion_ready() -> None:
    plan = build_plan(_fleet(eligible=True), "host03", "enable")

    assert plan["allowed"] is True
    assert plan["blockers"] == []
    assert plan["target_access"]["status"] == "not_checked"
    assert plan["target_state"]["already_enabled"] is False
    assert "argus_egress_canary.py" in plan["commands"][0]["command"]
    assert "[argus.network_egress]" in plan["commands"][1]["command"]
    assert "shallot_alert_assess.py --hours 1 --summary-json" in plan["commands"][2]["command"]
    assert "shallot_alert_assess.py --hours 1 --json" not in plan["commands"][2]["command"]


def test_plan_blocks_enable_when_target_ssh_access_is_denied() -> None:
    plan = build_plan(
        _fleet(eligible=True),
        "host03",
        "enable",
        target_access={
            "status": "ssh_publickey_denied",
            "target": "host03",
            "ssh_target": "192.168.0.224",
            "detail": "Permission denied (publickey).",
            "repair_commands": [
                "On host03 console, run: sudo bash -lc 'install key'",
                "ssh 192.168.0.224 'hostname && systemctl is-active argus-agent.service'",
            ],
        },
    )

    assert plan["allowed"] is False
    assert "target_access:host03:ssh_publickey_denied" in plan["blockers"]
    assert plan["target_access"]["status"] == "ssh_publickey_denied"
    assert plan["commands"][0]["step"] == "repair_target_access"
    assert "On host03 console" in plan["commands"][0]["command"]
    assert all(item["step"] != "enable_target" for item in plan["commands"])


def test_plan_uses_local_commands_for_local_target_access() -> None:
    plan = build_plan(
        _fleet(eligible=True),
        "host01",
        "plan",
        target_access={
            "status": "ok",
            "target": "host01",
            "ssh_target": "192.168.0.172",
            "detail": "host01",
            "local": True,
            "repair_commands": [],
        },
    )

    commands = {item["step"]: item["command"] for item in plan["commands"]}
    assert commands["dry_run_target"].startswith("cd /home/user/security-shallots")
    assert commands["enable_target"].startswith("sudo bash -lc")
    assert commands["rollback_target"].startswith("sudo bash -lc")
    assert all(not command.startswith("ssh 192.168.0.172") for command in commands.values())


def test_plan_allows_rollback_even_when_canary_not_ready() -> None:
    plan = build_plan(_fleet(eligible=False, events_remaining=4), "host01", "rollback")

    assert plan["allowed"] is True
    assert plan["blockers"] == []
    assert [item["step"] for item in plan["commands"]] == ["rollback_target", "watch_central"]
    assert "config.toml.bak-network-egress" in plan["commands"][0]["command"]


def test_plan_blocks_unhealthy_target_webhook() -> None:
    fleet = _fleet(eligible=True)
    fleet["agents"][1]["webhook_ok"] = False

    plan = build_plan(fleet, "host03", "enable")

    assert plan["allowed"] is False
    assert "host03:webhook_not_healthy" in plan["blockers"]


def test_plan_blocks_target_disk_pressure() -> None:
    fleet = _fleet(eligible=True)
    fleet["agents"][1]["warnings"] = ["disk>=80%"]

    plan = build_plan(fleet, "host03", "enable")

    assert plan["allowed"] is False
    assert "target_resource_warning:host03:disk>=80%" in plan["blockers"]
    assert [item["step"] for item in plan["commands"]] == ["dry_run_target", "watch_central"]
    assert all(item["step"] != "enable_target" for item in plan["commands"])


def test_plan_requires_all_expected_canaries_to_be_promotion_ready() -> None:
    fleet = _fleet(eligible=True)
    canary = fleet["summary"]["monitor_coverage"]["canary_monitors"]["network_egress"]
    canary["expected_agents"] = ["host01", "host04"]
    canary["present_agents"] = ["host01", "host04"]
    canary["stable_agents"] = ["host01", "host04"]
    canary["promotion_eligible_agents"] = ["host01"]
    canary["next_promotion_target"] = "wait:host04:needs_9_more_clean_events"
    canary["agents"]["host04"] = {
        "present": True,
        "stable": True,
        "promotion_eligible": False,
        "events_remaining": 9,
    }

    plan = build_plan(fleet, "host02", "enable")

    assert plan["allowed"] is False
    assert "canary_not_promotion_ready:wait:host04:needs_9_more_clean_events" in plan["blockers"]
    assert [item["step"] for item in plan["commands"]] == ["dry_run_target", "watch_central"]


def test_plan_rejects_unknown_target() -> None:
    with pytest.raises(ValueError, match="unknown target agent"):
        build_plan(_fleet(eligible=True), "not-a-box", "enable")


def test_local_target_access_does_not_require_ssh(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    class Completed:
        returncode = 0
        stdout = "host01\n"
        stderr = ""

    monkeypatch.setattr(rollout, "_local_ipv4s", lambda: {"192.168.0.172"})

    def fake_run(cmd: list[str], **kwargs: object) -> Completed:
        calls.append(cmd)
        return Completed()

    monkeypatch.setattr(rollout.subprocess, "run", fake_run)

    result = rollout.check_target_access("host01")

    assert result["status"] == "ok"
    assert result["local"] is True
    assert calls == [["bash", "-lc", "hostname && test -r /etc/argus/config.toml && systemctl is-active argus-agent.service >/dev/null"]]
