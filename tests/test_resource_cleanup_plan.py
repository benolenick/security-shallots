"""Resource cleanup planner tests."""

from __future__ import annotations

import json
import sys

from tools import shallot_resource_cleanup_plan
from tools.shallot_resource_cleanup_plan import build_plan


def test_host03_cleanup_plan_lists_blocker_and_safe_candidates() -> None:
    plan = build_plan(
        "host03",
        host_hygiene={
            "status": "ok",
            "mode": "666",
            "owner": "root:root",
            "file_type": "character special file",
        },
        disk_status={
            "status": "blocked",
            "source": "/dev/sda2",
            "size_gb": 3299,
            "used_gb": 2781,
            "avail_gb": 351,
            "used_pct": 89.0,
            "mount": "/",
            "raw": "/dev/sda2 3299G 2781G 351G 89% /",
        },
    )

    assert plan["status"] == "blocked"
    assert plan["blockers"] == ["disk>=80%"]
    assert "89%" in plan["direct_df"]
    assert plan["disk_status"]["used_pct"] == 89.0
    assert plan["cleanup_target"]["current_free"] == "351G"
    assert plan["cleanup_target"]["target_extra_free"] == "150G"
    assert "below 80%" in plan["cleanup_target"]["goal"]
    assert "Freeing about 142G reaches 80%" in plan["cleanup_target"]["rationale"]
    paths = [item["path"] for item in plan["candidates"]]
    assert "/home/user/backups" in paths
    assert "/home/user/chemister_db" in paths
    assert [item["priority"] for item in plan["candidates"]] == sorted(
        item["priority"] for item in plan["candidates"]
    )
    backups = next(item for item in plan["candidates"] if item["path"] == "/home/user/backups")
    assert any("find /home/user/backups" in cmd for cmd in backups["inspect_commands"])
    assert any("priority 1-3" in item for item in plan["recommended_sequence"])
    assert any(item["risk"] == "high" for item in plan["candidates"])
    assert any("Do not delete live databases" in item for item in plan["safety"])
    assert plan["host_hygiene_status"]["status"] == "ok"
    assert any("verified ok" in item for item in plan["host_hygiene"])
    assert all(
        "2>/dev/null" not in command
        for item in plan["candidates"]
        for command in item["inspect_commands"]
    )
    assert ".venv/bin/python tools/shallot_production_gate.py" in plan["verify_commands"]
    assert any("below 80%" in item for item in plan["success_criteria"])
    assert any("target_resource_warning" in item for item in plan["success_criteria"])
    assert any("rollout:host03:disk" in item for item in plan["success_criteria"])
    assert any("/dev/null" in item and "mode 666" in item for item in plan["success_criteria"])
    assert plan["access_diagnosis"]["status"] == "ok"


def test_host03_cleanup_plan_warns_when_dev_null_is_broken() -> None:
    plan = build_plan(
        "host03",
        host_hygiene={
            "status": "warn",
            "mode": "644",
            "owner": "root:root",
            "file_type": "character special file",
        },
    )

    assert plan["host_hygiene_status"]["status"] == "warn"
    assert any("not healthy" in item for item in plan["host_hygiene"])
    assert any("sudo chmod 666 /dev/null" in item for item in plan["host_hygiene"])


def test_host03_cleanup_plan_handles_unknown_dev_null_state() -> None:
    plan = build_plan("host03")

    assert plan["host_hygiene_status"]["status"] == "unknown"
    assert plan["disk_status"]["status"] == "unknown"
    assert "89%" in plan["direct_df"]
    assert any("live state was not checked" in item for item in plan["host_hygiene"])


def test_host03_cleanup_plan_diagnoses_publickey_denied_live_checks() -> None:
    plan = build_plan(
        "host03",
        host_hygiene={"status": "unknown", "error": "om@192.168.0.224: Permission denied (publickey)."},
        disk_status={"status": "unknown", "error": "om@192.168.0.224: Permission denied (publickey)."},
    )

    assert plan["access_diagnosis"]["status"] == "ssh_publickey_denied"
    assert "public-key authentication is denied" in plan["access_diagnosis"]["detail"]
    assert any("On host03 console" in cmd for cmd in plan["access_diagnosis"]["repair_commands"])
    assert any("Restore live SSH visibility" in item for item in plan["recommended_sequence"])
    assert any("On host03 console" in cmd for cmd in plan["verify_commands"])


def test_host03_cleanup_plan_uses_fleet_disk_when_ssh_is_denied() -> None:
    plan = build_plan(
        "host03",
        host_hygiene={"status": "unknown", "error": "om@192.168.0.224: Permission denied (publickey)."},
        disk_status={"status": "unknown", "error": "om@192.168.0.224: Permission denied (publickey)."},
        fleet={
            "agents": [
                {
                    "agent": "host03",
                    "disk_used_pct": 75.0,
                    "disk_free_gb": 656.8,
                    "warnings": [],
                    "last_seen": "2026-07-15T15:25:05+00:00",
                    "age_sec": 108,
                }
            ]
        },
    )

    assert plan["status"] == "watch"
    assert plan["blockers"] == []
    assert plan["effective_disk_source"] == "fleet_heartbeat"
    assert plan["fleet_disk_status"]["used_pct"] == 75.0
    assert "disk>=80%" not in plan["blockers"]
    assert any("Do not run cleanup for rollout readiness" in item for item in plan["recommended_sequence"])
    assert any("SSH access" in item for item in plan["recommended_sequence"])


def test_unknown_agent_plan_is_non_destructive() -> None:
    plan = build_plan("unknown")

    assert plan["status"] == "unknown_agent"
    assert plan["blockers"] == []
    assert plan["candidates"] == []
    assert plan["verify_commands"] == []


def test_live_json_alias_outputs_json_with_live_defaults(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["shallot_resource_cleanup_plan.py", "--agent", "host03", "--live-json"])
    monkeypatch.setattr(
        shallot_resource_cleanup_plan,
        "inspect_host_hygiene",
        lambda host: {"status": "ok", "mode": "666", "owner": "root:root", "file_type": "character special file"},
    )
    monkeypatch.setattr(
        shallot_resource_cleanup_plan,
        "inspect_disk_status",
        lambda host: {
            "status": "blocked",
            "source": "/dev/sda2",
            "size_gb": 3299,
            "used_gb": 2781,
            "avail_gb": 351,
            "used_pct": 89.0,
            "mount": "/",
            "raw": "/dev/sda2 3299G 2781G 351G 89% /",
        },
    )

    assert shallot_resource_cleanup_plan.main() == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["agent"] == "host03"
    assert payload["disk_status"]["used_pct"] == 89.0
    assert payload["host_hygiene_status"]["status"] == "ok"
