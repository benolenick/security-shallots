"""Agent service supervision check tests."""

from __future__ import annotations

import subprocess

from tools import shallot_agent_service_check
from tools.shallot_agent_service_check import _ssh, build_summary, check_agent


def test_ssh_uses_accept_new_host_key_policy(monkeypatch) -> None:
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    _ssh("192.168.0.204", "true")

    assert "StrictHostKeyChecking=accept-new" in captured["args"]


def test_check_agent_reports_ok_when_service_and_process_present(monkeypatch) -> None:
    def fake_ssh(host: str, command: str, *, timeout: int = 8):
        return subprocess.CompletedProcess(
            args=["ssh"],
            returncode=0,
            stdout="service=active\nprocess=123 /home/user/security-shallots/.venv/bin/python -m argus run-monitor\n",
            stderr="",
        )

    monkeypatch.setattr(shallot_agent_service_check, "_ssh", fake_ssh)

    row = check_agent("host04", "192.168.0.204")

    assert row["status"] == "ok"
    assert row["service_active"] is True
    assert row["process_running"] is True
    assert row["warnings"] == []


def test_check_agent_uses_local_command_for_local_host(monkeypatch) -> None:
    calls = []

    def fake_local_addresses():
        return {"192.168.0.172"}

    def fake_local(command: str, *, timeout: int = 8):
        calls.append(("local", command))
        return subprocess.CompletedProcess(
            args=["bash"],
            returncode=0,
            stdout="service=active\nprocess=123 /home/user/security-shallots/.venv/bin/python -m argus run-monitor\n",
            stderr="",
        )

    def fake_ssh(host: str, command: str, *, timeout: int = 8):
        calls.append(("ssh", command))
        raise AssertionError("local host should not use ssh")

    monkeypatch.setattr(shallot_agent_service_check, "_local_addresses", fake_local_addresses)
    monkeypatch.setattr(shallot_agent_service_check, "_local", fake_local)
    monkeypatch.setattr(shallot_agent_service_check, "_ssh", fake_ssh)

    row = check_agent("host01", "192.168.0.172")

    assert row["status"] == "ok"
    assert calls == [("local", calls[0][1])]


def test_check_agent_warns_on_manual_process_without_active_service(monkeypatch) -> None:
    def fake_ssh(host: str, command: str, *, timeout: int = 8):
        return subprocess.CompletedProcess(
            args=["ssh"],
            returncode=0,
            stdout="service=inactive\nprocess=123 /home/user/security-shallots/.venv/bin/python -m argus run-monitor\n",
            stderr="",
        )

    monkeypatch.setattr(shallot_agent_service_check, "_ssh", fake_ssh)

    row = check_agent("host04", "192.168.0.204")

    assert row["status"] == "warn"
    assert row["warnings"] == ["argus_service_inactive_process_running"]


def test_build_summary_collects_agent_service_warnings(monkeypatch) -> None:
    def fake_check(name: str, host: str):
        return {
            "agent": name,
            "host": host,
            "status": "warn" if name == "host04" else "ok",
            "warnings": ["argus_service_inactive_process_running"] if name == "host04" else [],
        }

    monkeypatch.setattr(shallot_agent_service_check, "check_agent", fake_check)

    summary = build_summary({"host01": "192.168.0.172", "host04": "192.168.0.204"}, heartbeats={})

    assert summary["status"] == "warn"
    assert summary["warnings"] == ["host04:argus_service_inactive_process_running"]


def test_build_summary_treats_ssh_failures_as_unchecked_not_gate_warnings(monkeypatch) -> None:
    def fake_check(name: str, host: str):
        return {
            "agent": name,
            "host": host,
            "status": "warn",
            "warnings": ["ssh_check_failed"],
        }

    monkeypatch.setattr(shallot_agent_service_check, "check_agent", fake_check)

    summary = build_summary({"host04": "192.168.0.204"}, heartbeats={})

    assert summary["status"] == "partial"
    assert summary["warnings"] == []
    assert summary["unchecked_agents"] == ["host04"]
    assert summary["heartbeat_corroborated_agents"] == []
    assert summary["unchecked_without_fresh_heartbeat"] == ["host04"]


def test_build_summary_corroborates_ssh_unchecked_agents_with_fresh_heartbeats(monkeypatch) -> None:
    def fake_check(name: str, host: str):
        return {
            "agent": name,
            "host": host,
            "status": "warn",
            "warnings": ["ssh_check_failed"],
        }

    monkeypatch.setattr(shallot_agent_service_check, "check_agent", fake_check)

    summary = build_summary(
        {"host04": "192.168.0.204", "host02": "192.168.2.177"},
        heartbeats={
            "host04": {"agent": "host04", "age_sec": 90, "state": "watch", "webhook_ok": True},
            "host02": {"agent": "host02", "age_sec": 900, "state": "STALE/watch", "webhook_ok": True},
        },
    )

    assert summary["status"] == "partial"
    assert summary["warnings"] == []
    assert summary["unchecked_agents"] == ["host04", "host02"]
    assert summary["heartbeat_corroborated_agents"] == ["host04"]
    assert summary["unchecked_without_fresh_heartbeat"] == ["host02"]
    assert summary["agents"][0]["heartbeat_corroborated"] is True
    assert summary["agents"][1]["heartbeat_corroborated"] is False


def test_build_summary_reports_ok_corroborated_when_all_unchecked_have_fresh_heartbeats(monkeypatch) -> None:
    def fake_check(name: str, host: str):
        return {
            "agent": name,
            "host": host,
            "status": "warn",
            "warnings": ["ssh_check_failed"],
        }

    monkeypatch.setattr(shallot_agent_service_check, "check_agent", fake_check)

    summary = build_summary(
        {"host04": "192.168.0.204", "host02": "192.168.2.177"},
        heartbeats={
            "host04": {"agent": "host04", "age_sec": 90, "state": "ARMED_HOME", "webhook_ok": True},
            "host02": {"agent": "host02", "age_sec": 120, "state": "ARMED_HOME", "webhook_ok": True},
        },
    )

    assert summary["status"] == "ok_corroborated"
    assert summary["warnings"] == []
    assert summary["unchecked_agents"] == ["host04", "host02"]
    assert summary["heartbeat_corroborated_agents"] == ["host04", "host02"]
    assert summary["unchecked_without_fresh_heartbeat"] == []
