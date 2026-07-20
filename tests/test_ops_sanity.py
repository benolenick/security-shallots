import json
import os
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from tools.shallot_ops_sanity import (
    ALERT_ASSESS_UNIT_SNIPPETS,
    _check_alert_assessment_unit,
    _check_assessment_log_fresh,
    _check_central_api_health,
    _check_controller_ssh_key,
    _check_executable_tools,
    _check_json_state_fresh,
    _check_production_gate,
    _check_security_ops_api,
    _check_security_ops_gate_consistency,
    _check_security_ops_self_assess_consistency,
    _check_security_ops_assets,
    _check_shallotd_service_active,
    _check_syslog_receiver,
    _check_systemd_service_not_failed,
    _check_systemd_timer_active,
)


def test_executable_tool_check_reports_missing_and_not_executable(tmp_path: Path):
    present = tmp_path / "ok.py"
    present.write_text("#!/usr/bin/env python3\n")
    present.chmod(present.stat().st_mode | stat.S_IXUSR)
    blocked = tmp_path / "blocked.py"
    blocked.write_text("#!/usr/bin/env python3\n")
    blocked.chmod(blocked.stat().st_mode & ~stat.S_IXUSR & ~stat.S_IXGRP & ~stat.S_IXOTH)

    checks = _check_executable_tools(tmp_path, ("ok.py", "blocked.py", "missing.py"))

    assert [check.status for check in checks] == ["ok", "fail", "fail"]
    assert checks[1].detail == "not executable"
    assert checks[2].detail == "missing"


def test_controller_ssh_key_check_accepts_locked_ed25519_key(tmp_path: Path):
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    private_key = ssh_dir / "id_ed25519"
    private_key.write_text("private\n")
    private_key.chmod(0o600)
    (ssh_dir / "id_ed25519.pub").write_text("ssh-ed25519 AAAA om@host01-security-shallots\n")

    check = _check_controller_ssh_key(tmp_path)

    assert check.status == "ok"
    assert "om@host01-security-shallots" in check.detail


def test_controller_ssh_key_check_fails_when_private_key_is_too_open(tmp_path: Path):
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    private_key = ssh_dir / "id_ed25519"
    private_key.write_text("private\n")
    private_key.chmod(0o644)
    (ssh_dir / "id_ed25519.pub").write_text("ssh-ed25519 AAAA om@host01-security-shallots\n")

    check = _check_controller_ssh_key(tmp_path)

    assert check.status == "fail"
    assert "permissions too open" in check.detail


def test_production_gate_accepts_blocked_json(monkeypatch, tmp_path: Path):
    script = tmp_path / "tools" / "shallot_production_gate.py"
    script.parent.mkdir()
    script.write_text("")

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=2,
            stdout=json.dumps({"status": "blocked", "blockers": ["x"], "warnings": []}),
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    check = _check_production_gate(tmp_path, os.environ.get("PYTHON", "python3"))

    assert check.status == "ok"
    assert "blocked" in check.detail


def test_alert_assessment_unit_check_accepts_hardened_installed_unit(monkeypatch, tmp_path: Path):
    unit = tmp_path / "setup" / "systemd" / "shallot-alert-assess.service"
    unit.parent.mkdir(parents=True)
    text = "\n".join(ALERT_ASSESS_UNIT_SNIPPETS)
    unit.write_text(text)

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout=text, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    check = _check_alert_assessment_unit(tmp_path)

    assert check.status == "ok"
    assert check.detail == "canonical and installed unit hardened"


def test_alert_assessment_unit_check_fails_on_installed_drift(monkeypatch, tmp_path: Path):
    unit = tmp_path / "setup" / "systemd" / "shallot-alert-assess.service"
    unit.parent.mkdir(parents=True)
    unit.write_text("\n".join(ALERT_ASSESS_UNIT_SNIPPETS))

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout="tools/shallot_alert_assess.py --hours 1\n",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    check = _check_alert_assessment_unit(tmp_path)

    assert check.status == "fail"
    assert "installed missing:" in check.detail
    assert "tools/shallot_syslog_canary.py --timeout 30" in check.detail


def test_systemd_timer_check_accepts_active_timer(monkeypatch, tmp_path: Path):
    calls = iter(
        [
            subprocess.CompletedProcess(args=["systemctl", "is-active"], returncode=0, stdout="active\n", stderr=""),
            subprocess.CompletedProcess(args=["systemctl", "is-enabled"], returncode=0, stdout="enabled\n", stderr=""),
        ]
    )

    def fake_run(*args, **kwargs):
        return next(calls)

    monkeypatch.setattr(subprocess, "run", fake_run)

    check = _check_systemd_timer_active(tmp_path)

    assert check.status == "ok"
    assert check.detail == "active; enabled"


def test_systemd_timer_check_fails_on_inactive_timer(monkeypatch, tmp_path: Path):
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args[0], returncode=3, stdout="inactive\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    check = _check_systemd_timer_active(tmp_path)

    assert check.status == "fail"
    assert check.detail == "inactive"


def test_systemd_timer_check_fails_when_active_but_disabled(monkeypatch, tmp_path: Path):
    calls = iter(
        [
            subprocess.CompletedProcess(args=["systemctl", "is-active"], returncode=0, stdout="active\n", stderr=""),
            subprocess.CompletedProcess(args=["systemctl", "is-enabled"], returncode=1, stdout="disabled\n", stderr=""),
        ]
    )

    def fake_run(*args, **kwargs):
        return next(calls)

    monkeypatch.setattr(subprocess, "run", fake_run)

    check = _check_systemd_timer_active(tmp_path)

    assert check.status == "fail"
    assert check.detail == "active but not enabled: disabled"


def test_systemd_service_check_accepts_inactive_success_state(monkeypatch, tmp_path: Path):
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args[0], returncode=1, stdout="inactive\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    check = _check_systemd_service_not_failed(tmp_path)

    assert check.status == "ok"
    assert check.detail == "inactive"


def test_systemd_service_check_fails_on_failed_state(monkeypatch, tmp_path: Path):
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="failed\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    check = _check_systemd_service_not_failed(tmp_path)

    assert check.status == "fail"
    assert check.detail == "failed"


def test_shallotd_service_check_accepts_active_service(monkeypatch, tmp_path: Path):
    calls = iter(
        [
            subprocess.CompletedProcess(args=["systemctl", "is-active"], returncode=0, stdout="active\n", stderr=""),
            subprocess.CompletedProcess(args=["systemctl", "is-failed"], returncode=1, stdout="active\n", stderr=""),
        ]
    )

    def fake_run(*args, **kwargs):
        return next(calls)

    monkeypatch.setattr(subprocess, "run", fake_run)

    check = _check_shallotd_service_active(tmp_path)

    assert check.status == "ok"
    assert check.detail == "active; failed_state=active"


def test_shallotd_service_check_fails_on_inactive_service(monkeypatch, tmp_path: Path):
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args[0], returncode=3, stdout="inactive\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    check = _check_shallotd_service_active(tmp_path)

    assert check.status == "fail"
    assert check.detail == "inactive"


class _FakeHealthResponse:
    status = 200

    def __init__(self, payload: dict):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, _limit: int) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


def test_central_api_health_accepts_tls_ok(monkeypatch, tmp_path: Path):
    (tmp_path / "config.yaml").write_text(
        "web:\n  port: 8844\n  tls_cert: tls.cert\n  tls_key: tls.key\n"
    )

    def fake_urlopen(url, **kwargs):
        assert url.full_url == "https://127.0.0.1:8844/api/health"
        assert kwargs["context"] is not None
        return _FakeHealthResponse(
            {"status": "ok", "ingest_queue": {"size": 1, "maxsize": 10000, "full": False, "dropped_total": 0}}
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    check = _check_central_api_health(tmp_path)

    assert check.status == "ok"
    assert "status=ok; queue=1/10000; dropped=0" in check.detail


def test_central_api_health_fails_on_degraded_status(monkeypatch, tmp_path: Path):
    (tmp_path / "config.yaml").write_text("web:\n  port: 8844\n")

    def fake_urlopen(url, **kwargs):
        assert url.full_url == "http://127.0.0.1:8844/api/health"
        assert kwargs["context"] is None
        return _FakeHealthResponse({"status": "degraded", "error": "db unavailable"})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    check = _check_central_api_health(tmp_path)

    assert check.status == "fail"
    assert "status=degraded" in check.detail


def test_central_api_health_fails_when_ingest_queue_full(monkeypatch, tmp_path: Path):
    (tmp_path / "config.yaml").write_text("web:\n  port: 8844\n")

    def fake_urlopen(*args, **kwargs):
        return _FakeHealthResponse({"status": "ok", "ingest_queue": {"full": True}})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    check = _check_central_api_health(tmp_path)

    assert check.status == "fail"
    assert "ingest_queue full" in check.detail


def test_security_ops_api_accepts_authenticated_snapshot(monkeypatch, tmp_path: Path):
    (tmp_path / "config.yaml").write_text(
        "web:\n  port: 8844\n  username: admin\n  password: secret\n  tls_cert: tls.cert\n  tls_key: tls.key\n"
    )

    def fake_urlopen(url, **kwargs):
        assert url.full_url == "https://127.0.0.1:8844/api/security/ops"
        assert url.get_header("Authorization", "").startswith("Basic ")
        assert kwargs["context"] is not None
        return _FakeHealthResponse(
            {
                "production_gate": {
                    "status": "blocked",
                    "blockers": ["x"],
                    "warnings": ["y"],
                    "action_items": [{"domain": "network", "owner": "manual", "urgency": "high", "action": "x"}],
                    "remediation_commands": ["tools/check.py"],
                },
                "self_assessment": {
                    "readiness_score": 64,
                    "sections": [{"name": "production_gate", "status": "blocked", "detail": "1 blocker"}],
                    "risks": [{"severity": "high", "domain": "network", "risk": "gap"}],
                    "next_slow_steps": [{"domain": "network", "owner": "manual", "urgency": "high", "action": "x"}],
                    "blocker_review": [
                        {
                            "kind": "blocker",
                            "name": "network:expected_syslog_missing:dlink",
                            "age_sec": 3600,
                            "age": "1.0h",
                            "tier": "aging",
                            "needs_operator": True,
                            "domain": "network_source",
                            "owner": "manual_router_admin",
                            "urgency": "high",
                            "action": "Enable router syslog",
                            "commands": [".venv/bin/python tools/shallot_router_syslog_plan.py --probe"],
                        }
                    ],
                    "alert_rates": {
                        "real_raw_per_hour_24h": 0,
                        "synthetic_per_hour_24h": 0,
                        "visible_per_hour_24h": 0,
                    },
                },
                "fleet": {"agents": [{"agent": "host01", "state": "ARMED_HOME", "age_sec": 12, "warnings": []}]},
                "agent_services": {
                    "status": "ok",
                    "warnings": [],
                    "unchecked_agents": [],
                    "heartbeat_corroborated_agents": [],
                    "unchecked_without_fresh_heartbeat": [],
                    "agents": [
                        {
                            "agent": "host01",
                            "host": "192.168.0.172",
                            "status": "ok",
                            "warnings": [],
                            "heartbeat_seen": True,
                            "heartbeat_corroborated": True,
                        }
                    ],
                },
                "central_health": {},
                "noise_housekeep": {"synthetic_prune": {"status": {}}},
                "network": {},
                "alerts": {
                    "raw_per_hour_24h": 0,
                    "real_raw_per_hour_24h": 0,
                    "synthetic_per_hour_24h": 0,
                    "visible_per_hour_24h": 0,
                    "volume_by_host_24h": [{"host": "host01", "raw": 0, "visible": 0, "real_raw": 0}],
                    "suppression_review_examples": [
                        {
                            "asset": "host03",
                            "severity": "high",
                            "title": "Session activity detected",
                            "count": 2,
                            "latest_age_hours": 9.8,
                        }
                    ],
                    "incident_candidates": [
                        {
                            "timestamp": "2026-07-15T12:00:00+00:00",
                            "asset": "host01",
                            "source": "suricata",
                            "severity": "critical",
                            "title": "ET MALWARE Possible C2 Beacon",
                            "verdict": "pending",
                            "rule_hits": [{"rule_id": "suricata.threat_signature"}],
                        }
                    ],
                    "rate_baseline": {"adaptive_thresholds": {}, "per_host": []},
                },
                "external_sources": [
                    {
                        "name": "dlink",
                        "status": "missing",
                        "src_ips": ["192.168.0.1"],
                        "diagnosis": "missing",
                        "fingerprints": {},
                    }
                ],
                "rule_canary": {
                    "coverage": {
                        "total_cases": 61,
                        "positive_cases": 49,
                        "quiet_cases": 12,
                        "covered_rule_ids": [
                            "syslog.access_control_change",
                            "syslog.auth_failure",
                            "syslog.config_export",
                            "syslog.credential_change",
                            "syslog.dhcp_reservation_change",
                            "syslog.dmz_exposure_change",
                            "syslog.dns_change",
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
                    "cases": [{"name": "router_auth", "source": "syslog", "ok": True, "expected": [], "actual": []}],
                },
                "assessment_loop": {"latest_log_age_sec": 30},
                "gate_watch": {"new_blockers": [], "blocker_age_sec": {}},
            }
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    check = _check_security_ops_api(tmp_path)

    assert check.status == "ok"
    assert check.detail == "blocked; blockers=1; warnings=1"


def test_security_ops_gate_consistency_accepts_matching_cli_and_api(monkeypatch, tmp_path: Path):
    (tmp_path / "config.yaml").write_text(
        "web:\n  port: 8844\n  username: admin\n  password: secret\n  tls_cert: tls.cert\n  tls_key: tls.key\n"
    )
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "shallot_production_gate.py").write_text("")

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=2,
            stdout=json.dumps({"status": "blocked", "blockers": ["b"], "warnings": ["w"]}),
            stderr="",
        )

    def fake_urlopen(url, **kwargs):
        assert url.full_url == "https://127.0.0.1:8844/api/security/ops"
        return _FakeHealthResponse({"production_gate": {"status": "blocked", "blockers": ["b"], "warnings": ["w"]}})

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    check = _check_security_ops_gate_consistency(tmp_path, os.environ.get("PYTHON", "python3"))

    assert check.status == "ok"
    assert check.detail == "blockers=1; warnings=1"


def test_security_ops_gate_consistency_fails_on_blocker_drift(monkeypatch, tmp_path: Path):
    (tmp_path / "config.yaml").write_text("web:\n  port: 8844\n")
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "shallot_production_gate.py").write_text("")

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=2,
            stdout=json.dumps({"status": "blocked", "blockers": ["cli-only"], "warnings": []}),
            stderr="",
        )

    def fake_urlopen(*args, **kwargs):
        return _FakeHealthResponse({"production_gate": {"status": "blocked", "blockers": ["api-only"], "warnings": []}})

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    check = _check_security_ops_gate_consistency(tmp_path, os.environ.get("PYTHON", "python3"))

    assert check.status == "fail"
    assert "blockers differ:" in check.detail


def test_security_ops_self_assess_consistency_accepts_matching_gate_section(monkeypatch, tmp_path: Path):
    (tmp_path / "config.yaml").write_text(
        "web:\n  port: 8844\n  username: admin\n  password: secret\n  tls_cert: tls.cert\n  tls_key: tls.key\n"
    )

    def fake_urlopen(url, **kwargs):
        assert url.full_url == "https://127.0.0.1:8844/api/security/ops"
        return _FakeHealthResponse(
            {
                "production_gate": {
                    "status": "blocked",
                    "blockers": ["network:x", "rollout:target_access:host03:ssh_publickey_denied"],
                    "warnings": ["alerts:y"],
                },
                "self_assessment": {
                    "sections": [
                        {
                            "name": "production_gate",
                            "status": "blocked",
                            "detail": "2 blockers, 1 warnings; oldest_blocker=network:x age=1h",
                        }
                    ],
                    "risks": [{"domain": "agent_rollout", "risk": "blocked"}],
                },
            }
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    check = _check_security_ops_self_assess_consistency(tmp_path)

    assert check.status == "ok"
    assert check.detail == "production_section=2 blockers, 1 warnings"


def test_security_ops_self_assess_consistency_fails_on_count_drift(monkeypatch, tmp_path: Path):
    (tmp_path / "config.yaml").write_text("web:\n  port: 8844\n")

    def fake_urlopen(*args, **kwargs):
        return _FakeHealthResponse(
            {
                "production_gate": {"status": "blocked", "blockers": ["a", "b", "c"], "warnings": ["w"]},
                "self_assessment": {
                    "sections": [{"name": "production_gate", "status": "blocked", "detail": "2 blockers, 1 warnings"}],
                    "risks": [],
                },
            }
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    check = _check_security_ops_self_assess_consistency(tmp_path)

    assert check.status == "fail"
    assert "production section count drift" in check.detail


def test_security_ops_self_assess_consistency_requires_rollout_risk(monkeypatch, tmp_path: Path):
    (tmp_path / "config.yaml").write_text("web:\n  port: 8844\n")

    def fake_urlopen(*args, **kwargs):
        return _FakeHealthResponse(
            {
                "production_gate": {
                    "status": "blocked",
                    "blockers": ["rollout:target_access:host03:ssh_publickey_denied"],
                    "warnings": [],
                },
                "self_assessment": {
                    "sections": [{"name": "production_gate", "status": "blocked", "detail": "1 blockers, 0 warnings"}],
                    "risks": [{"domain": "network_visibility", "risk": "gap"}],
                },
            }
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    check = _check_security_ops_self_assess_consistency(tmp_path)

    assert check.status == "fail"
    assert "without agent_rollout" in check.detail


def test_security_ops_api_fails_when_snapshot_sections_missing(monkeypatch, tmp_path: Path):
    (tmp_path / "config.yaml").write_text("web:\n  port: 8844\n")

    def fake_urlopen(*args, **kwargs):
        return _FakeHealthResponse({"production_gate": {"status": "ready"}})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    check = _check_security_ops_api(tmp_path)

    assert check.status == "fail"
    assert "missing sections:" in check.detail


def test_security_ops_api_fails_when_dashboard_contract_fields_missing(monkeypatch, tmp_path: Path):
    (tmp_path / "config.yaml").write_text("web:\n  port: 8844\n")

    def fake_urlopen(*args, **kwargs):
        return _FakeHealthResponse(
            {
                "production_gate": {"status": "blocked", "blockers": [], "warnings": []},
                "self_assessment": {},
                "fleet": {},
                "central_health": {},
                "noise_housekeep": {},
                "network": {},
                "alerts": {},
                "external_sources": [],
                "rule_canary": {},
            }
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    check = _check_security_ops_api(tmp_path)

    assert check.status == "fail"
    assert "production_gate.action_items" in check.detail
    assert "production_gate.remediation_commands" in check.detail
    assert "self_assessment.readiness_score" in check.detail
    assert "self_assessment.sections" in check.detail
    assert "self_assessment.risks" in check.detail
    assert "self_assessment.next_slow_steps" in check.detail
    assert "self_assessment.blocker_review" in check.detail
    assert "fleet.agents" in check.detail
    assert "alerts.volume_by_host_24h" in check.detail
    assert "alerts.suppression_review_examples" in check.detail
    assert "alerts.incident_candidates" in check.detail
    assert "alerts.rate_baseline" in check.detail
    assert "rule_canary.cases" in check.detail
    assert "rule_canary.coverage" in check.detail
    assert "assessment_loop.latest_log_age_sec" in check.detail
    assert "gate_watch.new_blockers" in check.detail
    assert "gate_watch.blocker_age_sec" in check.detail
    assert "noise_housekeep.synthetic_prune.status" in check.detail


def test_security_ops_api_fails_when_dashboard_row_fields_missing(monkeypatch, tmp_path: Path):
    (tmp_path / "config.yaml").write_text("web:\n  port: 8844\n")

    def fake_urlopen(*args, **kwargs):
        return _FakeHealthResponse(
            {
                "production_gate": {
                    "status": "blocked",
                    "blockers": [],
                    "warnings": [],
                    "action_items": [{"domain": "network_source"}],
                    "remediation_commands": [],
                },
                "self_assessment": {
                    "readiness_score": 64,
                    "sections": [{"name": "production_gate"}],
                    "risks": [{"severity": "high"}],
                    "next_slow_steps": [{"domain": "network_source"}],
                    "blocker_review": [{"kind": "blocker"}],
                },
                "fleet": {"agents": [{"agent": "host01"}]},
                "central_health": {},
                "noise_housekeep": {"synthetic_prune": {"status": {}}},
                "network": {},
                "alerts": {
                    "volume_by_host_24h": [{"host": "host01"}],
                    "suppression_review_examples": [{"asset": "host03"}],
                    "incident_candidates": [{"asset": "host01"}],
                    "rate_baseline": {},
                },
                "external_sources": [{"name": "dlink"}],
                "rule_canary": {"coverage": {"sources": {}}, "coverage_guardrails": {}, "cases": [{"name": "router_auth"}]},
                "assessment_loop": {"latest_log_age_sec": 30},
                "gate_watch": {"new_blockers": [], "blocker_age_sec": {}},
            }
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    check = _check_security_ops_api(tmp_path)

    assert check.status == "fail"
    assert "production_gate.action_items[0].owner|urgency|action" in check.detail
    assert "self_assessment.sections[0].status|detail" in check.detail
    assert "self_assessment.risks[0].domain|risk" in check.detail
    assert "self_assessment.next_slow_steps[0].owner|urgency|action" in check.detail
    assert "self_assessment.blocker_review[0].name|age_sec|age|tier|needs_operator|domain|owner|urgency|action|commands" in check.detail
    assert "fleet.agents[0].state|age_sec|warnings" in check.detail
    assert "alerts.volume_by_host_24h[0].raw|visible|real_raw" in check.detail
    assert "alerts.suppression_review_examples[0].severity|title|count|latest_age_hours" in check.detail
    assert "alerts.incident_candidates[0].timestamp|source|severity|title|verdict|rule_hits" in check.detail
    assert "alerts.rate_baseline.adaptive_thresholds" in check.detail
    assert "alerts.rate_baseline.per_host" in check.detail
    assert "external_sources[0].status|src_ips|diagnosis|fingerprints" in check.detail
    assert "rule_canary.coverage.sources" in check.detail
    assert "rule_canary.coverage.total_cases" in check.detail
    assert "rule_canary.coverage.positive_cases" in check.detail
    assert "rule_canary.coverage.quiet_cases" in check.detail
    assert "rule_canary.coverage.covered_rule_ids" in check.detail
    assert "rule_canary.coverage.sources.argus|suricata|syslog" in check.detail
    assert "rule_canary.cases[0].source|ok|expected|actual" in check.detail


def _minimal_security_ops_payload() -> dict:
    return {
        "production_gate": {
            "status": "blocked",
            "blockers": [],
            "warnings": [],
            "action_items": [],
            "remediation_commands": [],
        },
        "self_assessment": {
            "readiness_score": 69,
            "sections": [{"name": "production_gate", "status": "blocked", "detail": "0 blockers, 0 warnings"}],
            "risks": [],
            "next_slow_steps": [],
            "blocker_review": [],
            "alert_rates": {
                "real_raw_per_hour_24h": 0,
                "synthetic_per_hour_24h": 0,
                "visible_per_hour_24h": 0,
            },
        },
        "fleet": {"agents": [{"agent": "host01", "state": "ARMED_HOME", "age_sec": 10, "warnings": []}]},
        "agent_services": {
            "status": "ok",
            "warnings": [],
            "unchecked_agents": [],
            "heartbeat_corroborated_agents": [],
            "unchecked_without_fresh_heartbeat": [],
            "agents": [
                {
                    "agent": "host01",
                    "host": "192.168.0.172",
                    "status": "ok",
                    "warnings": [],
                    "heartbeat_seen": True,
                    "heartbeat_corroborated": True,
                }
            ],
        },
        "central_health": {},
        "noise_housekeep": {"synthetic_prune": {"status": {}}},
        "network": {},
        "alerts": {
            "raw_per_hour_24h": 0,
            "real_raw_per_hour_24h": 0,
            "synthetic_per_hour_24h": 0,
            "visible_per_hour_24h": 0,
            "volume_by_host_24h": [{"host": "host01", "raw": 0, "visible": 0, "real_raw": 0}],
            "suppression_review_examples": [],
            "incident_candidates": [],
            "rate_baseline": {"adaptive_thresholds": {}, "per_host": []},
        },
        "external_sources": [],
        "rule_canary": {
            "coverage": {
                "total_cases": 61,
                "positive_cases": 49,
                "quiet_cases": 12,
                "covered_rule_ids": ["suricata.critical_signature"],
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
            "cases": [{"name": "router_auth", "source": "syslog", "ok": True, "expected": [], "actual": []}],
        },
        "assessment_loop": {"latest_log_age_sec": 30},
        "gate_watch": {"new_blockers": [], "blocker_age_sec": {}},
    }


def test_security_ops_api_fails_when_quiet_guardrail_headroom_is_negative(monkeypatch, tmp_path: Path):
    (tmp_path / "config.yaml").write_text("web:\n  port: 8844\n")
    payload = _minimal_security_ops_payload()
    payload["rule_canary"]["coverage_guardrails"]["quiet"]["headroom_cases"] = -1

    def fake_urlopen(*args, **kwargs):
        return _FakeHealthResponse(payload)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    check = _check_security_ops_api(tmp_path)

    assert check.status == "fail"
    assert "rule_canary.coverage_guardrails.quiet.headroom_cases<0" in check.detail


def test_security_ops_api_fails_when_source_guardrail_headroom_is_negative(monkeypatch, tmp_path: Path):
    (tmp_path / "config.yaml").write_text("web:\n  port: 8844\n")
    payload = _minimal_security_ops_payload()
    payload["rule_canary"]["coverage_guardrails"]["sources"]["headroom_cases"]["suricata"] = -1

    def fake_urlopen(*args, **kwargs):
        return _FakeHealthResponse(payload)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    check = _check_security_ops_api(tmp_path)

    assert check.status == "fail"
    assert "rule_canary.coverage_guardrails.sources.headroom_cases.suricata<0" in check.detail


def test_security_ops_api_requires_agent_service_contract(monkeypatch, tmp_path: Path):
    (tmp_path / "config.yaml").write_text("web:\n  port: 8844\n")
    payload = _minimal_security_ops_payload()
    del payload["agent_services"]["heartbeat_corroborated_agents"]

    def fake_urlopen(*args, **kwargs):
        return _FakeHealthResponse(payload)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    check = _check_security_ops_api(tmp_path)

    assert check.status == "fail"
    assert "agent_services.heartbeat_corroborated_agents" in check.detail


def test_security_ops_api_requires_real_and_synthetic_rate_fields(monkeypatch, tmp_path: Path):
    (tmp_path / "config.yaml").write_text("web:\n  port: 8844\n")
    payload = _minimal_security_ops_payload()
    del payload["alerts"]["real_raw_per_hour_24h"]

    def fake_urlopen(*args, **kwargs):
        return _FakeHealthResponse(payload)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    check = _check_security_ops_api(tmp_path)

    assert check.status == "fail"
    assert "alerts.real_raw_per_hour_24h" in check.detail


def test_security_ops_api_requires_self_assessment_alert_rates(monkeypatch, tmp_path: Path):
    (tmp_path / "config.yaml").write_text("web:\n  port: 8844\n")
    payload = _minimal_security_ops_payload()
    del payload["self_assessment"]["alert_rates"]["synthetic_per_hour_24h"]

    def fake_urlopen(*args, **kwargs):
        return _FakeHealthResponse(payload)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    check = _check_security_ops_api(tmp_path)

    assert check.status == "fail"
    assert "self_assessment.alert_rates.synthetic_per_hour_24h" in check.detail


class _FakeTextResponse:
    status = 200

    def __init__(self, text: str):
        self._text = text

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, _limit: int) -> bytes:
        return self._text.encode("utf-8")


def test_security_ops_assets_accept_served_panel_contract(monkeypatch, tmp_path: Path):
    (tmp_path / "config.yaml").write_text("web:\n  port: 8844\n  username: admin\n  password: secret\n")

    def fake_urlopen(request, **kwargs):
        assert request.get_header("Authorization", "").startswith("Basic ")
        if request.full_url.endswith("/static/index.html"):
            return _FakeTextResponse(
                "security-ops-section security-gate-status fleet-corner security-egress-status "
                "security-self-status security-self-table-wrap security-risk-table-wrap "
                "security-blocker-table-wrap "
                "security-loop-status security-syslog-status security-rule-status security-quality-status "
                "security-public-status security-public-table-wrap "
                "security-suppression-status security-action-table-wrap security-command-table-wrap "
                "security-incident-table-wrap security-suppression-table-wrap "
                "security-fleet-table-wrap security-volume-table-wrap "
                "security-source-table-wrap security-rule-table-wrap security-maint-table-wrap "
                "security-baseline-table-wrap"
            )
        if request.full_url.endswith("/static/app.js"):
            return _FakeTextResponse(
                "fetchSecurityOps('/api/security/ops'); renderSecurityOps({}); renderFleetCorner(); fleetCorner "
                "securitySelfStatus securitySelfTableWrap securityRiskTableWrap "
                "securityBlockerTableWrap security-blocker-table blocker_review commands "
                "securityEgressStatus securityLoopStatus securitySyslogStatus securityRuleStatus securityQualityStatus "
                "securityPublicStatus securityPublicTableWrap public_listeners security-public-table "
                "securitySuppressionStatus securityActionTableWrap securityCommandTableWrap "
                "securityIncidentTableWrap securitySuppressionTableWrap "
                "blocker_age_sec blocker_review needs_operator securityFleetTableWrap securityVolumeTableWrap action "
                    "securitySourceTableWrap fingerprints securityRuleTableWrap securityMaintTableWrap "
                    "securityBaselineTableWrap security-host-baseline-table per_host "
                    "adaptive_thresholds coverage coverage_guardrails sourceHeadroomText realRawRate"
                )
        if request.full_url.endswith("/static/app.css"):
            return _FakeTextResponse(
                ".security-ops-panel .fleet-corner .security-ops-grid .security-ops-action "
                ".security-self-table .security-risk-table .security-blocker-table "
                ".security-action-table .security-command-table .security-incident-table .security-suppression-table .security-fleet-table "
                ".security-public-table "
                ".security-volume-table .security-source-table "
                ".security-rule-table .security-maint-table .security-baseline-table .security-host-baseline-table"
            )
        raise AssertionError(request.full_url)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    check = _check_security_ops_assets(tmp_path)

    assert check.status == "ok"
    assert check.detail == "served markers: index.html,app.js,app.css"


def test_security_ops_assets_fails_when_marker_missing(monkeypatch, tmp_path: Path):
    (tmp_path / "config.yaml").write_text("web:\n  port: 8844\n")

    def fake_urlopen(request, **kwargs):
        if request.full_url.endswith("/static/index.html"):
            return _FakeTextResponse("security-ops-section")
        return _FakeTextResponse("")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    check = _check_security_ops_assets(tmp_path)

    assert check.status == "fail"
    assert "missing markers security-gate-status" in check.detail


def test_syslog_receiver_check_accepts_configured_udp_listener(tmp_path: Path):
    (tmp_path / "config.yaml").write_text("syslog:\n  enabled: true\n  udp_port: 514\n  tcp_port: 514\n")
    proc = tmp_path / "proc" / "net"
    proc.mkdir(parents=True)
    proc.joinpath("udp").write_text(
        "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
        "0: 00000000:0202 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 1\n"
    )
    proc.joinpath("tcp").write_text(
        "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
    )

    check = _check_syslog_receiver(tmp_path)

    assert check.status == "ok"
    assert check.detail == "udp:514=True; tcp:514=False"


def test_syslog_receiver_check_fails_when_enabled_and_not_listening(tmp_path: Path):
    (tmp_path / "config.yaml").write_text("syslog:\n  enabled: true\n  udp_port: 514\n  tcp_port: 514\n")
    proc = tmp_path / "proc" / "net"
    proc.mkdir(parents=True)
    proc.joinpath("udp").write_text(
        "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
    )
    proc.joinpath("tcp").write_text(
        "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
    )

    check = _check_syslog_receiver(tmp_path)

    assert check.status == "fail"
    assert check.detail == "udp:514=False; tcp:514=False"


def test_json_state_fresh_check_accepts_recent_timestamp(tmp_path: Path):
    state = tmp_path / "docs" / "GATE_WATCH_STATE.json"
    state.parent.mkdir()
    state.write_text('{"status":"stable","checked_at":"2026-07-15T11:30:00+00:00"}')

    check = _check_json_state_fresh(
        tmp_path,
        rel_path="docs/GATE_WATCH_STATE.json",
        name="gate_watch_state",
        timestamp_field="checked_at",
        now=datetime(2026, 7, 15, 11, 35, tzinfo=timezone.utc),
    )

    assert check.status == "ok"
    assert check.detail == "status=stable; age=300s"


def test_json_state_fresh_check_fails_on_stale_timestamp(tmp_path: Path):
    state = tmp_path / "docs" / "SYSLOG_CANARY_STATE.json"
    state.parent.mkdir()
    state.write_text('{"status":"ok","sent_at":"2026-07-15T09:00:00+00:00"}')

    check = _check_json_state_fresh(
        tmp_path,
        rel_path="docs/SYSLOG_CANARY_STATE.json",
        name="syslog_canary_state",
        timestamp_field="sent_at",
        max_age_sec=7200,
        now=datetime(2026, 7, 15, 11, 30, tzinfo=timezone.utc),
    )

    assert check.status == "fail"
    assert "stale sent_at" in check.detail


def test_json_state_fresh_check_fails_on_invalid_json(tmp_path: Path):
    state = tmp_path / "docs" / "GATE_WATCH_STATE.json"
    state.parent.mkdir()
    state.write_text("{")

    check = _check_json_state_fresh(
        tmp_path,
        rel_path="docs/GATE_WATCH_STATE.json",
        name="gate_watch_state",
        timestamp_field="checked_at",
    )

    assert check.status == "fail"
    assert check.detail.startswith("invalid json:")


def test_assessment_log_fresh_check_reads_latest_section(tmp_path: Path):
    log = tmp_path / "docs" / "ALERT_ASSESSMENT_LOG.md"
    log.parent.mkdir()
    log.write_text("intro\n## 2026-07-15T09:00:00+00:00\nold\n## 2026-07-15T11:25:00+00:00\nnew\n")

    check = _check_assessment_log_fresh(
        tmp_path,
        now=datetime(2026, 7, 15, 11, 30, tzinfo=timezone.utc),
    )

    assert check.status == "ok"
    assert check.detail == "latest_age=300s"


def test_assessment_log_fresh_check_fails_when_stale(tmp_path: Path):
    log = tmp_path / "docs" / "ALERT_ASSESSMENT_LOG.md"
    log.parent.mkdir()
    log.write_text("## 2026-07-15T08:00:00+00:00\nold\n")

    check = _check_assessment_log_fresh(
        tmp_path,
        max_age_sec=7200,
        now=datetime(2026, 7, 15, 11, 0, tzinfo=timezone.utc),
    )

    assert check.status == "fail"
    assert "stale latest section" in check.detail


def test_assessment_log_fresh_check_fails_without_parseable_heading(tmp_path: Path):
    log = tmp_path / "docs" / "ALERT_ASSESSMENT_LOG.md"
    log.parent.mkdir()
    log.write_text("## not-a-date\nbody\n")

    check = _check_assessment_log_fresh(tmp_path)

    assert check.status == "fail"
    assert check.detail == "no parseable section timestamp"
