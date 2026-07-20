#!/usr/bin/env python3
"""Sanity-check the operational Shallots tooling after deploy or crash recovery."""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shallots.config import load_config

DEFAULT_TOOLS = (
    "tools/argus_network_egress_rollout.py",
    "tools/shallot_agent_service_check.py",
    "tools/shallot_alert_assess.py",
    "tools/shallot_fleet_top.py",
    "tools/shallot_gate_eval.py",
    "tools/shallot_gate_watch.py",
    "tools/shallot_noise_housekeep.py",
    "tools/shallot_production_gate.py",
    "tools/shallot_public_listener_audit.py",
    "tools/shallot_resource_cleanup_plan.py",
    "tools/shallot_rollout_status.py",
    "tools/shallot_rule_canary.py",
    "tools/shallot_router_syslog_plan.py",
    "tools/shallot_security_snapshot.py",
    "tools/shallot_self_assess.py",
    "tools/shallot_syslog_canary.py",
)
RUNTIME_IMPORTS = ("aiosqlite", "yaml")
VALID_GATE_STATUSES = {"ready", "ready_with_warnings", "watch", "blocked"}
ALERT_ASSESS_UNIT = "shallot-alert-assess.service"
ALERT_ASSESS_TIMER = "shallot-alert-assess.timer"
SHALLOTD_UNIT = "shallotd.service"
ALERT_ASSESS_UNIT_SNIPPETS = (
    "tools/shallot_syslog_canary.py --timeout 30",
    "tools/shallot_alert_assess.py --hours 1 --summary-json",
    "tools/shallot_self_assess.py",
    "tools/shallot_fleet_top.py --compact-json",
    "tools/shallot_noise_housekeep.py --apply --prune-synthetic-older-hours 24 --apply-prune",
)
STATE_MAX_AGE_SEC = 7200
ASSESSMENT_LOG = "docs/ALERT_ASSESSMENT_LOG.md"
NOISE_HOUSEKEEP_STATE = "docs/NOISE_HOUSEKEEP_STATE.json"
JSON_FETCH_LIMIT_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str


def _check_executable_tools(root: Path, tools: tuple[str, ...] = DEFAULT_TOOLS) -> list[Check]:
    checks: list[Check] = []
    for rel in tools:
        path = root / rel
        if not path.exists():
            checks.append(Check(f"tool:{rel}", "fail", "missing"))
        elif not os.access(path, os.X_OK):
            checks.append(Check(f"tool:{rel}", "fail", "not executable"))
        else:
            checks.append(Check(f"tool:{rel}", "ok", "executable"))
    return checks


def _check_runtime_imports(root: Path, python: str) -> Check:
    code = "\n".join(f"import {mod}" for mod in RUNTIME_IMPORTS)
    completed = subprocess.run(
        [python, "-c", code],
        cwd=root,
        text=True,
        capture_output=True,
        timeout=10,
    )
    if completed.returncode == 0:
        return Check("runtime_imports", "ok", ",".join(RUNTIME_IMPORTS))
    detail = (completed.stderr or completed.stdout).strip().splitlines()
    return Check("runtime_imports", "fail", detail[-1] if detail else f"exit {completed.returncode}")


def _check_controller_ssh_key(home: Path | None = None) -> Check:
    ssh_dir = (home or Path.home()) / ".ssh"
    private_key = ssh_dir / "id_ed25519"
    public_key = ssh_dir / "id_ed25519.pub"
    if not private_key.exists():
        return Check("controller_ssh_key", "fail", f"missing {private_key}")
    if not public_key.exists():
        return Check("controller_ssh_key", "fail", f"missing {public_key}")
    try:
        public_text = public_key.read_text(encoding="utf-8").strip()
    except OSError as exc:
        return Check("controller_ssh_key", "fail", f"cannot read public key: {exc}")
    if not public_text.startswith("ssh-ed25519 "):
        return Check("controller_ssh_key", "fail", "public key is not ssh-ed25519")
    mode = private_key.stat().st_mode & 0o777
    if mode & 0o077:
        return Check("controller_ssh_key", "fail", f"private key permissions too open: {mode:o}")
    comment = public_text.split()[-1] if len(public_text.split()) >= 3 else "no-comment"
    return Check("controller_ssh_key", "ok", f"id_ed25519 public key present: {comment}")


def _port_listening(root: Path, port: int, proto: str) -> bool:
    path = root / ("proc/net/udp" if proto == "udp" else "proc/net/tcp")
    if not path.exists():
        path = Path("/proc/net/udp" if proto == "udp" else "/proc/net/tcp")
    try:
        lines = path.read_text().splitlines()[1:]
    except OSError:
        return False
    wanted = f"{int(port):04X}"
    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        _, _, raw_port = parts[1].rpartition(":")
        if raw_port.upper() != wanted:
            continue
        if proto == "udp" or parts[3] == "0A":
            return True
    return False


def _check_syslog_receiver(root: Path, *, config: str = "config.yaml") -> Check:
    try:
        cfg = load_config(str(root / config))
    except Exception as exc:
        return Check("syslog_receiver", "fail", f"config load failed: {type(exc).__name__}: {exc}")
    if not (cfg.components.syslog_receiver or cfg.syslog.enabled):
        return Check("syslog_receiver", "ok", "disabled")
    udp_ok = _port_listening(root, cfg.syslog.udp_port, "udp")
    tcp_ok = _port_listening(root, cfg.syslog.tcp_port, "tcp")
    detail = f"udp:{cfg.syslog.udp_port}={udp_ok}; tcp:{cfg.syslog.tcp_port}={tcp_ok}"
    if udp_ok or tcp_ok:
        return Check("syslog_receiver", "ok", detail)
    return Check("syslog_receiver", "fail", detail)


def _check_production_gate(root: Path, python: str) -> Check:
    completed = subprocess.run(
        [python, str(root / "tools" / "shallot_production_gate.py"), "--json"],
        cwd=root,
        text=True,
        capture_output=True,
        timeout=30,
    )
    if completed.returncode not in (0, 1, 2):
        detail = (completed.stderr or completed.stdout).strip().splitlines()
        return Check("production_gate", "fail", detail[-1] if detail else f"exit {completed.returncode}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        return Check("production_gate", "fail", f"invalid json: {exc}")
    status = str(payload.get("status") or "")
    if status not in VALID_GATE_STATUSES:
        return Check("production_gate", "fail", f"unexpected status {status!r}")
    blockers = len(payload.get("blockers") or [])
    warnings = len(payload.get("warnings") or [])
    return Check("production_gate", "ok", f"{status}; blockers={blockers}; warnings={warnings}")


def _check_rollout_status(root: Path, python: str) -> Check:
    completed = subprocess.run(
        [python, str(root / "tools" / "shallot_rollout_status.py"), "--json"],
        cwd=root,
        text=True,
        capture_output=True,
        timeout=45,
    )
    if completed.returncode not in (0, 1, 2):
        detail = (completed.stderr or completed.stdout).strip().splitlines()
        return Check("rollout_status", "fail", detail[-1] if detail else f"exit {completed.returncode}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        return Check("rollout_status", "fail", f"invalid json: {exc}")
    decision = str(payload.get("decision") or "")
    if decision not in {"hold_soak", "eligible_next_component", "whole_system_watch", "blocked"}:
        return Check("rollout_status", "fail", f"unexpected decision {decision!r}")
    blockers = payload.get("blockers") or []
    if decision == "blocked" or blockers:
        return Check("rollout_status", "fail", f"blocked; blockers={len(blockers)}")
    soak = payload.get("soak") or {}
    remaining = soak.get("remaining_seconds")
    next_component = payload.get("next_component") or "unknown"
    return Check("rollout_status", "ok", f"{decision}; next={next_component}; remaining={remaining}s")


def _production_gate_payload(root: Path, python: str) -> tuple[dict | None, str | None]:
    completed = subprocess.run(
        [python, str(root / "tools" / "shallot_production_gate.py"), "--json"],
        cwd=root,
        text=True,
        capture_output=True,
        timeout=30,
    )
    if completed.returncode not in (0, 1, 2):
        detail = (completed.stderr or completed.stdout).strip().splitlines()
        return None, detail[-1] if detail else f"exit {completed.returncode}"
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        return None, f"invalid json: {exc}"
    if not isinstance(payload, dict):
        return None, "json payload is not an object"
    return payload, None


def _sorted_text_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted(str(item) for item in value)


def _missing_unit_snippets(unit_text: str) -> list[str]:
    return [snippet for snippet in ALERT_ASSESS_UNIT_SNIPPETS if snippet not in unit_text]


def _check_alert_assessment_unit(root: Path) -> Check:
    canonical = root / "setup" / "systemd" / ALERT_ASSESS_UNIT
    try:
        canonical_text = canonical.read_text()
    except OSError:
        return Check("alert_assessment_unit", "fail", f"missing canonical {canonical}")
    missing = _missing_unit_snippets(canonical_text)
    if missing:
        return Check("alert_assessment_unit", "fail", "canonical missing: " + ", ".join(missing))

    completed = subprocess.run(
        ["systemctl", "cat", ALERT_ASSESS_UNIT, "--no-pager"],
        cwd=root,
        text=True,
        capture_output=True,
        timeout=10,
    )
    if completed.returncode != 0:
        return Check("alert_assessment_unit", "ok", "canonical hardened; installed unit unavailable")
    missing = _missing_unit_snippets(completed.stdout)
    if missing:
        return Check("alert_assessment_unit", "fail", "installed missing: " + ", ".join(missing))
    return Check("alert_assessment_unit", "ok", "canonical and installed unit hardened")


def _check_systemd_timer_active(root: Path, *, timer_name: str = ALERT_ASSESS_TIMER) -> Check:
    active = subprocess.run(
        ["systemctl", "is-active", timer_name],
        cwd=root,
        text=True,
        capture_output=True,
        timeout=10,
    )
    active_state = (active.stdout or active.stderr).strip()
    if active.returncode != 0 and not active_state:
        return Check("alert_assessment_timer", "ok", "timer status unavailable")
    if active_state != "active":
        return Check("alert_assessment_timer", "fail", active_state or f"exit {active.returncode}")

    enabled = subprocess.run(
        ["systemctl", "is-enabled", timer_name],
        cwd=root,
        text=True,
        capture_output=True,
        timeout=10,
    )
    enabled_state = (enabled.stdout or enabled.stderr).strip()
    if enabled.returncode != 0 and not enabled_state:
        return Check("alert_assessment_timer", "ok", "active; enabled status unavailable")
    if enabled_state != "enabled":
        return Check("alert_assessment_timer", "fail", f"active but not enabled: {enabled_state or f'exit {enabled.returncode}'}")
    return Check("alert_assessment_timer", "ok", "active; enabled")


def _check_systemd_service_not_failed(root: Path, *, service_name: str = ALERT_ASSESS_UNIT) -> Check:
    completed = subprocess.run(
        ["systemctl", "is-failed", service_name],
        cwd=root,
        text=True,
        capture_output=True,
        timeout=10,
    )
    state = (completed.stdout or completed.stderr).strip()
    if completed.returncode != 0 and not state:
        return Check("alert_assessment_service", "ok", "service failed-state unavailable")
    if state == "failed":
        return Check("alert_assessment_service", "fail", "failed")
    return Check("alert_assessment_service", "ok", state or f"exit {completed.returncode}")


def _check_shallotd_service_active(root: Path, *, service_name: str = SHALLOTD_UNIT) -> Check:
    active = subprocess.run(
        ["systemctl", "is-active", service_name],
        cwd=root,
        text=True,
        capture_output=True,
        timeout=10,
    )
    active_state = (active.stdout or active.stderr).strip()
    if active.returncode != 0 and not active_state:
        return Check("central_service", "ok", "service status unavailable")
    if active_state != "active":
        return Check("central_service", "fail", active_state or f"exit {active.returncode}")

    failed = subprocess.run(
        ["systemctl", "is-failed", service_name],
        cwd=root,
        text=True,
        capture_output=True,
        timeout=10,
    )
    failed_state = (failed.stdout or failed.stderr).strip()
    if failed_state == "failed":
        return Check("central_service", "fail", "active but failed")
    return Check("central_service", "ok", f"active; failed_state={failed_state or f'exit {failed.returncode}'}")


def _check_central_api_health(root: Path, *, config: str = "config.yaml", timeout: float = 5.0) -> Check:
    try:
        cfg = load_config(str(root / config))
    except Exception as exc:
        return Check("central_api_health", "fail", f"config load failed: {type(exc).__name__}: {exc}")
    scheme = "https" if cfg.web.tls_cert and cfg.web.tls_key else "http"
    url = f"{scheme}://127.0.0.1:{cfg.web.port}/api/health"
    try:
        status_code, payload = _fetch_json(url, timeout=timeout, tls=scheme == "https")
    except Exception as exc:
        return Check("central_api_health", "fail", f"{url}: {exc}")
    if status_code != 200:
        return Check("central_api_health", "fail", f"{url}: http {status_code}")
    status = str(payload.get("status") or "")
    queue = payload.get("ingest_queue") if isinstance(payload, dict) else None
    if status != "ok":
        return Check("central_api_health", "fail", f"{url}: status={status or 'missing'}")
    if isinstance(queue, dict) and queue.get("full"):
        return Check("central_api_health", "fail", f"{url}: ingest_queue full")
    queue_detail = ""
    if isinstance(queue, dict):
        queue_detail = f"; queue={queue.get('size')}/{queue.get('maxsize')}; dropped={queue.get('dropped_total')}"
    return Check("central_api_health", "ok", f"{url}: status=ok{queue_detail}")


def _fetch_json(
    url: str,
    *,
    timeout: float,
    tls: bool,
    username: str = "",
    password: str = "",
    limit: int = JSON_FETCH_LIMIT_BYTES,
) -> tuple[int, dict]:
    ssl_ctx = ssl._create_unverified_context() if tls else None
    headers = {}
    if username or password:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ssl_ctx) as response:
            status_code = int(response.status)
            raw = response.read(limit + 1)
    except urllib.error.URLError as exc:
        raise RuntimeError(str(exc)) from exc
    except OSError as exc:
        raise RuntimeError(f"{type(exc).__name__}: {exc}") from exc
    if len(raw) > limit:
        raise RuntimeError(f"json payload exceeded {limit} bytes")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid json: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("json payload is not an object")
    return status_code, payload


def _fetch_text(
    url: str,
    *,
    timeout: float,
    tls: bool,
    username: str = "",
    password: str = "",
    limit: int = 512000,
) -> tuple[int, str]:
    ssl_ctx = ssl._create_unverified_context() if tls else None
    headers = {}
    if username or password:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ssl_ctx) as response:
            status_code = int(response.status)
            raw = response.read(limit)
    except urllib.error.URLError as exc:
        raise RuntimeError(str(exc)) from exc
    except OSError as exc:
        raise RuntimeError(f"{type(exc).__name__}: {exc}") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"invalid utf-8: {exc}") from exc
    return status_code, text


def _check_security_ops_api(root: Path, *, config: str = "config.yaml", timeout: float = 20.0) -> Check:
    try:
        cfg = load_config(str(root / config))
    except Exception as exc:
        return Check("security_ops_api", "fail", f"config load failed: {type(exc).__name__}: {exc}")
    scheme = "https" if cfg.web.tls_cert and cfg.web.tls_key else "http"
    url = f"{scheme}://127.0.0.1:{cfg.web.port}/api/security/ops"
    try:
        status_code, payload = _fetch_json(
            url,
            timeout=timeout,
            tls=scheme == "https",
            username=cfg.web.username,
            password=cfg.web.password,
        )
    except Exception as exc:
        return Check("security_ops_api", "fail", f"{url}: {exc}")
    if status_code != 200:
        return Check("security_ops_api", "fail", f"{url}: http {status_code}")
    required = (
        "production_gate",
        "self_assessment",
        "fleet",
        "central_health",
        "noise_housekeep",
        "network",
        "alerts",
    )
    missing = [key for key in required if key not in payload]
    if missing:
        return Check("security_ops_api", "fail", "missing sections: " + ",".join(missing))
    gate = payload.get("production_gate") or {}
    gate_status = str(gate.get("status") or "")
    if gate_status not in {"ready", "ready_with_warnings", "watch", "blocked"}:
        return Check("security_ops_api", "fail", f"unexpected gate status {gate_status!r}")
    contract_errors: list[str] = []
    def require_row_fields(name: str, rows: Any, fields: tuple[str, ...]) -> None:
        if not rows:
            return
        if not isinstance(rows[0], dict):
            contract_errors.append(f"{name}[0]")
            return
        missing_fields = [field for field in fields if field not in rows[0]]
        if missing_fields:
            contract_errors.append(f"{name}[0]." + "|".join(missing_fields))

    if not isinstance(gate.get("action_items"), list):
        contract_errors.append("production_gate.action_items")
    else:
        require_row_fields("production_gate.action_items", gate.get("action_items"), ("domain", "owner", "urgency", "action"))
    if not isinstance(gate.get("remediation_commands"), list):
        contract_errors.append("production_gate.remediation_commands")
    self_assessment = payload.get("self_assessment") or {}
    if "readiness_score" not in self_assessment:
        contract_errors.append("self_assessment.readiness_score")
    if not isinstance(self_assessment.get("sections"), list):
        contract_errors.append("self_assessment.sections")
    else:
        require_row_fields("self_assessment.sections", self_assessment.get("sections"), ("name", "status", "detail"))
    if not isinstance(self_assessment.get("risks"), list):
        contract_errors.append("self_assessment.risks")
    else:
        require_row_fields("self_assessment.risks", self_assessment.get("risks"), ("severity", "domain", "risk"))
    if not isinstance(self_assessment.get("next_slow_steps"), list):
        contract_errors.append("self_assessment.next_slow_steps")
    else:
        require_row_fields(
            "self_assessment.next_slow_steps",
            self_assessment.get("next_slow_steps"),
            ("domain", "owner", "urgency", "action"),
        )
    if not isinstance(self_assessment.get("blocker_review"), list):
        contract_errors.append("self_assessment.blocker_review")
    else:
        require_row_fields(
            "self_assessment.blocker_review",
            self_assessment.get("blocker_review"),
            ("kind", "name", "age_sec", "age", "tier", "needs_operator", "domain", "owner", "urgency", "action", "commands"),
        )
    alert_rates = self_assessment.get("alert_rates")
    if not isinstance(alert_rates, dict):
        contract_errors.append("self_assessment.alert_rates")
    else:
        for field in ("real_raw_per_hour_24h", "synthetic_per_hour_24h", "visible_per_hour_24h"):
            if field not in alert_rates:
                contract_errors.append(f"self_assessment.alert_rates.{field}")
    fleet = payload.get("fleet") or {}
    if not isinstance(fleet.get("agents"), list):
        contract_errors.append("fleet.agents")
    else:
        require_row_fields("fleet.agents", fleet.get("agents"), ("agent", "state", "age_sec", "warnings"))
    agent_services = payload.get("agent_services")
    if not isinstance(agent_services, dict):
        contract_errors.append("agent_services")
    else:
        for field in (
            "status",
            "warnings",
            "unchecked_agents",
            "heartbeat_corroborated_agents",
            "unchecked_without_fresh_heartbeat",
            "agents",
        ):
            if field not in agent_services:
                contract_errors.append(f"agent_services.{field}")
        for field in ("warnings", "unchecked_agents", "heartbeat_corroborated_agents", "unchecked_without_fresh_heartbeat", "agents"):
            if field in agent_services and not isinstance(agent_services.get(field), list):
                contract_errors.append(f"agent_services.{field}")
        if isinstance(agent_services.get("agents"), list):
            require_row_fields(
                "agent_services.agents",
                agent_services.get("agents"),
                ("agent", "host", "status", "warnings", "heartbeat_seen", "heartbeat_corroborated"),
            )
    alerts = payload.get("alerts") or {}
    if not isinstance(alerts.get("volume_by_host_24h"), list):
        contract_errors.append("alerts.volume_by_host_24h")
    else:
        require_row_fields("alerts.volume_by_host_24h", alerts.get("volume_by_host_24h"), ("host", "raw", "visible", "real_raw"))
    for field in ("raw_per_hour_24h", "real_raw_per_hour_24h", "synthetic_per_hour_24h", "visible_per_hour_24h"):
        if field not in alerts:
            contract_errors.append(f"alerts.{field}")
    if not isinstance(alerts.get("suppression_review_examples"), list):
        contract_errors.append("alerts.suppression_review_examples")
    else:
        require_row_fields(
            "alerts.suppression_review_examples",
            alerts.get("suppression_review_examples"),
            ("asset", "severity", "title", "count", "latest_age_hours"),
        )
    if not isinstance(alerts.get("incident_candidates"), list):
        contract_errors.append("alerts.incident_candidates")
    else:
        require_row_fields(
            "alerts.incident_candidates",
            alerts.get("incident_candidates"),
            ("timestamp", "asset", "source", "severity", "title", "verdict", "rule_hits"),
        )
    rate_baseline = alerts.get("rate_baseline")
    if not isinstance(rate_baseline, dict):
        contract_errors.append("alerts.rate_baseline")
    else:
        if not isinstance(rate_baseline.get("adaptive_thresholds"), dict):
            contract_errors.append("alerts.rate_baseline.adaptive_thresholds")
        if not isinstance(rate_baseline.get("per_host"), list):
            contract_errors.append("alerts.rate_baseline.per_host")
    if not isinstance(payload.get("external_sources"), list):
        contract_errors.append("external_sources")
    else:
        require_row_fields(
            "external_sources",
            payload.get("external_sources"),
            ("name", "status", "src_ips", "diagnosis", "fingerprints"),
        )
    rule_canary = payload.get("rule_canary") or {}
    coverage = rule_canary.get("coverage") or {}
    coverage_guardrails = rule_canary.get("coverage_guardrails") or {}
    if not isinstance(rule_canary.get("coverage"), dict):
        contract_errors.append("rule_canary.coverage")
    elif not isinstance(coverage.get("sources"), dict):
        contract_errors.append("rule_canary.coverage.sources")
    else:
        for field in ("total_cases", "positive_cases", "quiet_cases", "covered_rule_ids"):
            if field not in coverage:
                contract_errors.append(f"rule_canary.coverage.{field}")
        sources = coverage.get("sources") or {}
        missing_sources = [source for source in ("argus", "suricata", "syslog") if source not in sources]
        if missing_sources:
            contract_errors.append("rule_canary.coverage.sources." + "|".join(missing_sources))
    if not isinstance(rule_canary.get("coverage_guardrails"), dict):
        contract_errors.append("rule_canary.coverage_guardrails")
    else:
        quiet_guardrail = coverage_guardrails.get("quiet")
        source_guardrails = coverage_guardrails.get("sources")
        if not isinstance(quiet_guardrail, dict):
            contract_errors.append("rule_canary.coverage_guardrails.quiet")
        else:
            for field in ("minimum_cases", "headroom_cases"):
                if field not in quiet_guardrail:
                    contract_errors.append(f"rule_canary.coverage_guardrails.quiet.{field}")
        if not isinstance(source_guardrails, dict):
            contract_errors.append("rule_canary.coverage_guardrails.sources")
        else:
            for field in ("minimum_cases", "headroom_cases"):
                if not isinstance(source_guardrails.get(field), dict):
                    contract_errors.append(f"rule_canary.coverage_guardrails.sources.{field}")
        if isinstance(quiet_guardrail, dict):
            try:
                quiet_headroom = int(quiet_guardrail.get("headroom_cases"))
            except (TypeError, ValueError):
                contract_errors.append("rule_canary.coverage_guardrails.quiet.headroom_cases")
            else:
                if quiet_headroom < 0:
                    contract_errors.append("rule_canary.coverage_guardrails.quiet.headroom_cases<0")
        if isinstance(source_guardrails, dict) and isinstance(source_guardrails.get("headroom_cases"), dict):
            for source, value in sorted(source_guardrails["headroom_cases"].items()):
                try:
                    source_headroom = int(value)
                except (TypeError, ValueError):
                    contract_errors.append(f"rule_canary.coverage_guardrails.sources.headroom_cases.{source}")
                    continue
                if source_headroom < 0:
                    contract_errors.append(f"rule_canary.coverage_guardrails.sources.headroom_cases.{source}<0")
    if not isinstance(rule_canary.get("cases"), list):
        contract_errors.append("rule_canary.cases")
    else:
        require_row_fields("rule_canary.cases", rule_canary.get("cases"), ("name", "source", "ok", "expected", "actual"))
    assessment_loop = payload.get("assessment_loop") or {}
    if "latest_log_age_sec" not in assessment_loop:
        contract_errors.append("assessment_loop.latest_log_age_sec")
    gate_watch = payload.get("gate_watch") or {}
    if not isinstance(gate_watch.get("new_blockers"), list):
        contract_errors.append("gate_watch.new_blockers")
    if not isinstance(gate_watch.get("blocker_age_sec"), dict):
        contract_errors.append("gate_watch.blocker_age_sec")
    noise_housekeep = payload.get("noise_housekeep") or {}
    synthetic_prune = noise_housekeep.get("synthetic_prune") or {}
    prune_status = synthetic_prune.get("status") if isinstance(synthetic_prune, dict) else None
    if not isinstance(prune_status, dict):
        contract_errors.append("noise_housekeep.synthetic_prune.status")
    if contract_errors:
        return Check("security_ops_api", "fail", "missing contract fields: " + ",".join(contract_errors))
    blockers = len(gate.get("blockers") or [])
    warnings = len(gate.get("warnings") or [])
    return Check("security_ops_api", "ok", f"{gate_status}; blockers={blockers}; warnings={warnings}")


def _check_security_ops_gate_consistency(
    root: Path,
    python: str,
    *,
    config: str = "config.yaml",
    timeout: float = 20.0,
) -> Check:
    gate_payload, gate_error = _production_gate_payload(root, python)
    if gate_error:
        return Check("security_ops_gate_consistency", "fail", f"production_gate: {gate_error}")
    try:
        cfg = load_config(str(root / config))
    except Exception as exc:
        return Check("security_ops_gate_consistency", "fail", f"config load failed: {type(exc).__name__}: {exc}")
    scheme = "https" if cfg.web.tls_cert and cfg.web.tls_key else "http"
    url = f"{scheme}://127.0.0.1:{cfg.web.port}/api/security/ops"
    try:
        status_code, payload = _fetch_json(
            url,
            timeout=timeout,
            tls=scheme == "https",
            username=cfg.web.username,
            password=cfg.web.password,
        )
    except Exception as exc:
        return Check("security_ops_gate_consistency", "fail", f"{url}: {exc}")
    if status_code != 200:
        return Check("security_ops_gate_consistency", "fail", f"{url}: http {status_code}")
    api_gate = payload.get("production_gate") if isinstance(payload, dict) else None
    if not isinstance(api_gate, dict):
        return Check("security_ops_gate_consistency", "fail", "api production_gate missing")
    cli_blockers = _sorted_text_list(gate_payload.get("blockers") if gate_payload else [])
    api_blockers = _sorted_text_list(api_gate.get("blockers"))
    cli_warnings = _sorted_text_list(gate_payload.get("warnings") if gate_payload else [])
    api_warnings = _sorted_text_list(api_gate.get("warnings"))
    if cli_blockers != api_blockers:
        return Check(
            "security_ops_gate_consistency",
            "fail",
            f"blockers differ: cli={cli_blockers} api={api_blockers}",
        )
    if cli_warnings != api_warnings:
        return Check(
            "security_ops_gate_consistency",
            "fail",
            f"warnings differ: cli={cli_warnings} api={api_warnings}",
        )
    return Check(
        "security_ops_gate_consistency",
        "ok",
        f"blockers={len(cli_blockers)}; warnings={len(cli_warnings)}",
    )


def _check_security_ops_self_assess_consistency(
    root: Path,
    *,
    config: str = "config.yaml",
    timeout: float = 20.0,
) -> Check:
    try:
        cfg = load_config(str(root / config))
    except Exception as exc:
        return Check("security_ops_self_assess_consistency", "fail", f"config load failed: {type(exc).__name__}: {exc}")
    scheme = "https" if cfg.web.tls_cert and cfg.web.tls_key else "http"
    url = f"{scheme}://127.0.0.1:{cfg.web.port}/api/security/ops"
    try:
        status_code, payload = _fetch_json(
            url,
            timeout=timeout,
            tls=scheme == "https",
            username=cfg.web.username,
            password=cfg.web.password,
        )
    except Exception as exc:
        return Check("security_ops_self_assess_consistency", "fail", f"{url}: {exc}")
    if status_code != 200:
        return Check("security_ops_self_assess_consistency", "fail", f"{url}: http {status_code}")
    gate = payload.get("production_gate") if isinstance(payload, dict) else None
    self_assessment = payload.get("self_assessment") if isinstance(payload, dict) else None
    if not isinstance(gate, dict) or not isinstance(self_assessment, dict):
        return Check("security_ops_self_assess_consistency", "fail", "missing production_gate or self_assessment")
    gate_blockers = _sorted_text_list(gate.get("blockers"))
    gate_warnings = _sorted_text_list(gate.get("warnings"))
    sections = self_assessment.get("sections")
    if not isinstance(sections, list):
        return Check("security_ops_self_assess_consistency", "fail", "self_assessment.sections missing")
    production_sections = [
        section for section in sections
        if isinstance(section, dict) and section.get("name") == "production_gate"
    ]
    if not production_sections:
        return Check("security_ops_self_assess_consistency", "fail", "self_assessment production_gate section missing")
    detail = str(production_sections[0].get("detail") or "")
    expected_counts = f"{len(gate_blockers)} blockers, {len(gate_warnings)} warnings"
    if expected_counts not in detail:
        return Check(
            "security_ops_self_assess_consistency",
            "fail",
            f"production section count drift: expected {expected_counts!r}; detail={detail!r}",
        )
    rollout_blockers = [blocker for blocker in gate_blockers if blocker.startswith("rollout:")]
    risks = self_assessment.get("risks")
    if rollout_blockers:
        has_rollout_risk = any(
            isinstance(risk, dict) and risk.get("domain") == "agent_rollout"
            for risk in (risks if isinstance(risks, list) else [])
        )
        if not has_rollout_risk:
            return Check(
                "security_ops_self_assess_consistency",
                "fail",
                "rollout blockers present without agent_rollout self-assessment risk",
            )
    return Check(
        "security_ops_self_assess_consistency",
        "ok",
        f"production_section={expected_counts}",
    )


def _check_security_ops_assets(root: Path, *, config: str = "config.yaml", timeout: float = 10.0) -> Check:
    try:
        cfg = load_config(str(root / config))
    except Exception as exc:
        return Check("security_ops_assets", "fail", f"config load failed: {type(exc).__name__}: {exc}")
    scheme = "https" if cfg.web.tls_cert and cfg.web.tls_key else "http"
    base = f"{scheme}://127.0.0.1:{cfg.web.port}"
    assets = {
        "/static/index.html": (
            "security-ops-section",
            "security-gate-status",
            "fleet-corner",
            "security-self-status",
            "security-egress-status",
            "security-loop-status",
            "security-public-status",
            "security-syslog-status",
            "security-rule-status",
            "security-quality-status",
            "security-suppression-status",
            "security-self-table-wrap",
            "security-risk-table-wrap",
            "security-blocker-table-wrap",
            "security-action-table-wrap",
            "security-command-table-wrap",
            "security-incident-table-wrap",
            "security-public-table-wrap",
            "security-suppression-table-wrap",
            "security-fleet-table-wrap",
            "security-volume-table-wrap",
            "security-source-table-wrap",
            "security-rule-table-wrap",
            "security-maint-table-wrap",
            "security-baseline-table-wrap",
        ),
        "/static/app.js": (
            "fetchSecurityOps",
            "/api/security/ops",
            "renderSecurityOps",
            "renderFleetCorner",
            "fleetCorner",
            "securitySelfStatus",
            "securityEgressStatus",
            "securityLoopStatus",
            "securityPublicStatus",
            "securitySyslogStatus",
            "securityRuleStatus",
            "coverage_guardrails",
            "sourceHeadroomText",
            "realRawRate",
            "securityQualityStatus",
            "securitySuppressionStatus",
            "securitySelfTableWrap",
            "securityRiskTableWrap",
            "securityBlockerTableWrap",
            "blocker_review",
            "commands",
            "securityActionTableWrap",
            "securityCommandTableWrap",
            "securityIncidentTableWrap",
            "securityPublicTableWrap",
            "securitySuppressionTableWrap",
            "public_listeners",
            "security-public-table",
            "securityFleetTableWrap",
            "securityVolumeTableWrap",
            "securitySourceTableWrap",
            "securityRuleTableWrap",
            "securityMaintTableWrap",
            "securityBaselineTableWrap",
            "security-host-baseline-table",
            "per_host",
        ),
        "/static/app.css": (
            "security-ops-panel",
            "fleet-corner",
            "security-ops-grid",
            "security-ops-action",
            "security-self-table",
            "security-risk-table",
            "security-blocker-table",
            "security-action-table",
            "security-command-table",
            "security-incident-table",
            "security-public-table",
            "security-suppression-table",
            "security-fleet-table",
            "security-volume-table",
            "security-source-table",
            "security-rule-table",
            "security-maint-table",
            "security-baseline-table",
            "security-host-baseline-table",
        ),
    }
    checked: list[str] = []
    for path, markers in assets.items():
        url = f"{base}{path}"
        try:
            status_code, text = _fetch_text(
                url,
                timeout=timeout,
                tls=scheme == "https",
                username=cfg.web.username,
                password=cfg.web.password,
            )
        except Exception as exc:
            return Check("security_ops_assets", "fail", f"{url}: {exc}")
        if status_code != 200:
            return Check("security_ops_assets", "fail", f"{url}: http {status_code}")
        missing = [marker for marker in markers if marker not in text]
        if missing:
            return Check("security_ops_assets", "fail", f"{path}: missing markers {','.join(missing)}")
        checked.append(path.rsplit("/", 1)[-1])
    return Check("security_ops_assets", "ok", "served markers: " + ",".join(checked))


def _parse_time(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _check_json_state_fresh(
    root: Path,
    *,
    rel_path: str,
    name: str,
    timestamp_field: str,
    max_age_sec: int = STATE_MAX_AGE_SEC,
    now: datetime | None = None,
) -> Check:
    path = root / rel_path
    try:
        payload = json.loads(path.read_text())
    except OSError:
        return Check(name, "fail", f"missing {rel_path}")
    except json.JSONDecodeError as exc:
        return Check(name, "fail", f"invalid json: {exc}")
    if not isinstance(payload, dict):
        return Check(name, "fail", "state is not an object")
    timestamp = _parse_time(payload.get(timestamp_field))
    if timestamp is None:
        return Check(name, "fail", f"missing or invalid {timestamp_field}")
    current = now or datetime.now(timezone.utc)
    age = int((current - timestamp.astimezone(timezone.utc)).total_seconds())
    if age < 0:
        return Check(name, "fail", f"{timestamp_field} is in the future: age={age}s")
    if age > max_age_sec:
        return Check(name, "fail", f"stale {timestamp_field}: age={age}s > {max_age_sec}s")
    status = str(payload.get("status") or "unknown")
    return Check(name, "ok", f"status={status}; age={age}s")


def _check_assessment_log_fresh(
    root: Path,
    *,
    rel_path: str = ASSESSMENT_LOG,
    max_age_sec: int = STATE_MAX_AGE_SEC,
    now: datetime | None = None,
) -> Check:
    path = root / rel_path
    latest: datetime | None = None
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except OSError:
        return Check("assessment_log", "fail", f"missing {rel_path}")
    for line in lines:
        if not line.startswith("## "):
            continue
        parsed = _parse_time(line[3:].strip())
        if parsed is not None:
            latest = parsed
    if latest is None:
        return Check("assessment_log", "fail", "no parseable section timestamp")
    current = now or datetime.now(timezone.utc)
    age = int((current - latest.astimezone(timezone.utc)).total_seconds())
    if age < 0:
        return Check("assessment_log", "fail", f"latest section is in the future: age={age}s")
    if age > max_age_sec:
        return Check("assessment_log", "fail", f"stale latest section: age={age}s > {max_age_sec}s")
    return Check("assessment_log", "ok", f"latest_age={age}s")


def run_checks(root: Path = ROOT, python: str | None = None, include_gate: bool = True) -> list[Check]:
    root = root.resolve()
    py = python or str(root / ".venv" / "bin" / "python")
    checks = _check_executable_tools(root)
    if not Path(py).exists():
        checks.append(Check("runtime_python", "fail", f"missing {py}"))
        return checks
    checks.append(Check("runtime_python", "ok", py))
    checks.append(_check_runtime_imports(root, py))
    checks.append(_check_controller_ssh_key())
    checks.append(_check_shallotd_service_active(root))
    checks.append(_check_central_api_health(root))
    checks.append(_check_security_ops_api(root))
    checks.append(_check_security_ops_gate_consistency(root, py))
    checks.append(_check_security_ops_self_assess_consistency(root))
    checks.append(_check_security_ops_assets(root))
    checks.append(_check_syslog_receiver(root))
    checks.append(_check_alert_assessment_unit(root))
    checks.append(_check_systemd_timer_active(root))
    checks.append(_check_systemd_service_not_failed(root))
    checks.append(_check_assessment_log_fresh(root))
    checks.append(
        _check_json_state_fresh(
            root,
            rel_path=NOISE_HOUSEKEEP_STATE,
            name="noise_housekeep_state",
            timestamp_field="run_at",
        )
    )
    checks.append(
        _check_json_state_fresh(
            root,
            rel_path="docs/GATE_WATCH_STATE.json",
            name="gate_watch_state",
            timestamp_field="checked_at",
        )
    )
    checks.append(
        _check_json_state_fresh(
            root,
            rel_path="docs/SYSLOG_CANARY_STATE.json",
            name="syslog_canary_state",
            timestamp_field="sent_at",
        )
    )
    if include_gate:
        checks.append(_check_production_gate(root, py))
        checks.append(_check_rollout_status(root, py))
    return checks


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--python", default=None)
    parser.add_argument("--skip-gate", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    checks = run_checks(Path(args.root), args.python, include_gate=not args.skip_gate)
    failed = [check for check in checks if check.status != "ok"]
    payload = {
        "status": "fail" if failed else "ok",
        "failed": len(failed),
        "checks": [check.__dict__ for check in checks],
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"ops sanity: {payload['status']} ({len(checks) - len(failed)}/{len(checks)} ok)")
        for check in checks:
            print(f"{check.status:4} {check.name}: {check.detail}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
