#!/usr/bin/env python3
"""Safe experiment runner for the host01 Security Shallots deployment.

This intentionally exercises the central Shallots server only. It does not
install agents, modify firewall rules, fill disks, or enable active response.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import datetime as dt
import json
import os
import shlex
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_HOST = "192.168.0.172"
DEFAULT_USER = "om"
REMOTE_REPO = "/home/user/security-shallots"
EXPERIMENT_ARGUS_AGENT = "shallot-experiment-agent"


def run(cmd: list[str], *, timeout: int = 30, input_text: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def ssh(host: str, user: str, remote_cmd: str, *, timeout: int = 30) -> subprocess.CompletedProcess:
    return run(["ssh", "-o", "BatchMode=yes", f"{user}@{host}", remote_cmd], timeout=timeout)


def ssh_json(host: str, user: str, remote_cmd: str, *, timeout: int = 30) -> Any:
    proc = ssh(host, user, remote_cmd, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"remote command failed: {proc.stderr.strip() or proc.stdout.strip()}")
    return json.loads(proc.stdout)


def remote_config(host: str, user: str) -> dict[str, Any]:
    script = f"""
import json, yaml
experiment_agent = {EXPERIMENT_ARGUS_AGENT!r}
with open({str(Path(REMOTE_REPO) / "config.yaml")!r}, "r", encoding="utf-8") as f:
    cfg = yaml.safe_load(f)
    argus = cfg.get("argus", {{}})
    agent_secrets = argus.get("agent_secrets", {{}}) or {{}}
    require_per_agent = bool(argus.get("require_per_agent_secret", False))
    print(json.dumps({{
        "web_user": cfg["web"]["username"],
        "web_password": cfg["web"]["password"],
        "argus_secret": agent_secrets.get(experiment_agent, "") if require_per_agent else argus.get("webhook_secret", ""),
        "argus_legacy_shared_secret": argus.get("webhook_secret", ""),
        "heartbeat_secret": cfg.get("agent_monitor", {{}}).get("heartbeat_secret", ""),
        "argus_secret_set": bool((agent_secrets.get(experiment_agent, "") if require_per_agent else argus.get("webhook_secret", ""))),
        "argus_per_agent_required": require_per_agent,
        "argus_experiment_agent_configured": bool(agent_secrets.get(experiment_agent, "")),
        "heartbeat_secret_set": bool(cfg.get("agent_monitor", {{}}).get("heartbeat_secret", "")),
        "argus_webhook_scheme": "https" if argus.get("webhook_tls_enabled", False) else "http",
}}))
"""
    return ssh_json(host, user, "python3 - <<'PY'\n" + script + "PY")


def api_get(host: str, cfg: dict[str, Any], path: str, *, timeout: int = 10) -> tuple[int, Any]:
    url = f"https://{host}:8844{path}"
    req = urllib.request.Request(url)
    token = base64.b64encode(f"{cfg['web_user']}:{cfg['web_password']}".encode()).decode()
    req.add_header("Authorization", f"Basic {token}")
    ctx = _insecure_ssl_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {"body": body}
        return exc.code, parsed


def api_post(host: str, cfg: dict[str, Any], path: str, payload: Any, headers: dict[str, str]) -> tuple[int, Any]:
    url = f"https://{host}:8844{path}"
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    token = base64.b64encode(f"{cfg['web_user']}:{cfg['web_password']}".encode()).decode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Authorization": f"Basic {token}", "Content-Type": "application/json", **headers},
        method="POST",
    )
    ctx = _insecure_ssl_context()
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {"body": body}
        return exc.code, parsed


def api_post_raw(host: str, cfg: dict[str, Any], path: str, body: bytes, headers: dict[str, str]) -> tuple[int, Any]:
    url = f"https://{host}:8844{path}"
    token = base64.b64encode(f"{cfg['web_user']}:{cfg['web_password']}".encode()).decode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Authorization": f"Basic {token}", "Content-Type": "application/json", **headers},
        method="POST",
    )
    ctx = _insecure_ssl_context()
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                parsed = {"body": raw}
            return resp.status, parsed
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {"body": raw}
        return exc.code, parsed


def post_json(url: str, payload: Any, headers: dict[str, str], *, timeout: int = 10) -> tuple[int, Any]:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", **headers}, method="POST")
    ctx = _insecure_ssl_context() if url.startswith("https://") else None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {"body": body}
        return exc.code, parsed


def post_raw(url: str, body: bytes, headers: dict[str, str], *, timeout: int = 10) -> tuple[int, Any]:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    ctx = _insecure_ssl_context() if url.startswith("https://") else None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                parsed = {"body": raw}
            return resp.status, parsed
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {"body": raw}
        return exc.code, parsed


def _insecure_ssl_context():
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def remote_state(host: str, user: str) -> dict[str, Any]:
    cmd = r"""
python3 - <<'PY'
import json, os, shutil, sqlite3, subprocess
def show(unit, *props):
    p = subprocess.run(["systemctl", "show", unit, *sum([["-p", x] for x in props], [])], capture_output=True, text=True)
    out = {}
    for line in p.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out
def active(unit):
    return subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True).stdout.strip()
def enabled(unit):
    return subprocess.run(["systemctl", "is-enabled", unit], capture_output=True, text=True).stdout.strip()
def agent_units():
    units = {}
    p = subprocess.run(["systemctl", "list-unit-files", "--no-pager", "--plain", "--type=service"], capture_output=True, text=True)
    for line in (p.stdout or "").splitlines():
        parts = line.split()
        if not parts:
            continue
        name = parts[0]
        low = name.lower()
        if any(tok in low for tok in ("argus", "clove", "fleet-agent")):
            units[name] = {
                "enabled": enabled(name),
                "active": active(name),
            }
    return units
def matching_lines(cmd, tokens):
    p = subprocess.run(cmd, capture_output=True, text=True)
    lines = []
    for line in (p.stdout or "").splitlines():
        low = line.lower()
        if any(tok in low for tok in tokens):
            lines.append(line.strip())
    return lines
def user_agent_units():
    return matching_lines(["systemctl", "--user", "list-unit-files", "--no-pager", "--plain"], ("argus", "clove", "fleet-agent"))
def agent_timers():
    return matching_lines(["systemctl", "list-unit-files", "--no-pager", "--plain", "--type=timer"], ("argus", "clove", "fleet-agent"))
def agent_processes():
    p = subprocess.run(["ps", "-eo", "pid=,comm=,args="], capture_output=True, text=True)
    lines = []
    self_pid = str(os.getpid())
    for line in (p.stdout or "").splitlines():
        parts = line.strip().split(None, 2)
        pid = parts[0] if parts else ""
        low = line.lower()
        if pid == self_pid:
            continue
        if "shallot_experiment.py" in low:
            continue
        if any(tok in low for tok in ("argus", "clove", "fleet-agent")):
            lines.append(line.strip())
    return lines
def agent_containers():
    if shutil.which("docker") is None:
        return []
    return matching_lines(["docker", "ps", "--format", "{{.Names}} {{.Image}} {{.Status}}"], ("argus", "clove", "fleet-agent"))
def agent_cron():
    lines = []
    p = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    for line in (p.stdout or "").splitlines():
        low = line.lower()
        if any(tok in low for tok in ("argus", "clove", "fleet-agent")):
            lines.append(f"user-crontab: {line.strip()}")
    for root, _dirs, files in os.walk("/etc/cron.d"):
        for name in files:
            path = os.path.join(root, name)
            try:
                text = open(path, "r", encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            if any(tok in text.lower() for tok in ("argus", "clove", "fleet-agent")):
                lines.append(path)
    return lines
def host_impact():
    load1 = 0.0
    try:
        load1 = os.getloadavg()[0]
    except OSError:
        pass
    cpu_count = os.cpu_count() or 1
    iowait = 0
    try:
        fields = open("/proc/stat", "r", encoding="utf-8").readline().split()
        if fields and fields[0] == "cpu" and len(fields) > 5:
            iowait = int(fields[5])
    except (OSError, ValueError):
        pass
    return {
        "load1": round(float(load1), 3),
        "load_per_core": round(float(load1) / max(1, cpu_count), 4),
        "cpu_count": cpu_count,
        "iowait_jiffies": iowait,
    }
def journal_count(priority):
    p = subprocess.run(
        ["journalctl", "-u", "shallotd.service", "--since", "-15min", "-p", priority, "--no-pager", "-q"],
        capture_output=True,
        text=True,
    )
    return len([x for x in p.stdout.splitlines() if x.strip()])
du = shutil.disk_usage("/")
db = "/home/user/security-shallots/shallots.db"
alert_count = None
try:
    con = sqlite3.connect(db)
    alert_count = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    con.close()
except Exception:
    pass
svc = show(
  "shallotd.service",
  "ActiveState", "SubState", "NRestarts", "MemoryCurrent", "MemoryPeak",
  "MemoryMax", "CPUUsageNSec", "MainPID", "TasksCurrent"
)
pid = svc.get("MainPID", "0")
fd_count = 0
try:
    fd_count = len(os.listdir(f"/proc/{pid}/fd")) if pid and pid != "0" else 0
except OSError:
    pass
ss = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True)
listeners = []
for line in (ss.stdout or "").splitlines():
    if ":8844" in line or ":8855" in line:
        listeners.append(line.strip())
print(json.dumps({
  "shallotd": svc,
  "watchdog_timer": active("shallot-watchdog.timer"),
  "backup_timer": active("shallot-backup.timer"),
  "argus_canary_active": active("argus-canary.service"),
  "argus_canary_enabled": enabled("argus-canary.service"),
  "agent_units": agent_units(),
  "agent_user_units": user_agent_units(),
  "agent_timers": agent_timers(),
  "agent_processes": agent_processes(),
  "agent_containers": agent_containers(),
  "agent_cron": agent_cron(),
  "host": host_impact(),
  "disk_root": {"used_pct": round(du.used / du.total * 100, 1), "free_gb": round(du.free / (1024**3), 1)},
  "db_size_bytes": os.path.getsize(db) if os.path.exists(db) else 0,
  "alert_count": alert_count,
  "open_fd_count": fd_count,
  "listeners": listeners,
  "journal": {
    "err_or_worse_15m": journal_count("err"),
    "warning_or_worse_15m": journal_count("warning"),
  },
}))
PY
"""
    return ssh_json(host, user, cmd)


def db_integrity(host: str, user: str) -> dict[str, Any]:
    cmd = f"""python3 - <<'PY'
import json, sqlite3
db = {str(Path(REMOTE_REPO) / "shallots.db")!r}
try:
    con = sqlite3.connect(db)
    integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
    alert_count = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    con.close()
    print(json.dumps({{"integrity": integrity, "alert_count": alert_count, "error": ""}}))
except Exception as exc:
    print(json.dumps({{"integrity": "", "alert_count": None, "error": str(exc)}}))
    raise
PY"""
    proc = ssh(host, user, cmd)
    try:
        parsed = json.loads(proc.stdout)
    except json.JSONDecodeError:
        parsed = {"integrity": "", "alert_count": None, "error": proc.stdout.strip()}
    return {
        "returncode": proc.returncode,
        "integrity": parsed.get("integrity", ""),
        "alert_count": parsed.get("alert_count"),
        "stderr": proc.stderr.strip() or parsed.get("error", ""),
    }


def impact_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    def as_int(v: Any) -> int:
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0

    bsvc = before.get("shallotd", {})
    asvc = after.get("shallotd", {})
    return {
        "service_restarted": as_int(asvc.get("NRestarts")) > as_int(bsvc.get("NRestarts")),
        "cpu_nsec_delta": as_int(asvc.get("CPUUsageNSec")) - as_int(bsvc.get("CPUUsageNSec")),
        "memory_current_delta": as_int(asvc.get("MemoryCurrent")) - as_int(bsvc.get("MemoryCurrent")),
        "db_size_delta_bytes": as_int(after.get("db_size_bytes")) - as_int(before.get("db_size_bytes")),
        "alert_count_delta": as_int(after.get("alert_count")) - as_int(before.get("alert_count")),
        "open_fd_delta": as_int(after.get("open_fd_count")) - as_int(before.get("open_fd_count")),
        "tasks_delta": as_int(asvc.get("TasksCurrent")) - as_int(bsvc.get("TasksCurrent")),
        "host_load1_delta": round(
            float(after.get("host", {}).get("load1", 0.0)) - float(before.get("host", {}).get("load1", 0.0)),
            3,
        ),
        "host_load_per_core_delta": round(
            float(after.get("host", {}).get("load_per_core", 0.0))
            - float(before.get("host", {}).get("load_per_core", 0.0)),
            4,
        ),
        "host_iowait_jiffies_delta": as_int(after.get("host", {}).get("iowait_jiffies"))
        - as_int(before.get("host", {}).get("iowait_jiffies")),
        "disk_free_delta_gb": round(
            float(after.get("disk_root", {}).get("free_gb", 0.0))
            - float(before.get("disk_root", {}).get("free_gb", 0.0)),
            3,
        ),
        "warnings_delta_15m": as_int(after.get("journal", {}).get("warning_or_worse_15m"))
        - as_int(before.get("journal", {}).get("warning_or_worse_15m")),
        "errors_delta_15m": as_int(after.get("journal", {}).get("err_or_worse_15m"))
        - as_int(before.get("journal", {}).get("err_or_worse_15m")),
    }


def impact_pass(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    expected_alert_delta: int = 0,
    allow_db_growth: bool = False,
) -> bool:
    delta = impact_delta(before, after)
    svc = after.get("shallotd", {})
    disk = after.get("disk_root", {})
    memory_current = int(svc.get("MemoryCurrent") or 0)
    memory_peak = int(svc.get("MemoryPeak") or 0)
    memory_max = int(svc.get("MemoryMax") or 0)
    memory_ok = True if memory_max <= 0 else max(memory_current, memory_peak) < memory_max * 0.25
    alert_ok = delta["alert_count_delta"] == expected_alert_delta
    db_ok = allow_db_growth or delta["db_size_delta_bytes"] <= 0
    listeners = after.get("listeners", [])
    listener_ok = any(":8844" in x for x in listeners) and any(":8855" in x for x in listeners)
    host_load_ok = float(after.get("host", {}).get("load_per_core", 0.0)) <= 1.5
    parked_agents_ok = (
        not after.get("agent_user_units")
        and not after.get("agent_processes")
        and not after.get("agent_containers")
        and not after.get("agent_cron")
        and all("enabled" not in str(x).lower() for x in after.get("agent_timers", []))
    )
    return (
        svc.get("ActiveState") == "active"
        and svc.get("SubState") == "running"
        and not delta["service_restarted"]
        and after.get("watchdog_timer") == "active"
        and after.get("backup_timer") == "active"
        and after.get("argus_canary_active") != "active"
        and all(unit.get("active") != "active" for unit in after.get("agent_units", {}).values())
        and parked_agents_ok
        and float(disk.get("free_gb", 0.0)) > 10.0
        and memory_ok
        and db_ok
        and alert_ok
        and listener_ok
        and host_load_ok
        and delta["warnings_delta_15m"] <= 0
        and delta["errors_delta_15m"] <= 0
        and delta["open_fd_delta"] <= 2
        and delta["tasks_delta"] <= 0
    )


def round_baseline(host: str, user: str, cfg: dict[str, Any]) -> dict[str, Any]:
    impact_before = remote_state(host, user)
    status, health = api_get(host, cfg, "/api/health")
    cli = ssh(host, user, f"cd {shlex.quote(REMOTE_REPO)} && .venv/bin/python -m shallots -c config.yaml health")
    integrity = db_integrity(host, user)
    impact_after = remote_state(host, user)
    return {
        "api_health_status": status,
        "api_health": health,
        "cli_health_rc": cli.returncode,
        "cli_health_stdout": cli.stdout.strip().splitlines(),
        "cli_health_stderr": cli.stderr.strip(),
        "impact": {
            "before": impact_before,
            "after": impact_after,
            "delta": impact_delta(impact_before, impact_after),
        },
        "db": integrity,
        "secret_config": {
            "argus_secret_set": bool(cfg.get("argus_secret_set")),
            "argus_per_agent_required": bool(cfg.get("argus_per_agent_required")),
            "argus_experiment_agent_configured": bool(cfg.get("argus_experiment_agent_configured")),
            "heartbeat_secret_set": bool(cfg.get("heartbeat_secret_set")),
        },
        "pass": (
            status == 200
            and health.get("status") == "ok"
            and cli.returncode == 0
            and integrity.get("integrity") == "ok"
            and bool(cfg.get("argus_secret_set"))
            and (not cfg.get("argus_per_agent_required") or bool(cfg.get("argus_experiment_agent_configured")))
            and bool(cfg.get("heartbeat_secret_set"))
            and impact_pass(impact_before, impact_after, expected_alert_delta=0)
        ),
    }


def argus_event(hostname: str, severity: str, idx: int, *, run_id: str = "") -> dict[str, Any]:
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")
    details = {"round": "synthetic_ingest", "idx": idx}
    if run_id:
        details["run_id"] = run_id
    return {
        "version": 1,
        "source": "argus",
        "timestamp": now,
        "host": hostname,
        "event_type": "synthetic_experiment",
        "severity": severity,
        "confidence": 0.7,
        "state": "TEST",
        "title": f"Synthetic Shallots experiment {severity} #{idx}",
        "description": "Bounded synthetic ingest event generated by tools/shallot_experiment.py",
        "category": "experiment",
        "details": details,
        "actions_taken": [],
        "raw": {},
    }


def clove_payload() -> dict[str, Any]:
    return {
        "agent_name": "shallot-experiment-clove",
        "agent_type": "clove",
        "os": "linux",
        "ip": "127.0.0.1",
        "version": "experiment",
        "health": {"cpu": 0, "memory": 0, "disk": 0},
        "baselines": {},
        "alerts": [],
    }


def heartbeat_payload(agent_name: str = "shallot-experiment-heartbeat") -> dict[str, Any]:
    return {
        "agent_name": agent_name,
        "agent_type": "experiment",
        "os": "linux",
        "ip": "127.0.0.1",
        "version": "experiment",
        "health": {"cpu": 0, "memory": 0, "disk": 0},
        "baselines": {},
    }


def argus_heartbeat(hostname: str) -> dict[str, Any]:
    return {
        "version": 1,
        "source": "argus",
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds"),
        "host": hostname,
        "event_type": "heartbeat",
        "severity": "low",
        "confidence": 1.0,
        "state": "TEST",
        "title": "Argus heartbeat",
        "description": "Synthetic auth-boundary heartbeat",
        "category": "health",
        "details": {"os": "experiment", "ip_address": "127.0.0.1", "active_monitors": []},
    }


def round_auth_boundary(host: str, user: str, cfg: dict[str, Any]) -> dict[str, Any]:
    impact_before = remote_state(host, user)
    argus_payload = argus_heartbeat(EXPERIMENT_ARGUS_AGENT)
    argus_missing = api_post(host, cfg, "/api/ingest/argus", argus_payload, {})
    argus_wrong = api_post(host, cfg, "/api/ingest/argus", argus_payload, {"X-Argus-Secret": "wrong"})
    argus_ok = api_post(host, cfg, "/api/ingest/argus", argus_payload, {"X-Argus-Secret": cfg["argus_secret"]})
    argus_shared = None
    if cfg.get("argus_per_agent_required") and cfg.get("argus_legacy_shared_secret"):
        argus_shared = api_post(
            host,
            cfg,
            "/api/ingest/argus",
            argus_payload,
            {"X-Argus-Secret": cfg["argus_legacy_shared_secret"]},
        )
    clove_missing = api_post(host, cfg, "/api/ingest/clove", clove_payload(), {})
    clove_wrong = api_post(host, cfg, "/api/ingest/clove", clove_payload(), {"X-Heartbeat-Secret": "wrong"})
    clove_ok = api_post(
        host,
        cfg,
        "/api/ingest/clove",
        clove_payload(),
        {"X-Heartbeat-Secret": cfg["heartbeat_secret"]},
    )
    heartbeat_missing = api_post(host, cfg, "/api/heartbeat", heartbeat_payload(), {})
    heartbeat_wrong = api_post(
        host,
        cfg,
        "/api/heartbeat",
        heartbeat_payload(),
        {"X-Heartbeat-Secret": "wrong"},
    )
    heartbeat_ok = api_post(
        host,
        cfg,
        "/api/heartbeat",
        heartbeat_payload(),
        {"X-Heartbeat-Secret": cfg["heartbeat_secret"]},
    )
    argus_malformed = api_post_raw(
        host,
        cfg,
        "/api/ingest/argus",
        b"{not-json",
        {"X-Argus-Secret": cfg["argus_secret"]},
    )
    clove_malformed = api_post_raw(
        host,
        cfg,
        "/api/ingest/clove",
        b"{not-json",
        {"X-Heartbeat-Secret": cfg["heartbeat_secret"]},
    )
    heartbeat_malformed = api_post_raw(
        host,
        cfg,
        "/api/heartbeat",
        b"{not-json",
        {"X-Heartbeat-Secret": cfg["heartbeat_secret"]},
    )
    webhook_url = f"{cfg.get('argus_webhook_scheme', 'http')}://{host}:8855/api/ingest/argus"
    webhook_missing = post_json(webhook_url, argus_payload, {})
    webhook_wrong = post_json(webhook_url, argus_payload, {"X-Argus-Secret": "wrong"})
    webhook_ok = post_json(webhook_url, argus_payload, {"X-Argus-Secret": cfg["argus_secret"]})
    webhook_shared = None
    if cfg.get("argus_per_agent_required") and cfg.get("argus_legacy_shared_secret"):
        webhook_shared = post_json(
            webhook_url,
            argus_payload,
            {"X-Argus-Secret": cfg["argus_legacy_shared_secret"]},
        )
    webhook_malformed = post_raw(webhook_url, b"{not-json", {"X-Argus-Secret": cfg["argus_secret"]})
    shared_rejected_ok = (
        not cfg.get("argus_per_agent_required")
        or (
            argus_shared is not None
            and webhook_shared is not None
            and argus_shared[0] == 401
            and webhook_shared[0] == 401
        )
    )
    impact_after = remote_state(host, user)
    return {
        "argus_missing_secret": {"status": argus_missing[0], "body": argus_missing[1]},
        "argus_wrong_secret": {"status": argus_wrong[0], "body": argus_wrong[1]},
        "argus_legacy_shared_secret": {
            "status": argus_shared[0] if argus_shared else None,
            "checked": argus_shared is not None,
        },
        "argus_with_secret": {"status": argus_ok[0], "body": argus_ok[1]},
        "clove_missing_secret": {"status": clove_missing[0], "body": clove_missing[1]},
        "clove_wrong_secret": {"status": clove_wrong[0], "body": clove_wrong[1]},
        "clove_with_secret": {"status": clove_ok[0], "body": clove_ok[1]},
        "heartbeat_missing_secret": {"status": heartbeat_missing[0], "body": heartbeat_missing[1]},
        "heartbeat_wrong_secret": {"status": heartbeat_wrong[0], "body": heartbeat_wrong[1]},
        "heartbeat_with_secret": {"status": heartbeat_ok[0], "body": heartbeat_ok[1]},
        "argus_malformed": {"status": argus_malformed[0], "body": argus_malformed[1]},
        "clove_malformed": {"status": clove_malformed[0], "body": clove_malformed[1]},
        "heartbeat_malformed": {"status": heartbeat_malformed[0], "body": heartbeat_malformed[1]},
        "webhook_missing_secret": {"status": webhook_missing[0], "body": webhook_missing[1]},
        "webhook_wrong_secret": {"status": webhook_wrong[0], "body": webhook_wrong[1]},
        "webhook_legacy_shared_secret": {
            "status": webhook_shared[0] if webhook_shared else None,
            "checked": webhook_shared is not None,
        },
        "webhook_with_secret": {"status": webhook_ok[0], "body": webhook_ok[1]},
        "webhook_malformed": {"status": webhook_malformed[0], "body": webhook_malformed[1]},
        "impact": {
            "before": impact_before,
            "after": impact_after,
            "delta": impact_delta(impact_before, impact_after),
        },
        "pass": (
            argus_missing[0] == 401
            and argus_wrong[0] == 401
            and argus_ok[0] == 200
            and clove_missing[0] == 401
            and clove_wrong[0] == 401
            and clove_ok[0] == 200
            and heartbeat_missing[0] == 401
            and heartbeat_wrong[0] == 401
            and heartbeat_ok[0] == 200
            and argus_malformed[0] == 400
            and clove_malformed[0] == 400
            and heartbeat_malformed[0] == 400
            and webhook_missing[0] == 401
            and webhook_wrong[0] == 401
            and shared_rejected_ok
            and webhook_ok[0] == 200
            and webhook_malformed[0] == 400
            and impact_pass(impact_before, impact_after, expected_alert_delta=0, allow_db_growth=True)
        ),
    }


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((pct / 100) * (len(ordered) - 1)))))
    return ordered[idx]


def round_load(
    host: str,
    user: str,
    cfg: dict[str, Any],
    *,
    events: int = 50,
    observe_seconds: int = 30,
    path: str = "webhook-8855",
    kind: str = "alert",
    concurrency: int = 1,
) -> dict[str, Any]:
    impact_before = remote_state(host, user)
    canonical_note = {
        "webhook-8855": "queued standalone Argus webhook; host02 command canary config currently points here",
        "api-8844": "main authenticated dashboard/API route; now uses shared Argus parser and alert queue",
    }[path]
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    latencies_ms: list[float] = []
    statuses: dict[str, int] = {}
    accepted = 0

    def payload_for(idx: int) -> dict[str, Any]:
        if kind == "heartbeat":
            event = argus_heartbeat(EXPERIMENT_ARGUS_AGENT)
            event["details"]["run_id"] = run_id
            event["details"]["idx"] = idx
            return event
        return argus_event(EXPERIMENT_ARGUS_AGENT, "low", idx, run_id=run_id)

    def send_one(idx: int) -> tuple[int, Any, float]:
        event = payload_for(idx)
        t0 = time.monotonic()
        if path == "webhook-8855":
            status, body = post_json(
                f"{cfg.get('argus_webhook_scheme', 'http')}://{host}:8855/api/ingest/argus",
                event,
                {"X-Argus-Secret": cfg["argus_secret"]},
                timeout=10,
            )
        else:
            status, body = api_post(
                host,
                cfg,
                "/api/ingest/argus",
                event,
                {"X-Argus-Secret": cfg["argus_secret"]},
            )
        return status, body, (time.monotonic() - t0) * 1000

    start = time.monotonic()
    if concurrency <= 1:
        for i in range(events):
            status, body, latency = send_one(i + 1)
            latencies_ms.append(latency)
            statuses[str(status)] = statuses.get(str(status), 0) + 1
            if status == 200:
                accepted += _accepted_count(path, kind, body)
            time.sleep(0.02)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = [pool.submit(send_one, i + 1) for i in range(events)]
            for fut in concurrent.futures.as_completed(futures):
                status, body, latency = fut.result()
                latencies_ms.append(latency)
                statuses[str(status)] = statuses.get(str(status), 0) + 1
                if status == 200:
                    accepted += _accepted_count(path, kind, body)
    duration_s = time.monotonic() - start
    health_t0 = time.monotonic()
    health_status, health = api_get(host, cfg, "/api/health", timeout=10)
    health_latency_ms = (time.monotonic() - health_t0) * 1000
    impact_after = remote_state(host, user)
    integrity = db_integrity(host, user)
    time.sleep(max(0, observe_seconds))
    quiet_health_t0 = time.monotonic()
    quiet_health_status, quiet_health = api_get(host, cfg, "/api/health", timeout=10)
    quiet_health_latency_ms = (time.monotonic() - quiet_health_t0) * 1000
    impact_quiet = remote_state(host, user)
    expected_alert_delta = events if kind == "alert" else 0
    immediate_delta = impact_delta(impact_before, impact_after)
    final_delta = impact_delta(impact_before, impact_quiet)
    quiet_delta = impact_delta(impact_after, impact_quiet)
    dropped_during = int(health.get("ingest_queue", {}).get("dropped_total", 0) or 0)
    dropped_quiet = int(quiet_health.get("ingest_queue", {}).get("dropped_total", 0) or 0)
    return {
        "path": path,
        "path_note": canonical_note,
        "kind": kind,
        "run_id": run_id,
        "events_sent": events,
        "concurrency": concurrency,
        "accepted": accepted,
        "statuses": statuses,
        "duration_s": round(duration_s, 3),
        "events_per_sec": round(events / duration_s, 2) if duration_s else 0,
        "latency_ms": {
            "p50": round(percentile(latencies_ms, 50), 2),
            "p95": round(percentile(latencies_ms, 95), 2),
            "max": round(max(latencies_ms) if latencies_ms else 0.0, 2),
            "health": round(health_latency_ms, 2),
        },
        "api_health_status": health_status,
        "api_total_alerts": health.get("total_alerts"),
        "db_integrity": integrity,
        "quiet_observation": {
            "observe_seconds": observe_seconds,
            "api_health_status": quiet_health_status,
            "api_total_alerts": quiet_health.get("total_alerts"),
            "health_latency_ms": round(quiet_health_latency_ms, 2),
            "impact": {
                "after_load": impact_after,
                "after_quiet": impact_quiet,
                "delta": quiet_delta,
            },
        },
        "queue_metrics": {
            "during_load": health.get("ingest_queue", {}),
            "after_quiet": quiet_health.get("ingest_queue", {}),
        },
        "impact": {
            "before": impact_before,
            "after": impact_after,
            "delta": immediate_delta,
            "final_after_quiet_delta": final_delta,
        },
        "pass": (
            accepted == events
            and statuses == {"200": events}
            and health_status == 200
            and quiet_health_status == 200
            and health_latency_ms < 1000
            and quiet_health_latency_ms < 1000
            and percentile(latencies_ms, 95) < 1000
            and integrity.get("integrity") == "ok"
            and dropped_quiet == dropped_during
            and final_delta["alert_count_delta"] == expected_alert_delta
            and impact_pass(
                impact_before,
                impact_after,
                expected_alert_delta=immediate_delta["alert_count_delta"],
                allow_db_growth=True,
            )
            and impact_pass(impact_before, impact_quiet, expected_alert_delta=expected_alert_delta, allow_db_growth=True)
            and impact_pass(impact_after, impact_quiet, expected_alert_delta=0, allow_db_growth=True)
        ),
    }


def _accepted_count(path: str, kind: str, body: dict[str, Any]) -> int:
    if path == "webhook-8855":
        return int(body.get("accepted", 0))
    if kind == "heartbeat":
        return 1 if body.get("status") == "ok" else 0
    return int(body.get("alerts_ingested", 0))


def round_synthetic(host: str, _user: str, cfg: dict[str, Any]) -> dict[str, Any]:
    impact_before = remote_state(host, DEFAULT_USER)
    before_status, before = api_get(host, cfg, "/api/health")
    before_total = int(before.get("total_alerts", 0)) if before_status == 200 else -1
    url = f"{cfg.get('argus_webhook_scheme', 'http')}://{host}:8855/api/ingest/argus"
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    accepted = []
    for i, severity in enumerate(["low", "medium", "high"], start=1):
        status, body = post_json(
            url,
            argus_event(EXPERIMENT_ARGUS_AGENT, severity, i, run_id=run_id),
            {"X-Argus-Secret": cfg["argus_secret"]},
        )
        accepted.append({"severity": severity, "status": status, "body": body})
        time.sleep(0.2)
    unauthorized_status, unauthorized_body = post_json(
        url,
        argus_event(EXPERIMENT_ARGUS_AGENT, "low", 99, run_id=run_id),
        {},
    )
    malformed_status, malformed_body = post_raw(url, b"{not-json", {"X-Argus-Secret": cfg["argus_secret"]})
    time.sleep(1)
    after_status, after = api_get(host, cfg, "/api/health")
    after_total = int(after.get("total_alerts", 0)) if after_status == 200 else -1
    impact_after = remote_state(host, DEFAULT_USER)
    return {
        "before_total": before_total,
        "run_id": run_id,
        "accepted": accepted,
        "unauthorized": {"status": unauthorized_status, "body": unauthorized_body},
        "malformed": {"status": malformed_status, "body": malformed_body},
        "after_total": after_total,
        "delta": after_total - before_total if before_total >= 0 and after_total >= 0 else None,
        "impact": {
            "before": impact_before,
            "after": impact_after,
            "delta": impact_delta(impact_before, impact_after),
        },
        "pass": (
            all(x["status"] == 200 and x["body"].get("accepted") == 1 for x in accepted)
            and unauthorized_status == 401
            and malformed_status == 400
            and after_total - before_total == 3
            and impact_pass(impact_before, impact_after, expected_alert_delta=3, allow_db_growth=True)
        ),
    }


def round_backup_restore(host: str, user: str, _cfg: dict[str, Any]) -> dict[str, Any]:
    impact_before = remote_state(host, user)
    backup_start = time.time()
    start = ssh(host, user, "sudo systemctl start shallot-backup.service && sleep 1 && systemctl show shallot-backup.service -p Result -p ExecMainStatus")
    latest_cmd = "find /var/lib/shallots/backups -type f -name 'shallots-*.tar.*' -printf '%T@ %p\\n' | sort -rn | head -1"
    latest_line = ssh(host, user, latest_cmd).stdout.strip()
    latest_mtime = 0.0
    latest = ""
    if latest_line:
        first, _, rest = latest_line.partition(" ")
        try:
            latest_mtime = float(first)
        except ValueError:
            latest_mtime = 0.0
        latest = rest
    if not latest:
        impact_after = remote_state(host, user)
        return {
            "pass": False,
            "error": "no backup found",
            "service": start.stdout.strip(),
            "stderr": start.stderr.strip(),
            "impact": {"before": impact_before, "after": impact_after, "delta": impact_delta(impact_before, impact_after)},
        }
    with tempfile.TemporaryDirectory() as td:
        local = Path(td) / Path(latest).name
        scp = run(["scp", "-q", f"{user}@{host}:{latest}", str(local)], timeout=60)
        if scp.returncode != 0:
            impact_after = remote_state(host, user)
            return {
                "pass": False,
                "error": "scp failed",
                "stderr": scp.stderr.strip(),
                "latest": latest,
                "impact": {"before": impact_before, "after": impact_after, "delta": impact_delta(impact_before, impact_after)},
            }
        extract_dir = Path(td) / "extract"
        extract_dir.mkdir()
        if local.suffix == ".zst":
            tar_proc = run(["tar", "--use-compress-program=zstd", "-xf", str(local), "-C", str(extract_dir)], timeout=60)
        else:
            tar_proc = run(["tar", "-xf", str(local), "-C", str(extract_dir)], timeout=60)
        if tar_proc.returncode != 0:
            impact_after = remote_state(host, user)
            return {
                "pass": False,
                "error": "extract failed",
                "stderr": tar_proc.stderr.strip(),
                "latest": latest,
                "impact": {"before": impact_before, "after": impact_after, "delta": impact_delta(impact_before, impact_after)},
            }
        db_path = extract_dir / "shallots.db"
        config_path = extract_dir / "config.yaml"
        integrity = ""
        count = None
        if db_path.exists():
            con = sqlite3.connect(db_path)
            try:
                integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
                count = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            finally:
                con.close()
        impact_after = remote_state(host, user)
        return {
            "latest": latest,
            "backup_start_epoch": backup_start,
            "snapshot_mtime_epoch": latest_mtime,
            "snapshot_from_triggered_run": latest_mtime >= backup_start,
            "snapshot_bytes": local.stat().st_size,
            "has_db": db_path.exists(),
            "has_config": config_path.exists(),
            "integrity": integrity,
            "alert_count": count,
            "service": start.stdout.strip().splitlines(),
            "impact": {
                "before": impact_before,
                "after": impact_after,
                "delta": impact_delta(impact_before, impact_after),
            },
            "pass": db_path.exists()
            and config_path.exists()
            and integrity == "ok"
            and latest_mtime >= backup_start
            and impact_pass(impact_before, impact_after, expected_alert_delta=0, allow_db_growth=True),
        }


def append_log(path: Path, round_name: str, result: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().astimezone().isoformat(timespec="seconds")
    with path.open("a", encoding="utf-8") as f:
        f.write(f"\n## {stamp} - {round_name}\n\n")
        f.write(f"Pass: `{bool(result.get('pass'))}`\n\n")
        f.write("```json\n")
        f.write(json.dumps(_redact(result), indent=2, sort_keys=True))
        f.write("\n```\n")


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            key = k.lower()
            if key.endswith("_secret_set"):
                out[k] = _redact(v)
            elif any(word in key for word in ("password", "token", "api_key")):
                out[k] = "<redacted>"
            elif "secret" in key and isinstance(v, (str, int, float, bool)) and v:
                out[k] = "<redacted>"
            else:
                out[k] = _redact(v)
        return out
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--user", default=DEFAULT_USER)
    parser.add_argument(
        "--round",
        choices=["baseline", "auth-boundary", "synthetic", "backup-restore", "load", "all"],
        default="baseline",
    )
    parser.add_argument("--log", type=Path, default=Path("docs/EXPERIMENT_LOG.md"))
    parser.add_argument("--load-events", type=int, default=50, help="Event count for the load round")
    parser.add_argument("--observe-seconds", type=int, default=30, help="Quiet observation window after load")
    parser.add_argument(
        "--load-path",
        choices=["webhook-8855", "api-8844"],
        default="webhook-8855",
        help="Ingest path for the load round",
    )
    parser.add_argument(
        "--load-kind",
        choices=["alert", "heartbeat"],
        default="alert",
        help="Payload kind for the load round",
    )
    parser.add_argument("--load-concurrency", type=int, default=1, help="Concurrent requests for the load round")
    args = parser.parse_args()

    cfg = remote_config(args.host, args.user)
    rounds = (
        ["baseline", "auth-boundary", "synthetic", "backup-restore", "load"]
        if args.round == "all"
        else [args.round]
    )
    overall = True
    for name in rounds:
        if name == "baseline":
            result = round_baseline(args.host, args.user, cfg)
        elif name == "auth-boundary":
            result = round_auth_boundary(args.host, args.user, cfg)
        elif name == "synthetic":
            result = round_synthetic(args.host, args.user, cfg)
        elif name == "backup-restore":
            result = round_backup_restore(args.host, args.user, cfg)
        elif name == "load":
            result = round_load(
                args.host,
                args.user,
                cfg,
                events=args.load_events,
                observe_seconds=args.observe_seconds,
                path=args.load_path,
                kind=args.load_kind,
                concurrency=max(1, args.load_concurrency),
            )
        else:  # pragma: no cover
            raise AssertionError(name)
        append_log(args.log, name, result)
        print(json.dumps({"round": name, "pass": result.get("pass"), "log": str(args.log)}, indent=2))
        overall = overall and bool(result.get("pass"))
    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(main())
