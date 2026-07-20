#!/usr/bin/env python3
"""Check whether expected Argus agents are running under their system service."""

from __future__ import annotations

import argparse
import json
import sys
import socket
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_AGENTS = {
    "host01": "192.168.0.172",
    "host03": "192.168.0.224",
    "host04": "192.168.0.129",
    "host02": "192.168.2.177",
}


def _ssh(host: str, command: str, *, timeout: int = 8) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "StrictHostKeyChecking=accept-new",
            host,
            command,
        ],
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def _local_addresses() -> set[str]:
    hosts = {"127.0.0.1", "::1", "localhost"}
    try:
        hosts.add(socket.gethostname())
        hosts.add(socket.getfqdn())
    except Exception:
        pass
    try:
        completed = subprocess.run(
            ["hostname", "-I"],
            text=True,
            capture_output=True,
            timeout=2,
        )
        if completed.returncode == 0:
            hosts.update(item.strip() for item in completed.stdout.split() if item.strip())
    except Exception:
        pass
    return hosts


def _local(command: str, *, timeout: int = 8) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-lc", command],
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def _fleet_heartbeats() -> dict[str, dict[str, Any]]:
    try:
        completed = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "shallot_fleet_top.py"), "--summary-json"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=20,
        )
    except Exception:
        return {}
    if completed.returncode != 0:
        return {}
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {}
    return {str(row.get("agent")): row for row in payload.get("agents", []) if row.get("agent")}


def _attach_heartbeat(row: dict[str, Any], heartbeat: dict[str, Any] | None) -> dict[str, Any]:
    if not heartbeat:
        row.update(
            {
                "heartbeat_seen": False,
                "heartbeat_age_sec": None,
                "heartbeat_state": "",
                "webhook_ok": None,
                "heartbeat_corroborated": False,
            }
        )
        return row
    try:
        age = int(heartbeat.get("age_sec") or 999999)
    except (TypeError, ValueError):
        age = 999999
    webhook_ok = heartbeat.get("webhook_ok")
    corroborated = age <= 360 and webhook_ok is True
    row.update(
        {
            "heartbeat_seen": True,
            "heartbeat_age_sec": age,
            "heartbeat_state": heartbeat.get("state", ""),
            "webhook_ok": webhook_ok,
            "heartbeat_corroborated": corroborated,
        }
    )
    return row


def check_agent(name: str, host: str) -> dict[str, Any]:
    command = (
        "printf 'service='; systemctl is-active argus-agent.service 2>/dev/null || true; "
        "printf 'process='; pgrep -af 'python -m argus|argus.*run-monitor' | grep -v pgrep | head -1 || true"
    )
    result = {
        "agent": name,
        "host": host,
        "reachable": False,
        "service_active": None,
        "process_running": None,
        "status": "unknown",
        "warnings": [],
        "detail": "",
    }
    try:
        completed = _local(command) if host in _local_addresses() else _ssh(host, command)
    except Exception as exc:
        result.update({"status": "warn", "warnings": ["ssh_check_failed"], "detail": f"{type(exc).__name__}: {exc}"})
        return result
    result["reachable"] = completed.returncode == 0
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip().splitlines()
        result.update({"status": "warn", "warnings": ["ssh_check_failed"], "detail": detail[-1] if detail else "ssh failed"})
        return result
    service = ""
    process = ""
    for line in completed.stdout.splitlines():
        if line.startswith("service="):
            service = line.split("=", 1)[1].strip()
        elif line.startswith("process="):
            process = line.split("=", 1)[1].strip()
    service_active = service == "active"
    process_running = bool(process)
    warnings: list[str] = []
    if not service_active and process_running:
        warnings.append("argus_service_inactive_process_running")
    elif service_active and not process_running:
        warnings.append("argus_service_active_process_missing")
    elif not service_active and not process_running:
        warnings.append("argus_not_running")
    result.update(
        {
            "service_active": service_active,
            "process_running": process_running,
            "status": "ok" if not warnings else "warn",
            "warnings": warnings,
            "detail": process,
        }
    )
    return result


def build_summary(
    agents: dict[str, str] = DEFAULT_AGENTS,
    *,
    heartbeats: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    heartbeats = _fleet_heartbeats() if heartbeats is None else heartbeats
    rows = [
        _attach_heartbeat(check_agent(name, host), heartbeats.get(name))
        for name, host in agents.items()
    ]
    unchecked = [
        str(row["agent"])
        for row in rows
        if "ssh_check_failed" in (row.get("warnings") or [])
    ]
    heartbeat_corroborated = [
        str(row["agent"])
        for row in rows
        if "ssh_check_failed" in (row.get("warnings") or []) and row.get("heartbeat_corroborated") is True
    ]
    unchecked_without_fresh_heartbeat = [
        agent for agent in unchecked
        if agent not in set(heartbeat_corroborated)
    ]
    warnings = [
        f"{row['agent']}:{warning}"
        for row in rows
        for warning in row.get("warnings", [])
        if warning != "ssh_check_failed"
    ]
    if warnings:
        status = "warn"
    elif unchecked_without_fresh_heartbeat:
        status = "partial"
    elif unchecked:
        status = "ok_corroborated"
    else:
        status = "ok"
    return {
        "status": status,
        "warnings": warnings,
        "unchecked_agents": unchecked,
        "heartbeat_corroborated_agents": heartbeat_corroborated,
        "unchecked_without_fresh_heartbeat": unchecked_without_fresh_heartbeat,
        "agents": rows,
    }


def print_text(summary: dict[str, Any]) -> None:
    print(f"agent services: {summary['status']}")
    if summary.get("unchecked_agents"):
        print("unchecked agents: " + ", ".join(summary["unchecked_agents"]))
    if summary.get("heartbeat_corroborated_agents"):
        print("heartbeat-corroborated unchecked agents: " + ", ".join(summary["heartbeat_corroborated_agents"]))
    for row in summary["agents"]:
        warnings = ",".join(row.get("warnings") or []) or "-"
        print(
            f"{row['agent']:8} host={row['host']:15} service={row['service_active']} "
            f"process={row['process_running']} heartbeat_age={row.get('heartbeat_age_sec')} "
            f"webhook_ok={row.get('webhook_ok')} warnings={warnings}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    summary = build_summary()
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print_text(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
