#!/usr/bin/env python3
"""Plan safe promotion or rollback for the Argus network egress canary."""

from __future__ import annotations

import argparse
import asyncio
import json
import shlex
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.shallot_fleet_top import CANARY_PROMOTION_MIN_EVENTS, EXPECTED_AGENTS  # noqa: E402


AGENT_SSH_TARGETS = {
    "host01": "192.168.0.172",
    "host03": "192.168.0.224",
    "host04": "192.168.0.129",
    "host02": "192.168.2.177",
}
AGENT_SSH_COPY_TARGETS = {
    "host03": "om@192.168.0.224",
    "host04": "om@192.168.0.129",
    "host02": "om@192.168.2.177",
}
CANARY_NAME = "network_egress"
CONTROLLER_PUBLIC_KEY_PATHS = (
    Path.home() / ".ssh" / "id_ed25519.pub",
    Path.home() / ".ssh" / "id_rsa.pub",
)
CONFIG_BLOCK = """[argus.network_egress]
enabled = true
poll_seconds = 60
suspicious_ports = [4444, 5555, 6666, 9001, 1234, 1337, 31337]
suspicious_processes = ["nc", "ncat", "netcat", "socat", "plink", "chisel", "ligolo", "ngrok"]
process_allowlist = ["qbittorrent", "qbittorrent-nox", "firefox", "chrome", "chromium", "brave", "curl", "wget", "syncthing", "tailscale", "tailscaled"]
"""


def _shell(command: str) -> str:
    return shlex.quote(command)


def _ssh(agent: str, command: str) -> str:
    target = AGENT_SSH_TARGETS.get(agent, agent)
    return f"ssh {shlex.quote(target)} {_shell(command)}"


def _target_command(target: str, command: str, target_access: dict[str, Any] | None = None) -> str:
    if target_access and target_access.get("local") is True:
        return command
    return _ssh(target, command)


def _ssh_copy_target(agent: str) -> str:
    return AGENT_SSH_COPY_TARGETS.get(agent, AGENT_SSH_TARGETS.get(agent, agent))


def _local_ipv4s() -> set[str]:
    try:
        completed = subprocess.run(
            ["ip", "-o", "-4", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"127.0.0.1"}
    ips = {"127.0.0.1"}
    if completed.returncode == 0:
        for line in completed.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and "/" in parts[3]:
                ips.add(parts[3].split("/", 1)[0])
    return ips


def _is_local_target(target: str, ssh_target: str) -> bool:
    hostname = socket.gethostname()
    short = hostname.split(".", 1)[0]
    names = {hostname, short, "localhost"}
    return target in names or ssh_target in names or ssh_target in _local_ipv4s()


def _check_local_target_access(target: str, ssh_target: str) -> dict[str, Any]:
    cmd = "hostname && test -r /etc/argus/config.toml && systemctl is-active argus-agent.service >/dev/null"
    completed = subprocess.run(
        ["bash", "-lc", cmd],
        capture_output=True,
        text=True,
        timeout=8,
        check=False,
    )
    detail = (completed.stderr or completed.stdout or "").strip()
    if completed.returncode == 0:
        return {
            "status": "ok",
            "target": target,
            "ssh_target": ssh_target,
            "detail": (completed.stdout or "").strip(),
            "local": True,
            "repair_commands": [],
        }
    return {
        "status": "local_check_failed",
        "target": target,
        "ssh_target": ssh_target,
        "detail": detail,
        "local": True,
        "repair_commands": [
            "test -r /etc/argus/config.toml && systemctl is-active argus-agent.service",
        ],
    }


def _controller_public_key() -> str | None:
    for path in CONTROLLER_PUBLIC_KEY_PATHS:
        try:
            text = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if text:
            return text
    return None


def _console_authorized_key_command(agent: str) -> str:
    public_key = _controller_public_key()
    if not public_key:
        return (
            f"On {agent} console, add this controller's SSH public key to "
            "/home/user/.ssh/authorized_keys, then rerun the rollout plan."
        )
    quoted_key = shlex.quote(public_key)
    install_script = (
        "set -euo pipefail; "
        "install -d -m 700 -o om -g om /home/user/.ssh; "
        "touch /home/user/.ssh/authorized_keys; "
        "chown om:om /home/user/.ssh/authorized_keys; "
        "chmod 600 /home/user/.ssh/authorized_keys; "
        f"grep -qxF {quoted_key} /home/user/.ssh/authorized_keys || "
        f"printf '%s\\n' {quoted_key} >> /home/user/.ssh/authorized_keys"
    )
    return f"On {agent} console, run: sudo bash -lc {shlex.quote(install_script)}"


def _sudo(script: str) -> str:
    return "sudo bash -lc " + _shell(script)


def check_target_access(target: str) -> dict[str, Any]:
    ssh_target = AGENT_SSH_TARGETS.get(target, target)
    if _is_local_target(target, ssh_target):
        return _check_local_target_access(target, ssh_target)
    cmd = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "StrictHostKeyChecking=accept-new",
        ssh_target,
        "hostname && test -r /etc/argus/config.toml && systemctl is-active argus-agent.service >/dev/null",
    ]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=8, check=False)
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "ssh_timeout",
            "target": target,
            "ssh_target": ssh_target,
            "detail": str(exc),
            "repair_commands": [_ssh(target, "hostname && systemctl is-active argus-agent.service")],
        }
    detail = (completed.stderr or completed.stdout or "").strip()
    if completed.returncode == 0:
        return {
            "status": "ok",
            "target": target,
            "ssh_target": ssh_target,
            "detail": (completed.stdout or "").strip(),
            "repair_commands": [],
        }
    if "Permission denied (publickey)" in detail:
        status = "ssh_publickey_denied"
    elif "Connection timed out" in detail or "No route to host" in detail:
        status = "ssh_unreachable"
    else:
        status = "ssh_check_failed"
    return {
        "status": status,
        "target": target,
        "ssh_target": ssh_target,
        "detail": detail,
        "repair_commands": [
            _console_authorized_key_command(target)
            if status == "ssh_publickey_denied"
            else f"ssh-copy-id {shlex.quote(_ssh_copy_target(target))}",
            _ssh(target, "hostname && systemctl is-active argus-agent.service"),
        ],
    }


def load_fleet_json(path: str | None, config: str) -> dict[str, Any]:
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    cmd = [sys.executable, str(ROOT / "tools" / "shallot_fleet_top.py"), "-c", config, "--summary-json"]
    try:
        completed = subprocess.run(cmd, check=True, text=True, capture_output=True)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or str(exc)).strip()
        raise RuntimeError(
            "could not load central fleet summary; run this on host01, pass -c with the central "
            "config path, or use --fleet-json from shallot_fleet_top.py --summary-json"
            f": {detail}"
        ) from exc
    return json.loads(completed.stdout)


def canary_status(fleet: dict[str, Any], canary_name: str = CANARY_NAME) -> dict[str, Any]:
    coverage = fleet.get("summary", {}).get("monitor_coverage", {})
    canaries = coverage.get("canary_monitors", {})
    item = canaries.get(canary_name)
    if not isinstance(item, dict):
        return {
            "name": canary_name,
            "found": False,
            "eligible_agents": [],
            "next_promotion_target": "unknown",
            "agents": {},
        }
    return {
        "name": canary_name,
        "found": True,
        "expected_agents": item.get("expected_agents", []),
        "present_agents": item.get("present_agents", []),
        "stable_agents": item.get("stable_agents", []),
        "eligible_agents": item.get("promotion_eligible_agents", []),
        "promotion_min_events": item.get("promotion_min_events", CANARY_PROMOTION_MIN_EVENTS),
        "next_promotion_target": item.get("next_promotion_target", "unknown"),
        "agents": item.get("agents", {}),
    }


def _target_state(fleet: dict[str, Any], target: str) -> dict[str, Any]:
    for agent in fleet.get("agents", []):
        if agent.get("agent") == target:
            return agent
    return {}


def _eligible_for_promotion(status: dict[str, Any]) -> bool:
    expected = set(str(agent) for agent in status.get("expected_agents") or [])
    eligible = set(str(agent) for agent in status.get("eligible_agents") or [])
    return bool(expected) and expected <= eligible


def _resource_blocking_warnings(target_state: dict[str, Any]) -> list[str]:
    warnings = target_state.get("warnings") or []
    return [str(warning) for warning in warnings if str(warning).startswith("disk>=")]


def build_plan(
    fleet: dict[str, Any],
    target: str,
    action: str,
    *,
    dry_run_seconds: int = 300,
    target_access: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if target not in EXPECTED_AGENTS:
        raise ValueError(f"unknown target agent: {target}")
    if action not in {"plan", "enable", "rollback"}:
        raise ValueError(f"unknown action: {action}")

    status = canary_status(fleet)
    target_state = _target_state(fleet, target)
    monitors = {
        item.strip()
        for item in str(target_state.get("monitors", "")).split(",")
        if item.strip()
    }
    already_enabled = CANARY_NAME in monitors
    allowed = action == "rollback" or _eligible_for_promotion(status)
    blockers: list[str] = []
    warnings: list[str] = []

    if not status["found"]:
        blockers.append("canary_status_missing")
    if action in {"plan", "enable"} and not _eligible_for_promotion(status):
        blockers.append(f"canary_not_promotion_ready:{status['next_promotion_target']}")
    if action in {"plan", "enable"} and already_enabled and target not in status.get("expected_agents", []):
        warnings.append(f"{target}:network_egress_already_enabled_outside_expected_canary")
    if not target_state:
        blockers.append(f"{target}:no_recent_heartbeat")
    elif target_state.get("webhook_ok") is not True:
        blockers.append(f"{target}:webhook_not_healthy")
    if action in {"plan", "enable"} and target_state:
        for warning in _resource_blocking_warnings(target_state):
            blockers.append(f"target_resource_warning:{target}:{warning}")
    if target_access and target_access.get("status") != "ok":
        blockers.append(f"target_access:{target}:{target_access.get('status', 'unknown')}")

    backup = f"/etc/argus/config.toml.bak-network-egress-$(date -u +%Y%m%dT%H%M%SZ)"
    repair_access_cmd = "\n".join(target_access.get("repair_commands") or []) if target_access else ""
    dry_run_cmd = _target_command(
        target,
        "cd /home/user/security-shallots && "
        f".venv/bin/python tools/argus_egress_canary.py --duration {int(dry_run_seconds)} --interval 30 --fail-on-signal",
        target_access,
    )
    enable_script = (
        "set -euo pipefail\n"
        f"backup={backup}\n"
        "cp /etc/argus/config.toml \"$backup\"\n"
        "systemctl stop argus-agent.service\n"
        "python3 - <<'PY'\n"
        "from pathlib import Path\n"
        "path = Path('/etc/argus/config.toml')\n"
        "text = path.read_text()\n"
        "block = '''" + CONFIG_BLOCK + "'''\n"
        "if '[argus.network_egress]' not in text:\n"
        "    path.write_text(text.rstrip() + '\\n\\n' + block)\n"
        "PY\n"
        "systemctl start argus-agent.service\n"
        "systemctl is-active --quiet argus-agent.service\n"
        "echo \"$backup\""
    )
    rollback_script = (
        "set -euo pipefail\n"
        "latest=$(ls -1t /etc/argus/config.toml.bak-network-egress-* 2>/dev/null | head -n 1)\n"
        "test -n \"$latest\"\n"
        "systemctl stop argus-agent.service\n"
        "cp \"$latest\" /etc/argus/config.toml\n"
        "systemctl start argus-agent.service\n"
        "systemctl is-active --quiet argus-agent.service\n"
        "echo \"$latest\""
    )

    commands = [
        {
            "step": "repair_target_access",
            "purpose": "Restore SSH access needed for dry-run, enablement, or rollback on the target.",
            "command": repair_access_cmd or f"ssh-copy-id {shlex.quote(_ssh_copy_target(target))}",
        },
        {
            "step": "dry_run_target",
            "purpose": "Confirm the target would not emit a noisy signal before daemon enablement.",
            "command": dry_run_cmd,
        },
        {
            "step": "enable_target",
            "purpose": "Backup config, stop Argus, add the monitor block idempotently, then restart Argus.",
            "command": _target_command(target, _sudo(enable_script), target_access),
        },
        {
            "step": "watch_central",
            "purpose": "Verify heartbeat, webhook, monitor coverage, and alert quietness after enablement.",
            "command": (
                "cd /home/user/security-shallots && "
                ".venv/bin/python tools/shallot_fleet_top.py --summary-json && "
                ".venv/bin/python tools/shallot_alert_assess.py --hours 1 --summary-json"
            ),
        },
        {
            "step": "rollback_target",
            "purpose": "Restore the newest network-egress backup and restart Argus.",
            "command": _target_command(target, _sudo(rollback_script), target_access),
        },
    ]
    plan_allowed = allowed and not blockers
    if action == "rollback":
        selected_steps = ["rollback_target", "watch_central"]
    elif not plan_allowed:
        selected_steps = ["dry_run_target", "watch_central"]
    elif action == "enable":
        selected_steps = ["dry_run_target", "enable_target", "watch_central"]
    else:
        selected_steps = ["dry_run_target", "enable_target", "watch_central", "rollback_target"]
    command_by_step = {cmd["step"]: cmd for cmd in commands}
    access_blocked = any(str(blocker).startswith("target_access:") for blocker in blockers)

    return {
        "action": action,
        "target": target,
        "dry_run_only": True,
        "allowed": plan_allowed,
        "blockers": blockers,
        "warnings": warnings,
        "target_access": target_access or {"status": "not_checked", "target": target},
        "canary": status,
        "target_state": {
            "agent": target,
            "seen": bool(target_state),
            "age_sec": target_state.get("age_sec"),
            "webhook_ok": target_state.get("webhook_ok"),
            "monitors": sorted(monitors),
            "already_enabled": already_enabled,
            "warnings": target_state.get("warnings", []),
        },
        "commands": [command_by_step[step] for step in (["repair_target_access"] if access_blocked else []) + selected_steps],
    }


def _print_human(plan: dict[str, Any]) -> None:
    print(
        f"network egress rollout: action={plan['action']} target={plan['target']} "
        f"allowed={plan['allowed']} dry_run_only={plan['dry_run_only']}"
    )
    print(f"canary next: {plan['canary'].get('next_promotion_target')}")
    if plan["blockers"]:
        print("blockers:")
        for blocker in plan["blockers"]:
            print(f"  {blocker}")
    if plan["warnings"]:
        print("warnings:")
        for warning in plan["warnings"]:
            print(f"  {warning}")
    print("commands:")
    for command in plan["commands"]:
        print(f"  # {command['step']}: {command['purpose']}")
        print(f"  {command['command']}")


async def main_async() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=EXPECTED_AGENTS, help="Agent to promote or roll back")
    parser.add_argument("--action", choices=("plan", "enable", "rollback"), default="plan")
    parser.add_argument("--fleet-json", help="Read fleet summary JSON from a file instead of running shallot_fleet_top")
    parser.add_argument("-c", "--config", default="config.yaml", help="Central Shallots config path")
    parser.add_argument("--dry-run-seconds", type=int, default=300)
    parser.add_argument("--skip-access-check", action="store_true", help="Do not probe target SSH access")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    try:
        fleet = load_fleet_json(args.fleet_json, args.config)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    target_access = None if args.skip_access_check else check_target_access(args.target)
    plan = build_plan(
        fleet,
        args.target,
        args.action,
        dry_run_seconds=args.dry_run_seconds,
        target_access=target_access,
    )
    if args.json:
        print(json.dumps(plan, indent=2, sort_keys=True))
    else:
        _print_human(plan)
    return 0


def main() -> int:
    return asyncio.run(main_async())


if __name__ == "__main__":
    raise SystemExit(main())
