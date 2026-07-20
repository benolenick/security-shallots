#!/usr/bin/env python3
"""Render non-destructive cleanup guidance for agent resource blockers."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER_PUBLIC_KEY_PATHS = (
    Path.home() / ".ssh" / "id_ed25519.pub",
    Path.home() / ".ssh" / "id_rsa.pub",
)
HOST03_EVIDENCE = {
    "agent": "host03",
    "host": "192.168.0.224",
    "blocker": "disk>=80%",
    "direct_df": "/dev/sda2 3299G size, 2781G used, 351G available, 89% mounted on /",
    "cleanup_target": {
        "goal": "Get / below 80% before promoting network_egress on host03.",
        "current_free": "351G",
        "target_extra_free": "200G",
        "rationale": "Direct df shows 89% used on a 3299G root filesystem. Freeing about 142G reaches 80%; 200G leaves a buffer for normal churn and reserved-block differences.",
    },
    "candidates": [
        {
            "path": "/home/user/backups",
            "observed_size": "182G",
            "risk": "medium",
            "priority": 1,
            "reason": "Old host03-projects tarballs were observed here; likely removable only after confirming backup retention requirements.",
            "first_action": "List dated archives and keep the newest known-good backups before deleting or moving older copies.",
            "inspect_commands": [
                "ssh 192.168.0.224 'find /home/user/backups -maxdepth 2 -type f -printf \"%TY-%Tm-%Td %12s %p\\n\" | sort'",
                "ssh 192.168.0.224 'du -sh /home/user/backups/* 2>&1 | sort -h'",
            ],
        },
        {
            "path": "/home/user/Downloads",
            "observed_size": "109G",
            "risk": "medium",
            "priority": 2,
            "reason": "Usually user-managed files; inspect before deleting.",
            "first_action": "List largest files and move/delete only confirmed disposable downloads.",
            "inspect_commands": [
                "ssh 192.168.0.224 'find /home/user/Downloads -xdev -type f -printf \"%12s %TY-%Tm-%Td %p\\n\" 2>&1 | sort -nr | head -80'",
                "ssh 192.168.0.224 'du -sh /home/user/Downloads/* 2>&1 | sort -h'",
            ],
        },
        {
            "path": "/home/user/ComfyUI",
            "observed_size": "113G",
            "risk": "medium",
            "priority": 3,
            "reason": "Likely model/cache artifacts; safe cleanup depends on active workflows.",
            "first_action": "Inspect model/checkpoint/cache subdirectories and move unused artifacts off the root filesystem.",
            "inspect_commands": [
                "ssh 192.168.0.224 'du -sh /home/user/ComfyUI/* 2>&1 | sort -h'",
                "ssh 192.168.0.224 'find /home/user/ComfyUI -xdev -type f \\( -name \"*.safetensors\" -o -name \"*.ckpt\" -o -name \"*.pt\" -o -name \"*.pth\" \\) -printf \"%12s %TY-%Tm-%Td %p\\n\" 2>&1 | sort -nr | head -80'",
            ],
        },
        {
            "path": "/home/user/chemister_db",
            "observed_size": "400G",
            "risk": "high",
            "priority": 8,
            "reason": "Large live database/index area; do not delete without owner confirmation.",
            "first_action": "Move, archive, or prune only with an application-specific retention plan.",
            "inspect_commands": [
                "ssh 192.168.0.224 'du -sh /home/user/chemister_db/* 2>&1 | sort -h | tail -40'",
            ],
        },
        {
            "path": "/home/user/chemister_data",
            "observed_size": "401G",
            "risk": "high",
            "priority": 9,
            "reason": "Large live corpus/index area; do not delete without owner confirmation.",
            "first_action": "Move, archive, or prune only with an application-specific retention plan.",
            "inspect_commands": [
                "ssh 192.168.0.224 'du -sh /home/user/chemister_data/* 2>&1 | sort -h | tail -40'",
            ],
        },
    ],
}


def load_fleet_summary(config: str = "config.yaml") -> dict[str, Any]:
    try:
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools" / "shallot_fleet_top.py"),
                "-c",
                config,
                "--summary-json",
            ],
            text=True,
            capture_output=True,
            timeout=15,
        )
    except Exception as exc:
        return {"status": "unknown", "error": str(exc)}
    if completed.returncode != 0:
        return {"status": "unknown", "error": (completed.stderr or completed.stdout).strip()}
    try:
        data = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        return {"status": "unknown", "error": f"invalid fleet json: {exc}"}
    return data if isinstance(data, dict) else {"status": "unknown", "error": "fleet json was not an object"}


def fleet_agent_state(fleet: dict[str, Any] | None, agent: str) -> dict[str, Any]:
    if not isinstance(fleet, dict):
        return {}
    for row in fleet.get("agents") or []:
        if isinstance(row, dict) and row.get("agent") == agent:
            return dict(row)
    return {}


def inspect_host_hygiene(host: str) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=5",
                host,
                "stat -c '%a %U:%G %F' /dev/null && ls -l /dev/null",
            ],
            text=True,
            capture_output=True,
            timeout=8,
        )
    except Exception as exc:
        return {"status": "unknown", "error": str(exc)}
    if completed.returncode != 0:
        return {
            "status": "unknown",
            "error": (completed.stderr or completed.stdout).strip(),
        }
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    mode = ""
    owner = ""
    file_type = ""
    if lines:
        parts = lines[0].split(maxsplit=2)
        mode = parts[0] if len(parts) > 0 else ""
        owner = parts[1] if len(parts) > 1 else ""
        file_type = parts[2] if len(parts) > 2 else ""
    return {
        "status": "ok" if mode == "666" else "warn",
        "mode": mode,
        "owner": owner,
        "file_type": file_type,
        "ls": lines[1] if len(lines) > 1 else "",
    }


def inspect_disk_status(host: str) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=5",
                host,
                "df -BG --output=source,size,used,avail,pcent,target / | tail -n +2",
            ],
            text=True,
            capture_output=True,
            timeout=8,
        )
    except Exception as exc:
        return {"status": "unknown", "error": str(exc)}
    if completed.returncode != 0:
        return {
            "status": "unknown",
            "error": (completed.stderr or completed.stdout).strip(),
        }
    line = completed.stdout.strip()
    parts = line.split()
    if len(parts) < 6:
        return {"status": "unknown", "error": f"unexpected df output: {line}"}
    source, size_raw, used_raw, avail_raw, pcent_raw = parts[:5]
    target = " ".join(parts[5:])

    def parse_gib(raw: str) -> int | None:
        raw = raw.strip().upper()
        if not raw.endswith("G"):
            return None
        try:
            return int(float(raw[:-1]))
        except ValueError:
            return None

    size_gb = parse_gib(size_raw)
    used_gb = parse_gib(used_raw)
    avail_gb = parse_gib(avail_raw)
    try:
        used_pct = float(pcent_raw.rstrip("%"))
    except ValueError:
        used_pct = None
    status = "ok"
    if used_pct is None:
        status = "unknown"
    elif used_pct >= 80.0:
        status = "blocked"
    elif used_pct >= 75.0:
        status = "watch"
    return {
        "status": status,
        "source": source,
        "size_gb": size_gb,
        "used_gb": used_gb,
        "avail_gb": avail_gb,
        "used_pct": used_pct,
        "mount": target,
        "raw": line,
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


def _host03_console_key_repair_command() -> str:
    public_key = _controller_public_key()
    if not public_key:
        return (
            "On host03 console, add host01's SSH public key to "
            "/home/user/.ssh/authorized_keys, then rerun this plan."
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
    return f"On host03 console, run: sudo bash -lc {shlex.quote(install_script)}"


def _cleanup_target(disk_status: dict[str, Any] | None) -> tuple[str, dict[str, str]]:
    fallback = HOST03_EVIDENCE["cleanup_target"]
    if not disk_status or disk_status.get("status") == "unknown":
        return HOST03_EVIDENCE["direct_df"], dict(fallback)
    size_gb = disk_status.get("size_gb")
    used_gb = disk_status.get("used_gb")
    avail_gb = disk_status.get("avail_gb")
    used_pct = disk_status.get("used_pct")
    source = disk_status.get("source") or "unknown"
    mount = disk_status.get("mount") or "/"
    direct_df = (
        f"{source} {size_gb}G size, {used_gb}G used, {avail_gb}G available, "
        f"{used_pct:g}% mounted on {mount}"
    )
    if isinstance(size_gb, int) and isinstance(used_gb, int):
        target_used = int(size_gb * 0.80)
        needed = max(0, used_gb - target_used)
        target_extra = max(50, int(((needed + 49) // 50) * 50))
        rationale = (
            f"Live df shows {used_pct:g}% used on a {size_gb}G root filesystem. "
            f"Freeing about {needed}G reaches 80%; {target_extra}G leaves a rounded buffer for normal churn."
        )
    else:
        target_extra = 200
        rationale = (
            f"Live df shows {used_pct:g}% used, but size parsing was incomplete. "
            "Use the verification commands before deleting data."
        )
    return direct_df, {
        "goal": "Get / below 80% before promoting network_egress on host03.",
        "current_free": f"{avail_gb}G" if isinstance(avail_gb, int) else "unknown",
        "target_extra_free": f"{target_extra}G",
        "rationale": rationale,
    }


def _fleet_disk_status(fleet_agent: dict[str, Any]) -> dict[str, Any] | None:
    if not fleet_agent:
        return None
    used_pct = fleet_agent.get("disk_used_pct")
    free_gb = fleet_agent.get("disk_free_gb")
    warnings = [str(item) for item in fleet_agent.get("warnings") or []]
    try:
        used_pct_f = float(used_pct)
    except (TypeError, ValueError):
        used_pct_f = None
    try:
        free_gb_f = float(free_gb)
    except (TypeError, ValueError):
        free_gb_f = None
    if used_pct_f is None and free_gb_f is None and not warnings:
        return None
    status = "unknown"
    if any(item.startswith("disk>=") for item in warnings):
        status = "blocked"
    elif used_pct_f is not None:
        if used_pct_f >= 80.0:
            status = "blocked"
        elif used_pct_f >= 75.0:
            status = "watch"
        else:
            status = "ok"
    return {
        "status": status,
        "source": "fleet_heartbeat",
        "used_pct": used_pct_f,
        "avail_gb": free_gb_f,
        "warnings": warnings,
        "last_seen": fleet_agent.get("last_seen"),
        "age_sec": fleet_agent.get("age_sec"),
        "raw": f"fleet heartbeat disk_used_pct={used_pct_f} disk_free_gb={free_gb_f} warnings={warnings}",
    }


def _host_hygiene_messages(state: dict[str, Any] | None) -> tuple[dict[str, Any], list[str]]:
    if not state:
        status = {"status": "unknown"}
        return status, [
            "host03 /dev/null should be crw-rw-rw- / mode 666; live state was not checked in this plan.",
            "Verify before heavy cleanup inspection because commands using shell redirection can fail if /dev/null regresses.",
            "Repair command, when an operator is ready to authenticate: ssh 192.168.0.224 'sudo chmod 666 /dev/null && ls -l /dev/null'.",
        ]
    status = dict(state)
    if status.get("status") == "ok":
        return status, [
            f"host03 /dev/null verified ok: mode={status.get('mode', 'unknown')} owner={status.get('owner', 'unknown')} type={status.get('file_type', 'unknown')}.",
            "Normal shell redirection should work for cleanup inspection commands.",
        ]
    if status.get("mode"):
        return status, [
            f"host03 /dev/null is not healthy: mode={status.get('mode')} owner={status.get('owner', 'unknown')} type={status.get('file_type', 'unknown')}.",
            "Fix /dev/null before heavy cleanup inspection because commands using 2>/dev/null can fail for om on host03.",
            "Repair command, when an operator is ready to authenticate: ssh 192.168.0.224 'sudo chmod 666 /dev/null && ls -l /dev/null'.",
        ]
    return status, [
        f"host03 /dev/null live check could not complete: {status.get('error', 'unknown error')}.",
        "Verify /dev/null manually before cleanup inspection if shell redirects behave strangely.",
    ]


def _access_diagnosis(host_hygiene: dict[str, Any] | None, disk_status: dict[str, Any] | None) -> dict[str, Any]:
    errors = [
        str(item.get("error") or "")
        for item in (host_hygiene or {}, disk_status or {})
        if isinstance(item, dict) and item.get("error")
    ]
    joined = " ".join(errors).lower()
    if "permission denied" in joined and "publickey" in joined:
        status = "ssh_publickey_denied"
        detail = "Live host03 checks cannot run from this host because SSH public-key authentication is denied."
    elif errors:
        status = "ssh_live_check_failed"
        detail = "Live host03 checks failed; inspect the recorded SSH error before relying on live cleanup numbers."
    else:
        status = "ok"
        detail = "Live host03 checks completed or were intentionally skipped."
    return {
        "status": status,
        "detail": detail,
        "errors": errors,
        "repair_commands": [
            _host03_console_key_repair_command(),
            "ssh 192.168.0.172 'ssh 192.168.0.224 \"hostname && df -h /\"'",
        ]
        if status == "ssh_publickey_denied"
        else [],
    }


def build_plan(
    agent: str,
    *,
    host_hygiene: dict[str, Any] | None = None,
    disk_status: dict[str, Any] | None = None,
    fleet: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if agent != "host03":
        return {
            "agent": agent,
            "status": "unknown_agent",
            "blockers": [],
            "candidates": [],
            "verify_commands": [],
        }
    host_hygiene_status, host_hygiene_messages = _host_hygiene_messages(host_hygiene)
    fleet_state = fleet_agent_state(fleet, agent)
    fleet_disk = _fleet_disk_status(fleet_state)
    effective_disk = disk_status
    disk_source = "direct_ssh"
    if fleet_disk and fleet_disk.get("status") in {"ok", "watch"}:
        effective_disk = fleet_disk
        disk_source = "fleet_heartbeat"
    elif (
        (not effective_disk or effective_disk.get("status") == "unknown")
        and fleet_disk
        and fleet_disk.get("status") != "unknown"
    ):
        effective_disk = fleet_disk
        disk_source = "fleet_heartbeat"
    direct_df, cleanup_target = _cleanup_target(effective_disk)
    target_extra_free = cleanup_target.get("target_extra_free", HOST03_EVIDENCE["cleanup_target"]["target_extra_free"])
    access = _access_diagnosis(host_hygiene_status, disk_status)
    active_disk_blocker = bool(effective_disk and effective_disk.get("status") == "blocked")
    status = "blocked" if active_disk_blocker else ("watch" if effective_disk and effective_disk.get("status") == "watch" else "ready")
    blockers = [HOST03_EVIDENCE["blocker"]] if active_disk_blocker else []
    recommended_sequence = []
    if access["status"] != "ok":
        recommended_sequence.append(
            f"Restore live SSH visibility first: {access['detail']} This keeps cleanup targets based on current df instead of fallback evidence."
        )
    if active_disk_blocker:
        recommended_sequence.extend(
            [
                "Run the inspection commands for priority 1-3 candidates first.",
                f"Try to free or move roughly {target_extra_free} from backups/downloads/models before touching live chemister data.",
                "Re-run df and the rollout planner after each cleanup batch; stop once the gate clears.",
            ]
        )
    else:
        recommended_sequence.extend(
            [
                "Do not run cleanup for rollout readiness unless the live gate reports a resource blocker again.",
                "Keep the candidate list as cleanup context only; the current blocker to clear is SSH access for Host03 rollout.",
                "Re-run the rollout planner after restoring SSH key access.",
            ]
        )
    return {
        "agent": HOST03_EVIDENCE["agent"],
        "host": HOST03_EVIDENCE["host"],
        "status": status,
        "blockers": blockers,
        "direct_df": direct_df,
        "disk_status": disk_status or {"status": "unknown"},
        "fleet_disk_status": fleet_disk or {"status": "unknown"},
        "effective_disk_source": disk_source,
        "access_diagnosis": access,
        "cleanup_target": cleanup_target,
        "candidates": sorted(HOST03_EVIDENCE["candidates"], key=lambda item: int(item.get("priority", 99))),
        "recommended_sequence": recommended_sequence,
        "verify_commands": [
            "ssh 192.168.0.224 'df -h /'",
            "ssh 192.168.0.224 'for p in /home/user/backups /home/user/Downloads /home/user/ComfyUI /home/user/chemister_db /home/user/chemister_data; do [ -e \"$p\" ] && du -sh \"$p\"; done'",
            "ssh 192.168.0.224 'ls -l /dev/null; stat -c \"%a %U:%G %F\" /dev/null'",
            *access["repair_commands"],
            "cd /home/user/security-shallots",
            ".venv/bin/python tools/argus_network_egress_rollout.py --target host03 --action plan",
            ".venv/bin/python tools/shallot_production_gate.py",
        ],
        "success_criteria": [
            "host03 root filesystem is below 80% used, or at minimum below the rollout blocker threshold reported by argus_network_egress_rollout.",
            "argus_network_egress_rollout --target host03 --action plan no longer reports target_resource_warning for disk.",
            "production_gate.blockers no longer contains rollout:host03:disk>=80% or rollout:host03:disk>=85%.",
            "/dev/null on host03 is mode 666 so normal shell redirection and cleanup inspection commands work for om.",
        ],
        "safety": [
            "Do not delete live databases or indexes without owner confirmation.",
            "Prefer moving removable backups/downloads/models off the root filesystem first.",
            "After cleanup, require the rollout planner to clear target_resource_warning before promoting network_egress.",
        ],
        "host_hygiene_status": host_hygiene_status,
        "host_hygiene": host_hygiene_messages,
    }


def print_text(plan: dict[str, Any]) -> None:
    print(f"resource cleanup plan: {plan['agent']} status={plan['status']}")
    if plan.get("host"):
        print(f"host: {plan['host']}")
    for blocker in plan.get("blockers", []):
        print(f"blocker: {blocker}")
    if plan.get("direct_df"):
        print(f"direct df: {plan['direct_df']}")
    if plan.get("cleanup_target"):
        target = plan["cleanup_target"]
        print("cleanup target:")
        print(f"  goal: {target['goal']}")
        print(f"  current free: {target['current_free']}")
        print(f"  target extra free: {target['target_extra_free']}")
        print(f"  rationale: {target['rationale']}")
    if plan.get("access_diagnosis"):
        access = plan["access_diagnosis"]
        print("access diagnosis:")
        print(f"  status: {access.get('status', 'unknown')}")
        print(f"  detail: {access.get('detail', 'unknown')}")
        for cmd in access.get("repair_commands", []):
            print(f"  repair: {cmd}")
    print("candidates:")
    for item in plan.get("candidates", []):
        print(f"  - priority {item.get('priority', '?')}: {item['path']} {item['observed_size']} risk={item['risk']}")
        print(f"    reason: {item['reason']}")
        print(f"    first action: {item['first_action']}")
        for cmd in item.get("inspect_commands", []):
            print(f"    inspect: {cmd}")
    if plan.get("recommended_sequence"):
        print("recommended sequence:")
        for item in plan["recommended_sequence"]:
            print(f"  - {item}")
    print("verify:")
    for cmd in plan.get("verify_commands", []):
        print(f"  $ {cmd}")
    if plan.get("success_criteria"):
        print("success criteria:")
        for item in plan["success_criteria"]:
            print(f"  - {item}")
    print("safety:")
    for item in plan.get("safety", []):
        print(f"  - {item}")
    if plan.get("host_hygiene"):
        print("host hygiene:")
        for item in plan["host_hygiene"]:
            print(f"  - {item}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", default="host03")
    parser.add_argument("-c", "--config", default="config.yaml")
    parser.add_argument("--skip-live-host-hygiene", action="store_true")
    parser.add_argument("--skip-live-disk", action="store_true")
    parser.add_argument("--skip-fleet", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--live-json", action="store_true", help="Alias for --json with live checks enabled by default.")
    args = parser.parse_args()

    host_hygiene = None
    disk_status = None
    if args.agent == "host03":
        if not args.skip_live_host_hygiene:
            host_hygiene = inspect_host_hygiene(HOST03_EVIDENCE["host"])
        if not args.skip_live_disk:
            disk_status = inspect_disk_status(HOST03_EVIDENCE["host"])
    fleet = None if args.skip_fleet else load_fleet_summary(args.config)
    plan = build_plan(args.agent, host_hygiene=host_hygiene, disk_status=disk_status, fleet=fleet)
    if args.json or args.live_json:
        print(json.dumps(plan, indent=2))
    else:
        print_text(plan)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
