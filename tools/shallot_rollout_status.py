#!/usr/bin/env python3
"""Report whether the current one-at-a-time rollout soak may advance."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_STATE = ROOT / "docs" / "ROLLOUT_STATE.json"
DEFAULT_GPU_TEMP_LIMIT_C = 70.0
DEFAULT_ARGUS_ROLLBACK_TARGETS = ("host01", "host03", "host04", "host02")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _load_json_file(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _run_json(command: list[str]) -> dict[str, Any]:
    proc = subprocess.run(command, text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        return {
            "status": "command_failed",
            "returncode": proc.returncode,
            "stderr": proc.stderr.strip(),
            "command": " ".join(command),
        }
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {
            "status": "invalid_json",
            "stdout": proc.stdout[-1000:],
            "command": " ".join(command),
        }
    return data if isinstance(data, dict) else {"status": "invalid_json_type"}


def _run_shell(command: str) -> dict[str, Any]:
    proc = subprocess.run(command, text=True, capture_output=True, check=False, shell=True)
    return {
        "command": command,
        "returncode": proc.returncode,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
        "ok": proc.returncode == 0,
    }


def _query_gpu() -> dict[str, Any]:
    proc = subprocess.run(
        [
            "nvidia-smi",
            "--query-gpu=temperature.gpu,power.draw,memory.used,memory.total,utilization.gpu",
            "--format=csv,noheader,nounits",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        return {"available": False, "error": proc.stderr.strip()}
    gpus: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 5:
            continue
        try:
            gpus.append(
                {
                    "temp_c": float(parts[0]),
                    "power_w": float(parts[1]),
                    "memory_used_mb": float(parts[2]),
                    "memory_total_mb": float(parts[3]),
                    "util_pct": float(parts[4]),
                }
            )
        except ValueError:
            continue
    return {"available": True, "gpus": gpus}


def _soak_status(state: dict[str, Any], *, now: datetime) -> dict[str, Any]:
    started_at = _parse_time(state.get("soak_started_at"))
    hours = float(state.get("soak_hours") or 24.0)
    if started_at is None:
        return {
            "status": "missing_start",
            "complete": False,
            "elapsed_seconds": 0,
            "remaining_seconds": None,
            "deadline": None,
        }
    deadline = started_at.astimezone(timezone.utc) + timedelta(hours=hours)
    elapsed = max(0, int((now - started_at.astimezone(timezone.utc)).total_seconds()))
    remaining = max(0, int((deadline - now).total_seconds()))
    return {
        "status": "complete" if remaining == 0 else "running",
        "complete": remaining == 0,
        "started_at": started_at.astimezone(timezone.utc).isoformat(timespec="seconds"),
        "deadline": deadline.isoformat(timespec="seconds"),
        "elapsed_seconds": elapsed,
        "remaining_seconds": remaining,
        "hours_required": hours,
    }


def rollback_commands_for_state(state: dict[str, Any]) -> list[dict[str, str]]:
    active = str(state.get("active_component") or "")
    if active != "argus_network_egress":
        return []
    targets = state.get("rollback_targets") or DEFAULT_ARGUS_ROLLBACK_TARGETS
    commands: list[dict[str, str]] = []
    for target in targets:
        target_name = str(target)
        commands.append(
            {
                "target": target_name,
                "component": active,
                "command": (
                    "cd /home/user/security-shallots && "
                    f".venv/bin/python tools/argus_network_egress_rollout.py --target {target_name} --action rollback --json"
                ),
            }
        )
    return commands


def execute_rollback_commands(commands: list[dict[str, str]]) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for item in commands:
        plan_result = _run_shell(item["command"])
        result: dict[str, Any] = {
            "target": item.get("target"),
            "plan": plan_result,
            "rollback": None,
            "watch": None,
            "ok": False,
        }
        if not plan_result["ok"]:
            results.append(result)
            continue
        try:
            plan = json.loads(plan_result["stdout"])
        except json.JSONDecodeError as exc:
            result["plan_parse_error"] = str(exc)
            results.append(result)
            continue
        plan_commands = {
            str(command.get("step")): str(command.get("command"))
            for command in plan.get("commands") or []
            if isinstance(command, dict)
        }
        rollback_command = plan_commands.get("rollback_target")
        if not rollback_command:
            result["missing_step"] = "rollback_target"
            results.append(result)
            continue
        rollback_result = _run_shell(rollback_command)
        result["rollback"] = rollback_result
        if rollback_result["ok"] and plan_commands.get("watch_central"):
            result["watch"] = _run_shell(plan_commands["watch_central"])
        result["ok"] = rollback_result["ok"] and (result["watch"] is None or result["watch"]["ok"])
        results.append(result)
    return {
        "attempted": bool(results),
        "ok": bool(results) and all(item["ok"] for item in results),
        "results": results,
    }


def build_rollout_status(
    state: dict[str, Any],
    production_gate: dict[str, Any],
    fleet_top: dict[str, Any],
    alert_assessment: dict[str, Any],
    gpu: dict[str, Any],
    *,
    now: datetime | None = None,
    gpu_temp_limit_c: float = DEFAULT_GPU_TEMP_LIMIT_C,
    strict_warnings: bool = False,
) -> dict[str, Any]:
    checked_at = now or _now()
    soak = _soak_status(state, now=checked_at)
    fleet_summary = fleet_top.get("summary") or {}
    monitor_coverage = fleet_summary.get("monitor_coverage") or {}
    canaries = monitor_coverage.get("canary_monitors") or {}
    network_egress = canaries.get("network_egress") or {}
    readiness = alert_assessment.get("readiness") or {}

    production_blockers = [str(item) for item in production_gate.get("blockers") or []]
    production_warnings = [str(item) for item in production_gate.get("warnings") or []]
    fleet_blockers = [str(item) for item in fleet_summary.get("blockers") or []]
    fleet_warnings = [str(item) for item in fleet_summary.get("warnings") or []]
    alert_blockers = [str(item) for item in readiness.get("blockers") or []]
    alert_warnings = [str(item) for item in readiness.get("warnings") or []]
    collection_failures = []
    for name, payload in (
        ("production_gate", production_gate),
        ("fleet_top", fleet_top),
        ("alert_assessment", alert_assessment),
    ):
        if payload.get("status") in {"command_failed", "invalid_json", "invalid_json_type"}:
            collection_failures.append(f"collector:{name}:{payload['status']}")

    gpu_temps = [
        float(item["temp_c"])
        for item in gpu.get("gpus") or []
        if isinstance(item, dict) and item.get("temp_c") is not None
    ]
    max_gpu_temp = max(gpu_temps) if gpu_temps else None
    gpu_ok = max_gpu_temp is None or max_gpu_temp < gpu_temp_limit_c

    expected_agents = list(fleet_summary.get("expected_agents") or [])
    online_count = int(fleet_summary.get("online_count") or 0)
    expected_count = len(expected_agents)
    coverage_ok = (
        monitor_coverage.get("status") == "ok"
        and not fleet_blockers
        and expected_count > 0
        and online_count >= expected_count
    )
    policy = str(state.get("policy") or "one_component_24h_soak_auto_rollback")
    active_component = str(state.get("active_component") or "")
    broad_assessment = policy == "broad_enable_assess" or active_component == "broad_enable_all"
    expected_canary_agents = set(network_egress.get("expected_agents") or [])
    eligible_canary_agents = set(network_egress.get("promotion_eligible_agents") or [])
    network_egress_ready = bool(expected_canary_agents) and expected_canary_agents <= eligible_canary_agents

    blockers: list[str] = []
    if soak["status"] == "missing_start":
        blockers.append("soak:missing_start")
    blockers.extend(collection_failures)
    blockers.extend(f"production:{item}" for item in production_blockers)
    blockers.extend(f"fleet:{item}" for item in fleet_blockers)
    blockers.extend(f"alerts:{item}" for item in alert_blockers)
    if not gpu_ok:
        blockers.append(f"gpu:temp>={gpu_temp_limit_c:g}C")
    if not coverage_ok:
        blockers.append("fleet:coverage_not_ok")
    if not broad_assessment and not network_egress_ready:
        blockers.append("canary:network_egress_not_promotion_ready")
    if strict_warnings and (production_warnings or fleet_warnings or alert_warnings):
        blockers.append("warnings_present")

    if blockers:
        decision = "blocked"
    elif broad_assessment:
        decision = "whole_system_watch"
    elif not soak["complete"]:
        decision = "hold_soak"
    else:
        decision = "eligible_next_component"
    rollback_eligible = bool(blockers) and not collection_failures and soak["status"] != "missing_start"
    if collection_failures:
        rollback_reason = "collector_failure"
    elif soak["status"] == "missing_start":
        rollback_reason = "missing_soak_start"
    elif blockers:
        rollback_reason = "blocked_gate"
    else:
        rollback_reason = f"decision={decision}"

    return {
        "checked_at": checked_at.isoformat(timespec="seconds"),
        "decision": decision,
        "active_component": state.get("active_component"),
        "next_component": state.get("next_component"),
        "policy": policy,
        "soak": soak,
        "blockers": blockers,
        "production_gate": {
            "status": production_gate.get("status", "unknown"),
            "blockers": production_blockers,
            "warning_count": len(production_warnings),
        },
        "fleet": {
            "status": fleet_summary.get("status", "unknown"),
            "online_count": online_count,
            "expected_count": expected_count,
            "blockers": fleet_blockers,
            "warning_count": len(fleet_warnings),
            "network_egress_ready": network_egress_ready,
            "network_egress_required": not broad_assessment,
            "network_egress_eligible_agents": sorted(eligible_canary_agents),
        },
        "alerts": {
            "status": readiness.get("status", "unknown"),
            "raw_alerts": alert_assessment.get("raw_alerts"),
            "visible_non_synthetic": alert_assessment.get("visible_non_synthetic"),
            "incident_candidates": alert_assessment.get("incident_candidates") or [],
            "blockers": alert_blockers,
            "warning_count": len(alert_warnings),
        },
        "gpu": {
            "ok": gpu_ok,
            "max_temp_c": max_gpu_temp,
            "limit_c": gpu_temp_limit_c,
            "available": gpu.get("available", bool(gpu_temps)),
        },
        "warnings": {
            "production": production_warnings,
            "fleet": fleet_warnings,
            "alerts": alert_warnings,
        },
        "rollback": {
            "eligible": rollback_eligible,
            "reason": rollback_reason,
            "commands": rollback_commands_for_state(state) if rollback_eligible else [],
        },
    }


def _print_text(report: dict[str, Any]) -> None:
    soak = report["soak"]
    print(f"rollout: {report['decision']}")
    print(f"active component: {report.get('active_component') or 'unknown'}")
    print(f"next component: {report.get('next_component') or 'unknown'}")
    print(f"soak: {soak['status']} deadline={soak.get('deadline')} remaining={soak.get('remaining_seconds')}s")
    print(f"production gate: {report['production_gate']['status']} blockers={len(report['production_gate']['blockers'])} warnings={report['production_gate']['warning_count']}")
    print(f"fleet: {report['fleet']['online_count']}/{report['fleet']['expected_count']} online network_egress_ready={report['fleet']['network_egress_ready']}")
    print(f"alerts: visible={report['alerts']['visible_non_synthetic']} incidents={len(report['alerts']['incident_candidates'])} warnings={report['alerts']['warning_count']}")
    print(f"gpu: max_temp={report['gpu']['max_temp_c']}C limit={report['gpu']['limit_c']}C ok={report['gpu']['ok']}")
    if report["blockers"]:
        print("blockers:")
        for item in report["blockers"]:
            print(f"  - {item}")
    rollback = report.get("rollback") or {}
    if rollback.get("commands"):
        print("rollback commands:")
        for item in rollback["commands"]:
            print(f"  - {item['command']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-c", "--config", default="config.yaml")
    parser.add_argument("--hours", type=float, default=1.0)
    parser.add_argument("--state", default=str(DEFAULT_STATE))
    parser.add_argument("--gpu-temp-limit-c", type=float, default=DEFAULT_GPU_TEMP_LIMIT_C)
    parser.add_argument("--strict-warnings", action="store_true")
    parser.add_argument("--fail-on-hold", action="store_true")
    parser.add_argument(
        "--rollback-on-blocked",
        action="store_true",
        help="Execute the active component rollback commands only when the rollout gate is blocked.",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    python = sys.executable
    state = _load_json_file(Path(args.state))
    production_gate = _run_json([python, str(ROOT / "tools" / "shallot_production_gate.py"), "-c", args.config, "--hours", str(args.hours), "--json"])
    fleet_top = _run_json([python, str(ROOT / "tools" / "shallot_fleet_top.py"), "-c", args.config, "--summary-json"])
    alert_assessment = _run_json([python, str(ROOT / "tools" / "shallot_alert_assess.py"), "--hours", str(args.hours), "--summary-json"])
    report = build_rollout_status(
        state,
        production_gate,
        fleet_top,
        alert_assessment,
        _query_gpu(),
        gpu_temp_limit_c=args.gpu_temp_limit_c,
        strict_warnings=args.strict_warnings,
    )
    if args.rollback_on_blocked:
        if report["decision"] == "blocked" and report.get("rollback", {}).get("eligible"):
            report["auto_rollback"] = execute_rollback_commands(report["rollback"]["commands"])
        else:
            report["auto_rollback"] = {
                "attempted": False,
                "ok": True,
                "reason": report.get("rollback", {}).get("reason") or f"decision={report['decision']}",
            }
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_text(report)
    if report["decision"] == "blocked":
        return 2
    if args.fail_on_hold and report["decision"] == "hold_soak":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
