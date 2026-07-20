from __future__ import annotations

import platform
import os
import shutil
import socket
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass(slots=True)
class ArgusEvent:
    version: int
    source: str
    timestamp: str
    host: str
    event_type: str
    severity: str
    confidence: float
    state: str
    title: str
    description: str
    category: str | None = None
    mitre_attack: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    actions_taken: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def make_state_change_event(host: str, old_state: str, new_state: str, reason: str) -> ArgusEvent:
    sev = "low" if new_state in {"DISARMED", "ARMED_HOME"} else "medium"
    if new_state == "LOCKDOWN":
        sev = "critical"
    return ArgusEvent(
        version=1,
        source="argus",
        timestamp=utc_now_iso(),
        host=host,
        event_type="state_change",
        severity=sev,
        confidence=1.0,
        state=new_state,
        title=f"State changed: {old_state} -> {new_state}",
        description=f"Argus transitioned from {old_state} to {new_state} ({reason})",
        category="state_management",
        details={"from": old_state, "to": new_state, "reason": reason},
    )


def _local_ip_address() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.2)
            sock.connect(("1.1.1.1", 80))
            return str(sock.getsockname()[0])
    except OSError:
        return ""


def _linux_meminfo() -> dict[str, int]:
    out: dict[str, int] = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                key, _, rest = line.partition(":")
                if key in {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}:
                    raw = rest.strip().split()[0]
                    out[key] = int(raw) * 1024
    except (OSError, ValueError):
        pass
    return out


def _uptime_seconds() -> int:
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as f:
            return int(float(f.read().split()[0]))
    except (OSError, ValueError, IndexError):
        return 0


def _float_or_none(value: str) -> float | None:
    try:
        return float(value.strip())
    except (TypeError, ValueError):
        return None


def _cpu_times() -> tuple[int, int] | None:
    try:
        with open("/proc/stat", "r", encoding="utf-8") as f:
            fields = f.readline().split()
    except OSError:
        return None
    if len(fields) < 5 or fields[0] != "cpu":
        return None
    try:
        values = [int(value) for value in fields[1:]]
    except ValueError:
        return None
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return sum(values), idle


def _cpu_util_pct() -> float | None:
    first = _cpu_times()
    if first is None:
        return None
    time.sleep(0.1)
    second = _cpu_times()
    if second is None:
        return None
    total_delta = second[0] - first[0]
    idle_delta = second[1] - first[1]
    if total_delta <= 0:
        return None
    return round(max(0.0, min(100.0, (total_delta - idle_delta) / total_delta * 100)), 1)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _temp_input_c(path: Path) -> float | None:
    raw = _read_text(path)
    if not raw:
        return None
    value = _float_or_none(raw)
    if value is None:
        return None
    if value > 1000:
        value /= 1000
    if 0 <= value <= 130:
        return round(value, 1)
    return None


def _cpu_temperature() -> dict[str, Any]:
    preferred_tokens = (
        "package",
        "tctl",
        "tdie",
        "cpu",
        "core 0",
        "core",
        "composite",
    )
    candidates: list[tuple[int, float, str]] = []
    for input_path in Path("/sys/class/hwmon").glob("hwmon*/temp*_input"):
        temp_c = _temp_input_c(input_path)
        if temp_c is None:
            continue
        label_path = input_path.with_name(input_path.name.replace("_input", "_label"))
        label = _read_text(label_path) or _read_text(input_path.parent / "name") or input_path.name
        label_l = label.lower()
        priority = next((index for index, token in enumerate(preferred_tokens) if token in label_l), 99)
        if priority < 99 or not candidates:
            candidates.append((priority, temp_c, label))
    if candidates:
        priority, temp_c, label = sorted(candidates, key=lambda item: (item[0], -item[1]))[0]
        return {"cpu_temp_c": temp_c, "cpu_temp_label": label}

    thermal_values: list[tuple[float, str]] = []
    for input_path in Path("/sys/class/thermal").glob("thermal_zone*/temp"):
        temp_c = _temp_input_c(input_path)
        if temp_c is None:
            continue
        label = _read_text(input_path.parent / "type") or input_path.parent.name
        thermal_values.append((temp_c, label))
    if thermal_values:
        temp_c, label = max(thermal_values, key=lambda item: item[0])
        return {"cpu_temp_c": temp_c, "cpu_temp_label": label}
    return {}


def _nvidia_gpus() -> list[dict[str, Any]]:
    query = (
        "index,name,temperature.gpu,utilization.gpu,memory.used,memory.total,"
        "power.draw,power.limit"
    )
    try:
        completed = subprocess.run(
            [
                "nvidia-smi",
                f"--query-gpu={query}",
                "--format=csv,noheader,nounits",
            ],
            text=True,
            capture_output=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if completed.returncode != 0:
        return []

    gpus: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        parts = [part.strip() for part in line.split(",")]
        if len(parts) != 8:
            continue
        index, name, temp, util, mem_used, mem_total, power_draw, power_limit = parts
        try:
            gpu: dict[str, Any] = {
                "index": int(index),
                "name": name,
            }
        except ValueError:
            continue
        temp_value = _float_or_none(temp)
        util_value = _float_or_none(util)
        mem_used_value = _float_or_none(mem_used)
        mem_total_value = _float_or_none(mem_total)
        power_draw_value = _float_or_none(power_draw)
        power_limit_value = _float_or_none(power_limit)
        if temp_value is not None:
            gpu["temp_c"] = round(temp_value, 1)
        if util_value is not None:
            gpu["util_pct"] = round(util_value, 1)
        if mem_used_value is not None:
            gpu["mem_used_mb"] = round(mem_used_value)
        if mem_total_value is not None:
            gpu["mem_total_mb"] = round(mem_total_value)
        if mem_used_value is not None and mem_total_value:
            gpu["mem_used_pct"] = round(mem_used_value / mem_total_value * 100, 1)
        if power_draw_value is not None:
            gpu["power_w"] = round(power_draw_value, 1)
        if power_limit_value is not None:
            gpu["power_limit_w"] = round(power_limit_value, 1)
        if power_draw_value is not None and power_limit_value:
            gpu["power_pct"] = round(power_draw_value / power_limit_value * 100, 1)
        gpus.append(gpu)
    return gpus


def _host_metrics() -> dict[str, Any]:
    metrics: dict[str, Any] = {
        "pid": os.getpid(),
        "cpu_count": os.cpu_count() or 0,
        "uptime_seconds": _uptime_seconds(),
    }
    try:
        load1, load5, load15 = os.getloadavg()
        metrics["load1"] = round(float(load1), 3)
        metrics["load5"] = round(float(load5), 3)
        metrics["load15"] = round(float(load15), 3)
        if metrics["cpu_count"]:
            metrics["load_per_core"] = round(float(load1) / float(metrics["cpu_count"]), 4)
    except (AttributeError, OSError):
        pass

    cpu_util = _cpu_util_pct()
    if cpu_util is not None:
        metrics["cpu_util_pct"] = cpu_util
    metrics.update(_cpu_temperature())

    mem = _linux_meminfo()
    if mem:
        total = mem.get("MemTotal", 0)
        available = mem.get("MemAvailable", 0)
        metrics["mem_total_mb"] = round(total / (1024 * 1024))
        metrics["mem_available_mb"] = round(available / (1024 * 1024))
        if total:
            metrics["mem_used_pct"] = round((total - available) / total * 100, 1)

    try:
        disk = shutil.disk_usage("/")
        metrics["disk_free_gb"] = round(disk.free / (1024**3), 1)
        metrics["disk_used_pct"] = round(disk.used / disk.total * 100, 1)
    except OSError:
        pass
    gpus = _nvidia_gpus()
    metrics["gpu_count"] = len(gpus)
    if gpus:
        metrics["gpus"] = gpus
    return metrics


def make_heartbeat_event(host: str, state: str, active_monitors: list[str] | None = None) -> ArgusEvent:
    details: dict[str, Any] = {
        "os": platform.system().lower() or "unknown",
        "ip_address": _local_ip_address(),
        "host_metrics": _host_metrics(),
    }
    if active_monitors is not None:
        details["active_monitors"] = active_monitors
    return ArgusEvent(
        version=1,
        source="argus",
        timestamp=utc_now_iso(),
        host=host,
        event_type="heartbeat",
        severity="low",
        confidence=1.0,
        state=state,
        title="Argus heartbeat",
        description="Argus is running",
        category="health",
        details=details,
    )
