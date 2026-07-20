#!/usr/bin/env python3
"""Audit world-bound listeners on the Shallots controller host."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass
from typing import Any


DEFAULT_ALLOWED_PORTS = {
    22: "ssh",
    25: "smtp",
    514: "syslog",
    1984: "go2rtc",
    3000: "local_web_app",
    3333: "local_service",
    4000: "nomachine",
    8100: "hyphae",
    8123: "home_assistant",
    8250: "local_service",
    8554: "rtsp",
    8555: "rtsp_alt",
    8765: "local_service",
    8766: "local_service",
    8780: "local_service",
    8844: "shallots_web",
    8855: "argus_webhook",
    8892: "local_service",
    9800: "fluidsynth",
    27036: "steam",
}

HIGH_RISK_PORTS = {
    8000,
    8001,
    8002,
    8080,
    8081,
    8888,
    9000,
    9090,
    11434,
}

KNOWN_PORT_SERVICES = {
    11434: "ollama",
}

HIGH_RISK_PROCESSES = {
    "python",
    "python3",
    "uvicorn",
    "gunicorn",
    "node",
    "npm",
    "vite",
    "vllm::worker",
}

REVIEWED_LISTENERS = (
    {
        "port": 8600,
        "name": "host01_wall_board",
        "process": "python3",
        "cmdline_contains": "/home/user/wall/server.py",
        "review": "Local Host01 wall-board HTTP server; expected LAN-facing service.",
    },
    {
        "port": 8770,
        "name": "host01_musicd",
        "process": "python",
        "cmdline_contains": "/home/user/musicd/musicd.py",
        "review": "Local Host01 music daemon; expected LAN-facing service.",
    },
    {
        "port": 9922,
        "name": "shallots_honey_listener",
        "process": "python",
        "cmdline_contains": "/home/user/security-shallots/tools/shallot_posture_honey.py",
        "review": "Intentional Shallots honey listener; touches are posture findings.",
    },
)


@dataclass(frozen=True)
class Listener:
    proto: str
    bind: str
    port: int
    process: str
    pid: str
    raw: str
    cmdline: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "proto": self.proto,
            "bind": self.bind,
            "port": self.port,
            "process": self.process,
            "pid": self.pid,
            "cmdline": self.cmdline,
            "raw": self.raw,
        }


def _split_host_port(value: str) -> tuple[str, int]:
    host, sep, port = value.rpartition(":")
    if not sep:
        return "", 0
    try:
        return host.strip("[]"), int(port)
    except ValueError:
        return "", 0


def _is_world_bind(host: str) -> bool:
    return host in {"", "*", "0.0.0.0", "::"}


def parse_ss_listeners(raw: str) -> list[Listener]:
    listeners: list[Listener] = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        if proto != "tcp":
            continue
        local = parts[4] if parts[0].lower() in {"tcp", "udp"} else ""
        bind, port = _split_host_port(local)
        if not port or not _is_world_bind(bind):
            continue
        proc_match = re.search(r'users:\(\("([^"]+)",pid=([^,)\s]+)', line)
        process = proc_match.group(1) if proc_match else ""
        pid = proc_match.group(2) if proc_match else ""
        listeners.append(Listener(proto=proto, bind=bind or "*", port=port, process=process, pid=pid, raw=line))
    return listeners


def _ss_output() -> str:
    proc = subprocess.run(
        ["ss", "-H", "-ltnup"],
        text=True,
        capture_output=True,
        timeout=8,
        check=False,
    )
    return proc.stdout if proc.returncode == 0 else ""


def _ss_connections_output() -> str:
    proc = subprocess.run(
        ["ss", "-H", "-tn"],
        text=True,
        capture_output=True,
        timeout=8,
        check=False,
    )
    return proc.stdout if proc.returncode == 0 else ""


def _normalize_ip(value: str) -> str:
    value = value.strip("[]")
    if value.startswith("::ffff:"):
        return value.removeprefix("::ffff:")
    return value


def parse_active_clients(raw: str, port: int) -> list[str]:
    clients: set[str] = set()
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[-2]
        peer = parts[-1]
        _local_host, local_port = _split_host_port(local)
        if local_port != port:
            continue
        peer_host, _peer_port = _split_host_port(peer)
        peer_host = _normalize_ip(peer_host)
        if not peer_host or peer_host in {"127.0.0.1", "::1"}:
            continue
        clients.add(peer_host)
    return sorted(clients)


def _pid_cmdline(pid: str) -> str:
    if not pid:
        return ""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as handle:
            return handle.read().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    except OSError:
        return ""


def _enrich_cmdlines(listeners: list[Listener]) -> list[Listener]:
    out: list[Listener] = []
    for listener in listeners:
        out.append(
            Listener(
                proto=listener.proto,
                bind=listener.bind,
                port=listener.port,
                process=listener.process,
                pid=listener.pid,
                raw=listener.raw,
                cmdline=listener.cmdline or _pid_cmdline(listener.pid),
            )
        )
    return out


def _reviewed_listener(listener: Listener) -> dict[str, Any] | None:
    process = listener.process.lower()
    cmdline = listener.cmdline
    for item in REVIEWED_LISTENERS:
        if int(item["port"]) != listener.port:
            continue
        expected_process = str(item.get("process") or "").lower()
        if expected_process and expected_process != process:
            continue
        needle = str(item.get("cmdline_contains") or "")
        if needle and needle not in cmdline:
            continue
        return dict(item)
    return None


def classify_listener(listener: Listener, allowed_ports: dict[int, str]) -> dict[str, Any] | None:
    if listener.port in allowed_ports:
        return None
    reviewed = _reviewed_listener(listener)
    if reviewed:
        return None
    process = listener.process.lower()
    reasons: list[str] = []
    if listener.port in HIGH_RISK_PORTS or 8000 <= listener.port <= 8999:
        reasons.append("dev_or_model_port_world_bound")
    if process in HIGH_RISK_PROCESSES:
        reasons.append("dev_or_model_process_world_bound")
    if not reasons:
        return None
    service_name = KNOWN_PORT_SERVICES.get(listener.port, "")
    action = ""
    if service_name == "ollama":
        action = (
            "Review Ollama LAN exposure. If remote clients still need it, restrict 11434 to approved LAN clients "
            "or put it behind an authenticated proxy; otherwise bind OLLAMA_HOST to 127.0.0.1:11434."
        )
    return {
        **listener.to_dict(),
        "service": service_name,
        "action": action,
        "reason": ",".join(reasons),
        "severity": "high" if "dev_or_model" in ",".join(reasons) else "medium",
    }


def build_summary(raw: str | None = None, *, allowed_ports: dict[int, str] | None = None) -> dict[str, Any]:
    allowed_ports = dict(DEFAULT_ALLOWED_PORTS if allowed_ports is None else allowed_ports)
    listeners = parse_ss_listeners(_ss_output() if raw is None else raw)
    active_clients_by_port: dict[int, list[str]] = {}
    if raw is None:
        listeners = _enrich_cmdlines(listeners)
        connections_raw = _ss_connections_output()
        for listener in listeners:
            active_clients_by_port[listener.port] = parse_active_clients(connections_raw, listener.port)
    unexpected = [
        item for item in (classify_listener(listener, allowed_ports) for listener in listeners)
        if item is not None
    ]
    for item in unexpected:
        clients = active_clients_by_port.get(int(item.get("port") or 0), [])
        if clients:
            item["active_clients"] = clients
    reviewed = [
        {**listener.to_dict(), "review": reviewed_listener}
        for listener in listeners
        for reviewed_listener in [_reviewed_listener(listener)]
        if reviewed_listener is not None
    ]
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[int, str, str]] = set()
    for item in unexpected:
        key = (int(item.get("port") or 0), str(item.get("process") or ""), str(item.get("reason") or ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    unexpected = deduped
    warnings = [
        f"public_listener:{item['port']}:{item.get('process') or item.get('service') or 'unknown'}:{item['reason']}"
        for item in unexpected
    ]
    return {
        "status": "watch" if unexpected else "ok",
        "allowed_ports": [{"port": port, "name": name} for port, name in sorted(allowed_ports.items())],
        "reviewed_listeners": reviewed,
        "listener_count": len(listeners),
        "unexpected_count": len(unexpected),
        "warnings": warnings,
        "unexpected": unexpected,
        "listeners": [listener.to_dict() for listener in listeners],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    summary = build_summary()
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"public listeners: {summary['status']} unexpected={summary['unexpected_count']}")
        for item in summary["unexpected"]:
            print(f"- {item['proto']} {item['bind']}:{item['port']} {item.get('process') or '?'} {item['reason']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
