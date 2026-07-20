from __future__ import annotations

import asyncio
import ipaddress
import os
import pwd
import re
import subprocess
from dataclasses import dataclass, field

from .types import ThreatSignal


@dataclass(slots=True)
class NetworkEgressConfig:
    enabled: bool = False
    poll_seconds: int = 60
    suspicious_ports: list[int] = field(default_factory=lambda: [4444, 5555, 6666, 9001, 1234, 1337, 31337])
    suspicious_processes: list[str] = field(
        default_factory=lambda: ["nc", "ncat", "netcat", "socat", "plink", "chisel", "ligolo", "ngrok"]
    )
    process_allowlist: list[str] = field(
        default_factory=lambda: [
            "qbittorrent",
            "qbittorrent-nox",
            "firefox",
            "chrome",
            "chromium",
            "brave",
            "curl",
            "wget",
            "syncthing",
            "tailscale",
            "tailscaled",
        ]
    )


class NetworkEgressMonitor:
    def __init__(self, cfg: NetworkEgressConfig) -> None:
        self.cfg = cfg
        self._alerted: set[str] = set()

    async def start(self, queue: asyncio.Queue[ThreatSignal]) -> None:
        while True:
            for signal in self._poll_once():
                await queue.put(signal)
            await asyncio.sleep(max(30, int(self.cfg.poll_seconds)))

    def _poll_once(self) -> list[ThreatSignal]:
        current: set[str] = set()
        out: list[ThreatSignal] = []
        for conn in self._connections():
            hit = classify_connection(
                conn,
                suspicious_ports=set(int(p) for p in self.cfg.suspicious_ports),
                suspicious_processes={p.lower() for p in self.cfg.suspicious_processes},
                process_allowlist={p.lower() for p in self.cfg.process_allowlist},
            )
            if not hit:
                continue
            key = f"{hit['process']}:{hit['remote_ip']}:{hit['remote_port']}:{hit['reason']}"
            current.add(key)
            if key in self._alerted:
                continue
            self._alerted.add(key)
            hit = _enrich_attribution(hit, conn.get("pid"))
            out.append(
                ThreatSignal(
                    event_type="network_egress_suspicious",
                    title=f"Suspicious outbound connection: {hit['process']} -> {hit['remote_ip']}:{hit['remote_port']}",
                    description=(
                        f"Process {hit['process']} opened an outbound connection to "
                        f"{hit['remote_ip']}:{hit['remote_port']} ({hit['reason']})."
                    ),
                    severity=hit["severity"],
                    confidence=hit["confidence"],
                    category="c2",
                    details=hit,
                    raw=conn,
                )
            )
        self._alerted.intersection_update(current)
        return out

    def _connections(self) -> list[dict[str, str | int]]:
        if os.name == "nt":
            return self._connections_windows()
        return self._connections_linux()

    @staticmethod
    def _connections_linux() -> list[dict[str, str | int]]:
        for cmd in (["ss", "-H", "-tunp"], ["netstat", "-tunp"]):
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
            raw = proc.stdout or ""
            if raw.strip():
                return parse_ss_output(raw)
        return []

    @staticmethod
    def _connections_windows() -> list[dict[str, str | int]]:
        ps = (
            "Get-NetTCPConnection -State Established | "
            "Select-Object RemoteAddress,RemotePort,OwningProcess | ConvertTo-Json -Compress"
        )
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps],
                capture_output=True,
                text=True,
                timeout=15,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []
        # Keep Windows support conservative until process-name enrichment is added.
        return []


def classify_connection(
    conn: dict[str, str | int],
    *,
    suspicious_ports: set[int],
    suspicious_processes: set[str],
    process_allowlist: set[str],
) -> dict[str, str | int | float] | None:
    remote_ip = str(conn.get("remote_ip") or "")
    remote_port = int(conn.get("remote_port") or 0)
    process = str(conn.get("process") or "").lower()
    state = str(conn.get("state") or "").upper()
    if not remote_ip or not remote_port or _private_or_special(remote_ip):
        return None
    if not process and state in {"TIME-WAIT", "FIN-WAIT-1", "FIN-WAIT-2", "CLOSE-WAIT", "CLOSING", "LAST-ACK"}:
        return None
    if process in process_allowlist:
        return None
    if remote_port in suspicious_ports:
        return {
            "reason": "suspicious_port",
            "severity": "high",
            "confidence": 0.8,
            "process": process or "unknown",
            "remote_ip": remote_ip,
            "remote_port": remote_port,
        }
    if process in suspicious_processes:
        return {
            "reason": "suspicious_process_public_egress",
            "severity": "high",
            "confidence": 0.85,
            "process": process,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
        }
    return None


def parse_ss_output(raw: str) -> list[dict[str, str | int]]:
    out: list[dict[str, str | int]] = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        state = ""
        if parts[0].lower() in {"tcp", "udp"} and len(parts) >= 6 and not parts[1].isdigit():
            state = parts[1]
            remote = parts[5]
        else:
            state = parts[5] if len(parts) >= 6 else ""
            remote = parts[4]
        remote_ip, remote_port = _split_host_port(remote)
        if not remote_ip or not remote_port:
            continue
        proc_match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
        out.append(
            {
                "remote_ip": remote_ip.strip("[]"),
                "remote_port": remote_port,
                "process": proc_match.group(1) if proc_match else "",
                "pid": int(proc_match.group(2)) if proc_match else None,
                "state": state,
                "raw": line,
            }
        )
    return out


def _split_host_port(value: str) -> tuple[str, int]:
    host, sep, port = value.rpartition(":")
    if not sep:
        return "", 0
    try:
        return host, int(port)
    except ValueError:
        return "", 0


def _private_or_special(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    )


def _proc_attr(pid: int) -> dict:
    """Best-effort attribution from /proc (only fully readable for our own PIDs)."""
    attr: dict = {"pid": pid}
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            cmd = fh.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        if cmd:
            attr["cmdline"] = cmd
    except OSError:
        pass
    try:
        attr["exe"] = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        pass
    try:
        st = os.stat(f"/proc/{pid}")
        attr["uid"] = st.st_uid
        try:
            attr["user"] = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            attr["user"] = str(st.st_uid)
    except OSError:
        pass
    return attr


def _enrich_attribution(hit: dict, pid) -> dict:
    """Add process attribution to a suspicious-egress hit.

    argus runs unprivileged, so /proc is only fully readable for its own user's
    PIDs; root/other-user or already-closed sockets stay unattributed here and are
    labelled honestly. The root egress-watcher backfills the watched destinations.
    """
    if pid:
        for k, v in _proc_attr(pid).items():
            hit.setdefault(k, v)
        cmd = hit.get("cmdline")
        if cmd and hit.get("process") in ("", "unknown", None):
            hit["process"] = cmd.split()[0].rsplit("/", 1)[-1]
    else:
        hit.setdefault(
            "attribution",
            "unattributed: socket owned by another user or already closed "
            "(unprivileged argus); root egress-watcher covers watched destinations",
        )
    return hit
