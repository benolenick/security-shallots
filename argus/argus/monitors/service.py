from __future__ import annotations

import asyncio
import json
import os
import subprocess
from dataclasses import dataclass, field

from .types import ThreatSignal


_LINUX_SUSPICIOUS_PATHS = ["/tmp/", "/dev/shm/", "/var/tmp/", "/home/*/Downloads/"]


@dataclass(slots=True)
class ServiceMonitorConfig:
    enabled: bool = True
    poll_seconds: int = 60
    suspicious_paths: list[str] = field(
        default_factory=lambda: ["%temp%", "\\appdata\\", "\\downloads\\", "\\users\\public\\"]
    )
    linux_suspicious_paths: list[str] = field(
        default_factory=lambda: list(_LINUX_SUSPICIOUS_PATHS)
    )


class ServiceMonitor:
    def __init__(self, cfg: ServiceMonitorConfig) -> None:
        self.cfg = cfg
        # Maps service Name → PathName at baseline
        self._baseline: dict[str, str] = {}
        self._primed = False

    async def start(self, queue: asyncio.Queue[ThreatSignal]) -> None:
        while True:
            for signal in self._poll_once():
                await queue.put(signal)
            await asyncio.sleep(max(15, int(self.cfg.poll_seconds)))

    def _poll_once(self) -> list[ThreatSignal]:
        services = self._list_services()
        out: list[ThreatSignal] = []

        if not self._primed:
            self._baseline = {
                svc["name"]: svc["path"] for svc in services
            }
            self._primed = True
            return out

        current: dict[str, str] = {}
        for svc in services:
            name = svc["name"]
            path = svc["path"]
            state = svc["state"]
            start_mode = svc["start_mode"]
            current[name] = path

            if name not in self._baseline:
                # New service - check if it has a suspicious path
                if self._is_suspicious_path(path):
                    out.append(
                        ThreatSignal(
                            event_type="service_change",
                            title="New service with suspicious path",
                            description=(
                                f"New service '{name}' registered with a suspicious path: {path}"
                            ),
                            severity="high",
                            confidence=0.85,
                            category="persistence",
                            details={
                                "service_name": name,
                                "path": path,
                                "state": state,
                                "start_mode": start_mode,
                                "reason": "suspicious_path",
                            },
                            raw=svc,
                        )
                    )
                else:
                    out.append(
                        ThreatSignal(
                            event_type="service_change",
                            title="New service installed",
                            description=f"New service '{name}' was registered: {path}",
                            severity="medium",
                            confidence=0.7,
                            category="persistence",
                            details={
                                "service_name": name,
                                "path": path,
                                "state": state,
                                "start_mode": start_mode,
                                "reason": "new_service",
                            },
                            raw=svc,
                        )
                    )
            else:
                # Existing service - check for path change
                baseline_path = self._baseline[name]
                if path and path != baseline_path:
                    out.append(
                        ThreatSignal(
                            event_type="service_change",
                            title="Service executable path changed",
                            description=(
                                f"Service '{name}' path changed from "
                                f"'{baseline_path}' to '{path}'"
                            ),
                            severity="high",
                            confidence=0.85,
                            category="persistence",
                            details={
                                "service_name": name,
                                "path": path,
                                "previous_path": baseline_path,
                                "state": state,
                                "start_mode": start_mode,
                                "reason": "path_changed",
                            },
                            raw=svc,
                        )
                    )

        # Update baseline to include newly seen services for future polls
        self._baseline.update(current)
        return out

    def _is_suspicious_path(self, path: str) -> bool:
        if not path:
            return False
        path_lower = os.path.expandvars(path).lower()
        patterns = self.cfg.linux_suspicious_paths if os.name != "nt" else self.cfg.suspicious_paths
        for pattern in patterns:
            needle = os.path.expandvars(pattern).lower()
            # On Linux, handle glob-like wildcards simply
            if "*" in needle:
                # e.g. /home/*/downloads/ → check if /home/ and /downloads/ are in path
                parts = needle.split("*")
                if all(p in path_lower for p in parts if p):
                    return True
            elif needle in path_lower:
                return True
        return False

    @staticmethod
    def _list_services() -> list[dict]:
        if os.name != "nt":
            return ServiceMonitor._list_services_linux()

        ps = (
            "Get-CimInstance Win32_Service | "
            "Select-Object Name,PathName,State,StartMode | "
            "ConvertTo-Json -Compress"
        )
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        raw = (proc.stdout or "").strip()
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []
        items = parsed if isinstance(parsed, list) else [parsed]
        out = []
        for it in items:
            if not isinstance(it, dict):
                continue
            out.append(
                {
                    "name": str(it.get("Name", "") or ""),
                    "path": str(it.get("PathName", "") or ""),
                    "state": str(it.get("State", "") or ""),
                    "start_mode": str(it.get("StartMode", "") or ""),
                }
            )
        return out

    @staticmethod
    def _list_services_linux() -> list[dict]:
        """List systemd services on Linux."""
        try:
            proc = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--all",
                 "--no-pager", "--plain", "--no-legend"],
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            return []
        output = (proc.stdout or "").strip()
        if not output:
            return []

        out: list[dict] = []
        for line in output.splitlines():
            # Columns: UNIT  LOAD  ACTIVE  SUB  DESCRIPTION...
            parts = line.split(None, 4)
            if len(parts) < 4:
                continue
            unit = parts[0]          # e.g. sshd.service
            load_state = parts[1]    # loaded, not-found, etc.
            active = parts[2]        # active, inactive, failed
            sub = parts[3]           # running, dead, exited, etc.

            # Strip .service suffix for the name
            name = unit.removesuffix(".service") if unit.endswith(".service") else unit

            # Get the binary path via systemctl show
            path = ServiceMonitor._get_service_exec_linux(unit)

            # Map active+sub to a Windows-like state
            if active == "active" and sub == "running":
                state = "Running"
            elif active == "active":
                state = "Running"
            elif active == "inactive":
                state = "Stopped"
            elif active == "failed":
                state = "Stopped"
            else:
                state = sub

            # Map load → start_mode equivalent
            start_mode = "Auto" if load_state == "loaded" else "Disabled"

            out.append({
                "name": name,
                "path": path,
                "state": state,
                "start_mode": start_mode,
            })
        return out

    @staticmethod
    def _get_service_exec_linux(unit: str) -> str:
        """Get the ExecStart binary path for a systemd unit."""
        try:
            proc = subprocess.run(
                ["systemctl", "show", unit, "--property=ExecStart", "--no-pager"],
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            return ""
        raw = (proc.stdout or "").strip()
        # Output looks like: ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D ... }
        # or on some systems: ExecStart=/usr/sbin/sshd -D
        if not raw or "=" not in raw:
            return ""
        value = raw.split("=", 1)[1].strip()
        if not value or value == "":
            return ""
        # Try to extract path= from structured format
        if "path=" in value:
            # e.g. { path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D $OPTIONS }
            idx = value.find("path=")
            rest = value[idx + 5:]
            path = rest.split(";")[0].strip().strip("}")
            return path
        # Fallback: first token is the binary
        return value.split()[0].strip("{").strip("}")
