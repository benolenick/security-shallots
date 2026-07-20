from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
from dataclasses import dataclass, field

from .types import ThreatSignal


@dataclass(slots=True)
class RegistryMonitorConfig:
    enabled: bool = True
    poll_seconds: int = 30
    watch_keys: list[str] = field(
        default_factory=lambda: [
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        ]
    )


class RegistryMonitor:
    def __init__(self, cfg: RegistryMonitorConfig) -> None:
        self.cfg = cfg
        self._last_digest: str | None = None
        self._primed = False

    async def start(self, queue: asyncio.Queue[ThreatSignal]) -> None:
        while True:
            for signal in self._poll_once():
                await queue.put(signal)
            await asyncio.sleep(max(10, int(self.cfg.poll_seconds)))

    def _poll_once(self) -> list[ThreatSignal]:
        snapshot = self._collect_snapshot()
        digest = hashlib.sha256(snapshot.encode("utf-8", "replace")).hexdigest()

        if not self._primed:
            self._last_digest = digest
            self._primed = True
            return []

        if digest == self._last_digest:
            return []

        prev_digest = self._last_digest
        self._last_digest = digest
        return [
            ThreatSignal(
                event_type="registry_persistence",
                title="Registry persistence keys changed",
                description="One or more watched registry run/persistence keys changed",
                severity="high",
                confidence=0.85,
                category="persistence",
                details={
                    "snapshot_hash": digest,
                    "previous_hash": prev_digest,
                },
                raw={"snapshot_hash": digest},
            )
        ]

    def _collect_snapshot(self) -> str:
        if os.name != "nt":
            return self._collect_snapshot_linux()
        chunks: list[str] = []
        for key in self.cfg.watch_keys:
            proc = subprocess.run(
                ["reg", "query", key],
                capture_output=True,
                text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            chunks.append(proc.stdout or "")
        return "\n".join(chunks)

    @staticmethod
    def _collect_snapshot_linux() -> str:
        """Collect persistence locations on Linux: crontabs, cron dirs, systemd timers."""
        chunks: list[str] = []

        # Current user crontab
        try:
            proc = subprocess.run(
                ["crontab", "-l"],
                capture_output=True,
                text=True,
            )
            chunks.append("=== crontab -l ===\n" + (proc.stdout or ""))
        except FileNotFoundError:
            pass

        # System cron directories
        import os as _os
        for cron_dir in [
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
            "/etc/cron.hourly",
            "/var/spool/cron/crontabs",
        ]:
            try:
                entries = sorted(_os.listdir(cron_dir))
                chunks.append(f"=== {cron_dir} ===\n" + "\n".join(entries))
            except OSError:
                pass

        # Systemd timers
        try:
            proc = subprocess.run(
                ["systemctl", "list-timers", "--all", "--no-pager"],
                capture_output=True,
                text=True,
            )
            chunks.append("=== systemctl list-timers ===\n" + (proc.stdout or ""))
        except FileNotFoundError:
            pass

        # User systemd services/timers
        user_systemd = _os.path.expanduser("~/.config/systemd/user")
        try:
            entries = sorted(_os.listdir(user_systemd))
            chunks.append(f"=== {user_systemd} ===\n" + "\n".join(entries))
        except OSError:
            pass

        return "\n".join(chunks)
