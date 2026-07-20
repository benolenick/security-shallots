from __future__ import annotations

import asyncio
import hashlib
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .types import ThreatSignal, expand_config_path


@dataclass(slots=True)
class AntiTamperConfig:
    enabled: bool = False
    poll_seconds: int = 15
    watch_files: list[str] = field(default_factory=list)
    required_tasks: list[str] = field(default_factory=lambda: ["Argus-OnLock", "Argus-OnUnlock"])


class AntiTamperMonitor:
    def __init__(self, cfg: AntiTamperConfig) -> None:
        self.cfg = cfg
        self._baseline: dict[str, str] = {}
        self._task_baseline: dict[str, bool] = {}

    async def start(self, queue: asyncio.Queue[ThreatSignal]) -> None:
        while True:
            for s in self._poll_once():
                await queue.put(s)
            await asyncio.sleep(max(5, int(self.cfg.poll_seconds)))

    def _poll_once(self) -> list[ThreatSignal]:
        out: list[ThreatSignal] = []
        for raw in self.cfg.watch_files:
            p = Path(expand_config_path(str(raw)))
            sig = self._file_sig(p)
            prev = self._baseline.get(str(p))
            if prev is None:
                self._baseline[str(p)] = sig
                continue
            if sig != prev:
                self._baseline[str(p)] = sig
                out.append(
                    ThreatSignal(
                        event_type="anti_tamper",
                        title="Protected config changed",
                        description=f"Tamper signal: watched file changed: {p}",
                        severity="high",
                        confidence=0.95,
                        category="defense_evasion",
                        details={"path": str(p)},
                    )
                )

        if os.name == "nt":
            for task_name in self.cfg.required_tasks:
                present = self._task_exists(task_name)
                if task_name not in self._task_baseline:
                    self._task_baseline[task_name] = present
                    continue
                if self._task_baseline[task_name] and not present:
                    out.append(
                        ThreatSignal(
                            event_type="anti_tamper",
                            title="Required task missing",
                            description=f"Tamper signal: required task missing: {task_name}",
                            severity="medium",
                            confidence=0.98,
                            category="defense_evasion",
                            details={"task": task_name},
                        )
                    )
                self._task_baseline[task_name] = present
        else:
            for task_name in self.cfg.required_tasks:
                present = self._task_exists_linux(task_name)
                if task_name not in self._task_baseline:
                    self._task_baseline[task_name] = present
                    continue
                if self._task_baseline[task_name] and not present:
                    out.append(
                        ThreatSignal(
                            event_type="anti_tamper",
                            title="Required systemd unit missing",
                            description=f"Tamper signal: required systemd unit/cron missing: {task_name}",
                            severity="medium",
                            confidence=0.98,
                            category="defense_evasion",
                            details={"task": task_name},
                        )
                    )
                self._task_baseline[task_name] = present
        return out

    @staticmethod
    def _task_exists(task_name: str) -> bool:
        p = subprocess.run(
            ["schtasks", "/Query", "/TN", task_name],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return p.returncode == 0

    @staticmethod
    def _task_exists_linux(task_name: str) -> bool:
        """Check if a systemd unit or cron job exists on Linux."""
        # Check systemd unit (system and user)
        try:
            p = subprocess.run(
                ["systemctl", "list-units", "--all", "--no-pager", "--plain",
                 "--no-legend", task_name],
                capture_output=True,
                text=True,
            )
            if p.returncode == 0 and task_name in (p.stdout or ""):
                return True
        except FileNotFoundError:
            pass

        # Check systemctl is-enabled (for installed but inactive units)
        try:
            p = subprocess.run(
                ["systemctl", "is-enabled", task_name],
                capture_output=True,
                text=True,
            )
            if p.returncode == 0:
                return True
        except FileNotFoundError:
            pass

        # Check crontab for the task name
        try:
            p = subprocess.run(
                ["crontab", "-l"],
                capture_output=True,
                text=True,
            )
            if task_name in (p.stdout or ""):
                return True
        except FileNotFoundError:
            pass

        return False

    @staticmethod
    def _file_sig(path: Path) -> str:
        if not path.exists():
            return "MISSING"
        try:
            data = path.read_bytes()
        except OSError:
            return "ERROR"
        return hashlib.sha256(data).hexdigest()
