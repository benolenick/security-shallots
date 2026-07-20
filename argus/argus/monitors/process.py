from __future__ import annotations

import asyncio
import fnmatch
import json
import os
import subprocess
from dataclasses import dataclass, field

from .types import ThreatSignal


@dataclass(slots=True)
class ProcessMonitorConfig:
    enabled: bool = False
    poll_seconds: int = 10
    allowlist: list[str] = field(default_factory=list)
    denylist: list[str] = field(default_factory=list)
    alert_on_unknown: bool = True


class ProcessMonitor:
    def __init__(self, cfg: ProcessMonitorConfig) -> None:
        self.cfg = cfg
        self._seen: set[int] = set()
        self._primed = False

    async def start(self, queue: asyncio.Queue[ThreatSignal]) -> None:
        while True:
            for s in self._poll_once():
                await queue.put(s)
            await asyncio.sleep(max(3, int(self.cfg.poll_seconds)))

    def _poll_once(self) -> list[ThreatSignal]:
        procs = self._list_processes()
        out: list[ThreatSignal] = []
        if not self._primed:
            self._seen = {int(p.get("pid", 0)) for p in procs if int(p.get("pid", 0)) > 0}
            self._primed = True
            return out

        for p in procs:
            pid = int(p.get("pid", 0))
            if pid <= 0 or pid in self._seen:
                continue
            self._seen.add(pid)

            exe = str(p.get("exe", "") or "")
            name = str(p.get("name", "") or "")
            cmd = str(p.get("cmd", "") or "")

            if self._matches_any(name, exe, cmd, self.cfg.denylist):
                out.append(
                    ThreatSignal(
                        event_type="process_tripwire",
                        title="Denied process pattern matched",
                        description=f"Process matched denylist: {name} (pid={pid})",
                        severity="critical",
                        confidence=0.95,
                        category="execution",
                        details={"pid": pid, "name": name, "exe": exe},
                        raw=p,
                    )
                )
                continue

            if self.cfg.alert_on_unknown and not self._is_allowlisted(name, exe, cmd):
                out.append(
                    ThreatSignal(
                        event_type="process_tripwire",
                        title="Unknown process outside allowlist",
                        description=f"New process outside allowlist: {name} (pid={pid})",
                        severity="high",
                        confidence=0.8,
                        category="execution",
                        details={"pid": pid, "name": name, "exe": exe},
                        raw=p,
                    )
                )
        return out

    def _is_allowlisted(self, name: str, exe: str, cmd: str) -> bool:
        return self._matches_any(name, exe, cmd, self.cfg.allowlist)

    @staticmethod
    def _matches_any(name: str, exe: str, cmd: str, patterns: list[str]) -> bool:
        ln = name.lower()
        le = exe.lower()
        lc = cmd.lower()
        for pat in patterns:
            p = os.path.expandvars(str(pat)).lower()
            if fnmatch.fnmatch(ln, p) or fnmatch.fnmatch(le, p) or fnmatch.fnmatch(lc, p):
                return True
        return False

    @staticmethod
    def _list_processes() -> list[dict]:
        if os.name == "nt":
            ps = (
                "Get-CimInstance Win32_Process | "
                "Select-Object ProcessId,Name,ExecutablePath,CommandLine,ParentProcessId | "
                "ConvertTo-Json -Compress"
            )
            p = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps],
                capture_output=True,
                text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            raw = (p.stdout or "").strip()
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
                        "pid": int(it.get("ProcessId", 0) or 0),
                        "name": str(it.get("Name", "") or ""),
                        "exe": str(it.get("ExecutablePath", "") or ""),
                        "cmd": str(it.get("CommandLine", "") or ""),
                        "ppid": int(it.get("ParentProcessId", 0) or 0),
                    }
                )
            return out

        p = subprocess.run(["ps", "-eo", "pid,comm,args"], capture_output=True, text=True)
        lines = (p.stdout or "").splitlines()[1:]
        out = []
        for line in lines:
            parts = line.strip().split(None, 2)
            if len(parts) < 2:
                continue
            pid = int(parts[0])
            name = parts[1]
            cmd = parts[2] if len(parts) > 2 else name
            out.append({"pid": pid, "name": name, "exe": name, "cmd": cmd, "ppid": 0})
        return out
