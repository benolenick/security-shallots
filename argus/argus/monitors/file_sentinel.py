from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path

from .types import ThreatSignal, expand_config_path


@dataclass(slots=True)
class FileSentinelConfig:
    enabled: bool = False
    poll_seconds: int = 5
    paths: list[str] = field(default_factory=list)


class FileSentinelMonitor:
    def __init__(self, cfg: FileSentinelConfig) -> None:
        self.cfg = cfg
        self._baseline: dict[str, tuple[bool, int, int]] = {}
        self._primed = False

    async def start(self, queue: asyncio.Queue[ThreatSignal]) -> None:
        while True:
            for s in self._poll_once():
                await queue.put(s)
            await asyncio.sleep(max(3, int(self.cfg.poll_seconds)))

    def _snapshot_one(self, p: Path) -> tuple[bool, int, int]:
        if not p.exists():
            return (False, 0, 0)
        st = p.stat()
        return (True, int(st.st_mtime_ns), int(st.st_size))

    def _poll_once(self) -> list[ThreatSignal]:
        out: list[ThreatSignal] = []
        for raw_path in self.cfg.paths:
            p = Path(expand_config_path(str(raw_path)))
            key = str(p)
            snap = self._snapshot_one(p)
            prev = self._baseline.get(key)
            if prev is None:
                self._baseline[key] = snap
                continue

            if snap != prev:
                self._baseline[key] = snap
                if self._primed:
                    out.append(
                        ThreatSignal(
                            event_type="file_sentinel",
                            title="Protected file changed",
                            description=f"Protected file changed: {key}",
                            severity="high",
                            confidence=0.9,
                            category="collection",
                            details={"path": key, "previous": prev, "current": snap},
                        )
                    )
        self._primed = True
        return out
