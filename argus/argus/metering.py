from __future__ import annotations

import asyncio
import json
import os
import random
import shutil
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .monitors.types import ThreatSignal


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(slots=True)
class MeterDecision:
    accepted: bool
    reason: str = ""


class MeteredSignalQueue:
    """Admission-control wrapper for monitor signals.

    Monitors only need an async ``put`` method, so this deliberately exposes a
    tiny Queue-compatible surface. The daemon still consumes from the real
    bounded asyncio.Queue.
    """

    def __init__(
        self,
        queue: asyncio.Queue[ThreatSignal],
        *,
        max_payload_bytes: int = 0,
        max_signals_per_minute: int = 0,
        backoff_seconds: float = 0.0,
        cpu_max_load_per_core: float = 0.0,
        reserve_severity: str = "high",
    ) -> None:
        self._queue = queue
        self.max_payload_bytes = max(0, int(max_payload_bytes))
        self.max_signals_per_minute = max(0, int(max_signals_per_minute))
        self.backoff_seconds = max(0.0, float(backoff_seconds))
        self.cpu_max_load_per_core = max(0.0, float(cpu_max_load_per_core))
        self.reserve_severity = reserve_severity
        self.accepted = 0
        self.dropped = 0
        self.last_drop_reason = ""
        self._accepted_at: deque[float] = deque()

    def qsize(self) -> int:
        return self._queue.qsize()

    def full(self) -> bool:
        return self._queue.full()

    async def put(self, signal: ThreatSignal) -> None:
        decision = self.check(signal)
        if not decision.accepted:
            self.dropped += 1
            self.last_drop_reason = decision.reason
            if self.backoff_seconds > 0:
                await asyncio.sleep(self.backoff_seconds)
            return
        await self._queue.put(signal)
        self.accepted += 1
        self._accepted_at.append(time.monotonic())

    def check(self, signal: ThreatSignal) -> MeterDecision:
        if self._queue.full():
            return MeterDecision(False, "queue_full")
        if self.max_payload_bytes:
            size = _signal_payload_size(signal)
            if size > self.max_payload_bytes:
                return MeterDecision(False, "payload_too_large")
        if self.max_signals_per_minute:
            now = time.monotonic()
            while self._accepted_at and now - self._accepted_at[0] > 60:
                self._accepted_at.popleft()
            if len(self._accepted_at) >= self.max_signals_per_minute:
                return MeterDecision(False, "rate_limited")
        if self.cpu_max_load_per_core and _load_per_core() > self.cpu_max_load_per_core:
            if SEVERITY_ORDER.get(str(signal.severity).lower(), 0) < SEVERITY_ORDER.get(self.reserve_severity, 3):
                return MeterDecision(False, "cpu_pressure")
        return MeterDecision(True)


def _signal_payload_size(signal: ThreatSignal) -> int:
    body: dict[str, Any] = {
        "event_type": signal.event_type,
        "title": signal.title,
        "description": signal.description,
        "severity": signal.severity,
        "confidence": signal.confidence,
        "category": signal.category,
        "details": signal.details,
        "raw": signal.raw,
        "timestamp": signal.timestamp,
    }
    return len(json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))


def _load_per_core() -> float:
    if not hasattr(os, "getloadavg"):
        return 0.0
    try:
        one_minute = os.getloadavg()[0]
        cores = max(1, os.cpu_count() or 1)
        return float(one_minute) / float(cores)
    except OSError:
        return 0.0


def disk_has_capacity(path: str, *, min_free_mb: int = 0, min_free_percent: float = 0.0) -> bool:
    if min_free_mb <= 0 and min_free_percent <= 0:
        return True
    p = Path(path).expanduser()
    target = p if p.exists() else p.parent
    while not target.exists() and target.parent != target:
        target = target.parent
    try:
        usage = shutil.disk_usage(str(target))
    except OSError:
        return True
    free_mb = usage.free / (1024 * 1024)
    free_percent = (usage.free / usage.total) * 100 if usage.total else 100.0
    return free_mb >= min_free_mb and free_percent >= min_free_percent


def jittered_seconds(base_seconds: float, jitter_percent: float) -> float:
    base = max(0.0, float(base_seconds))
    pct = max(0.0, min(1.0, float(jitter_percent)))
    if base == 0 or pct == 0:
        return base
    spread = base * pct
    return max(0.0, base + random.uniform(-spread, spread))


async def await_with_budget(awaitable: Any, budget_seconds: float) -> Any:
    budget = max(0.0, float(budget_seconds))
    if budget <= 0:
        return await awaitable
    return await asyncio.wait_for(awaitable, timeout=budget)
