import asyncio
import contextlib
from pathlib import Path

from argus.config import ArgusConfig, load_config
from argus.core import StateStore
from argus.core.events import ArgusEvent
from argus.daemon import ArgusDaemon
from argus.metering import MeteredSignalQueue, jittered_seconds
from argus.monitors import ThreatSignal


def _signal(**overrides) -> ThreatSignal:
    values = {
        "event_type": "test_signal",
        "title": "Test signal",
        "description": "test",
        "severity": "medium",
        "confidence": 0.5,
        "category": "test",
    }
    values.update(overrides)
    return ThreatSignal(**values)


def test_lite_profile_applies_fleet_safe_defaults(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
[argus]

[argus.metering]
profile = "lite"
""",
        encoding="utf-8",
    )

    cfg = load_config(str(config_path))

    assert cfg.metering.profile == "lite"
    assert cfg.metering.queue_max_signals == 256
    assert cfg.metering.max_signal_payload_bytes == 32768
    assert cfg.metering.max_signals_per_minute == 120
    assert cfg.metering.loop_jitter_percent == 0.2
    assert cfg.metering.cycle_time_budget_seconds == 10.0
    assert cfg.metering.disk_min_free_mb == 512


def test_metering_overrides_profile_defaults(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
[argus]

[argus.metering]
profile = "lite"
queue_max_signals = 12
loop_jitter_percent = 0.5
""",
        encoding="utf-8",
    )

    cfg = load_config(str(config_path))

    assert cfg.metering.profile == "lite"
    assert cfg.metering.queue_max_signals == 12
    assert cfg.metering.loop_jitter_percent == 0.5
    assert cfg.metering.max_signal_payload_bytes == 32768


def test_daemon_uses_configured_queue_size(tmp_path: Path) -> None:
    cfg = ArgusConfig()
    cfg.metering.queue_max_signals = 7

    daemon = ArgusDaemon(cfg, StateStore(str(tmp_path / "state.json")))

    assert daemon.signal_queue.maxsize == 7


def test_metered_queue_drops_oversized_payload() -> None:
    async def run() -> None:
        queue: asyncio.Queue[ThreatSignal] = asyncio.Queue(maxsize=10)
        metered = MeteredSignalQueue(queue, max_payload_bytes=120)

        await metered.put(_signal(raw={"blob": "x" * 500}))

        assert queue.qsize() == 0
        assert metered.dropped == 1
        assert metered.last_drop_reason == "payload_too_large"

    asyncio.run(run())


def test_metered_queue_rate_limits() -> None:
    async def run() -> None:
        queue: asyncio.Queue[ThreatSignal] = asyncio.Queue(maxsize=10)
        metered = MeteredSignalQueue(queue, max_signals_per_minute=1)

        await metered.put(_signal())
        await metered.put(_signal(event_type="second"))

        assert queue.qsize() == 1
        assert metered.dropped == 1
        assert metered.last_drop_reason == "rate_limited"

    asyncio.run(run())


def test_jittered_seconds_stays_within_bounds() -> None:
    value = jittered_seconds(10, 0.25)

    assert 7.5 <= value <= 12.5


def test_cycle_budget_emits_timeout(monkeypatch, tmp_path: Path) -> None:
    async def run() -> list[ArgusEvent]:
        cfg = ArgusConfig()
        cfg.metering.cycle_time_budget_seconds = 0.01
        daemon = ArgusDaemon(cfg, StateStore(str(tmp_path / "state.json")))
        emitted: list[ArgusEvent] = []

        async def slow_handle(_: ThreatSignal) -> None:
            await asyncio.sleep(1)

        async def capture_emit(event: ArgusEvent) -> None:
            emitted.append(event)

        monkeypatch.setattr(daemon, "_handle_signal", slow_handle)
        monkeypatch.setattr(daemon, "_emit", capture_emit)
        await daemon.signal_queue.put(_signal())

        task = asyncio.create_task(daemon._consume_signals())
        try:
            await asyncio.wait_for(_wait_for_timeout_event(emitted), timeout=1)
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        return emitted

    events = asyncio.run(run())
    assert [event.event_type for event in events] == ["metering_cycle_timeout"]


async def _wait_for_timeout_event(events: list[ArgusEvent]) -> None:
    while not any(event.event_type == "metering_cycle_timeout" for event in events):
        await asyncio.sleep(0.001)
