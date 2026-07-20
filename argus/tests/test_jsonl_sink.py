import asyncio
import json
from pathlib import Path

from argus.core.events import ArgusEvent
from argus.sinks.jsonl import JsonlSink


def test_jsonl_sink_writes_event(tmp_path: Path) -> None:
    sink = JsonlSink(directory=str(tmp_path))
    event = ArgusEvent(
        version=1,
        source="argus",
        timestamp="2026-03-02T00:00:00.000+00:00",
        host="h",
        event_type="heartbeat",
        severity="low",
        confidence=1.0,
        state="ARMED_HOME",
        title="Argus heartbeat",
        description="ok",
    )

    asyncio.run(sink.emit(event))

    files = list(tmp_path.glob("argus_events_*.jsonl"))
    assert len(files) == 1
    data = json.loads(files[0].read_text(encoding="utf-8").strip())
    assert data["event_type"] == "heartbeat"
    assert data["source"] == "argus"
