import asyncio

from argus.core.events import ArgusEvent
from argus.sinks.webhook import WebhookSink


def _event() -> ArgusEvent:
    return ArgusEvent(
        version=1,
        source="argus",
        timestamp="2026-03-02T00:00:00.000Z",
        host="host1",
        event_type="process_tripwire",
        severity="high",
        confidence=0.9,
        state="ARMED_HOME",
        title="x",
        description="y",
    )


def test_webhook_sink_posts_payload(monkeypatch) -> None:
    sink = WebhookSink(enabled=True, url="http://127.0.0.1:8855/api/ingest/argus", secret="s3cr3t")
    seen: dict = {}

    def fake_post(payload) -> None:
        seen["payload"] = payload

    monkeypatch.setattr(sink, "_post_payload", fake_post)
    asyncio.run(sink.emit(_event()))
    assert seen["payload"]["event_type"] == "process_tripwire"


def test_webhook_sink_batch(monkeypatch) -> None:
    sink = WebhookSink(enabled=True, url="http://127.0.0.1:8855/api/ingest/argus", secret="")
    seen: dict = {}

    def fake_post(payload) -> None:
        seen["payload"] = payload

    monkeypatch.setattr(sink, "_post_payload", fake_post)
    asyncio.run(sink.emit_batch([_event(), _event()]))
    assert isinstance(seen["payload"], list)
    assert len(seen["payload"]) == 2
