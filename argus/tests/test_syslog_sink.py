import asyncio

from argus.core.events import ArgusEvent
from argus.sinks.syslog import SyslogSink


def _event(severity: str = "high") -> ArgusEvent:
    return ArgusEvent(
        version=1,
        source="argus",
        timestamp="2026-03-02T00:00:00.000Z",
        host="host1",
        event_type="anti_tamper",
        severity=severity,
        confidence=0.95,
        state="LOCKDOWN",
        title="x",
        description="y",
    )


def test_syslog_sink_formats_rfc5424_like_message() -> None:
    sink = SyslogSink(enabled=True, host="127.0.0.1", port=5514, protocol="udp")
    msg = sink._format_message(_event("critical")).decode("utf-8", "replace")
    assert msg.startswith("<130>1 ")
    assert '"event_type":"anti_tamper"' in msg


def test_syslog_sink_emit_calls_send(monkeypatch) -> None:
    sink = SyslogSink(enabled=True, host="127.0.0.1", port=5514, protocol="udp")
    seen: dict = {}

    def fake_send(message: bytes) -> None:
        seen["msg"] = message

    monkeypatch.setattr(sink, "_send_message", fake_send)
    asyncio.run(sink.emit(_event()))
    assert b"anti_tamper" in seen["msg"]
