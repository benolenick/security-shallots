"""Argus egress canary command tests."""

from __future__ import annotations

from tools import argus_egress_canary


class Signal:
    event_type = "network_egress_suspicious"
    title = "Suspicious outbound connection"
    severity = "high"
    confidence = 0.85
    details = {"process": "ngrok"}


class FakeMonitor:
    def __init__(self, _cfg):
        pass

    def _connections(self):
        return [{"remote_ip": "8.8.8.8"}]

    def _poll_once(self):
        return [Signal()]


class QuietMonitor:
    def __init__(self, _cfg):
        pass

    def _connections(self):
        return [{"remote_ip": "8.8.8.8"}, {"remote_ip": "1.1.1.1"}]

    def _poll_once(self):
        return []


def test_run_canary_reports_would_emit(monkeypatch) -> None:
    monkeypatch.setattr(argus_egress_canary, "NetworkEgressMonitor", FakeMonitor)

    result = argus_egress_canary.run_canary()

    assert result["connections"] == 1
    assert result["would_emit"] == 1
    assert result["sample_count"] == 1
    assert result["signals"][0]["details"] == {"process": "ngrok"}


def test_main_fails_on_signal_when_requested(monkeypatch) -> None:
    monkeypatch.setattr(argus_egress_canary, "NetworkEgressMonitor", FakeMonitor)
    monkeypatch.setattr(argus_egress_canary.sys, "argv", ["argus_egress_canary.py", "--fail-on-signal"])

    assert argus_egress_canary.main() == 1


def test_run_canary_timed_mode_summarizes_samples(monkeypatch) -> None:
    now = {"value": 0.0}

    def fake_monotonic() -> float:
        now["value"] += 1.0
        return now["value"]

    monkeypatch.setattr(argus_egress_canary, "NetworkEgressMonitor", QuietMonitor)
    monkeypatch.setattr(argus_egress_canary.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(argus_egress_canary.time, "sleep", lambda _seconds: None)

    result = argus_egress_canary.run_canary(duration_seconds=2, interval_seconds=1)

    assert result["sample_count"] >= 2
    assert result["would_emit"] == 0
    assert result["max_connections"] == 2
