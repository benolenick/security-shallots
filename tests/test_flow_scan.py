"""Tests for the flow-fan-out scan/sweep detector."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from shallots.ingest.flow_scan import FlowScanDetector


def _ts(base: datetime, offset_sec: float) -> str:
    return (base + timedelta(seconds=offset_sec)).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def _flow(src, dst, port, t="2026-07-19T15:00:00.000000+00:00", pkts_client=1, bytes_client=40):
    return {
        "event_type": "flow", "src_ip": src, "dest_ip": dst, "dest_port": port,
        "proto": "TCP", "timestamp": t,
        "flow": {"pkts_toserver": 1, "pkts_toclient": pkts_client,
                 "bytes_toserver": 60, "bytes_toclient": bytes_client, "state": "closed"},
    }


def test_port_scan_fires_on_fanout():
    d = FlowScanDetector(port_scan_threshold=15)
    fired = None
    for p in range(1, 20):
        a = d.observe(_flow("192.168.0.50", "192.168.0.212", p))
        if a:
            fired = a
    assert fired is not None
    assert fired.category == "attempted-recon"
    assert "Port scan" in fired.title
    assert fired.severity == "high"


def test_host_sweep_fires_on_many_dsts():
    d = FlowScanDetector(sweep_threshold=12)
    fired = None
    for i in range(2, 20):
        a = d.observe(_flow("192.168.0.50", f"192.168.0.{i}", 445))
        if a:
            fired = a
    assert fired is not None and "Host sweep" in fired.title


def test_negative_normal_traffic_stays_quiet():
    """A normal host hitting a handful of ports with real data flows must NOT fire."""
    d = FlowScanDetector(port_scan_threshold=15)
    hits = 0
    # a few services, each an established flow with real bytes back
    for port in (80, 443, 53, 22):
        for _ in range(5):
            a = d.observe(_flow("192.168.0.60", "192.168.0.212", port,
                                pkts_client=40, bytes_client=50000))
            if a:
                hits += 1
    assert hits == 0


def test_established_data_flows_are_not_scans():
    """High-byte responses are filtered as non-scan even across many ports."""
    d = FlowScanDetector(port_scan_threshold=5)
    fired = False
    for p in range(1, 30):
        if d.observe(_flow("192.168.0.61", "192.168.0.212", p,
                           pkts_client=100, bytes_client=200000)):
            fired = True
    assert not fired


def test_external_source_ignored():
    """Recon from the internet is handled by signatures; this detector is east-west."""
    d = FlowScanDetector(port_scan_threshold=15)
    fired = False
    for p in range(1, 25):
        if d.observe(_flow("8.8.8.8", "192.168.0.212", p)):
            fired = True
    assert not fired


def test_ignore_src_allowlist():
    d = FlowScanDetector(port_scan_threshold=15, ignore_src={"192.168.0.172"})
    fired = False
    for p in range(1, 25):
        if d.observe(_flow("192.168.0.172", "192.168.0.212", p)):
            fired = True
    assert not fired


def test_no_duplicate_alert_same_window():
    d = FlowScanDetector(port_scan_threshold=15)
    alerts = [d.observe(_flow("192.168.0.50", "192.168.0.212", p)) for p in range(1, 40)]
    fired = [a for a in alerts if a]
    assert len(fired) == 1  # one alert per (src,dst) per window, not per packet


def test_slow_scan_evades_fast_window_but_not_slow_window():
    # Regression for the gap found live 2026-07-21: probes spaced ~90s apart
    # reset the fast (60s) window every single time, so fan-out there never
    # accumulates past 1 port - a real low-and-slow scanner's whole point.
    d = FlowScanDetector(port_scan_threshold=15, window_sec=60,
                         slow_port_scan_threshold=20, slow_window_sec=2700)
    base = datetime(2026, 7, 21, 4, 0, 0, tzinfo=timezone.utc)
    fired = []
    for i in range(1, 26):  # 25 probes, 90s apart = 37.5 minutes total
        a = d.observe(_flow("192.168.0.50", "192.168.0.212", 9000 + i,
                            t=_ts(base, i * 90)))
        if a:
            fired.append(a)
    # never enough fan-out within any single 60s window to trip the fast path
    assert not any("Slow" not in a.title for a in fired)
    # but the slow window (45min) accumulates all of it and does fire
    assert any("Slow port scan" in a.title for a in fired)


def test_slow_window_does_not_fire_before_its_own_threshold():
    d = FlowScanDetector(slow_port_scan_threshold=20, slow_window_sec=2700)
    base = datetime(2026, 7, 21, 4, 0, 0, tzinfo=timezone.utc)
    fired = []
    for i in range(1, 15):  # only 14 distinct ports - under the slow threshold
        a = d.observe(_flow("192.168.0.51", "192.168.0.212", 9000 + i,
                            t=_ts(base, i * 90)))
        if a:
            fired.append(a)
    assert fired == []


def test_slow_scan_still_ignores_established_data_flows():
    d = FlowScanDetector(slow_port_scan_threshold=5, slow_window_sec=2700)
    base = datetime(2026, 7, 21, 4, 0, 0, tzinfo=timezone.utc)
    fired = False
    for i, port in enumerate((80, 443, 53, 22, 8080, 9000), start=1):
        if d.observe(_flow("192.168.0.61", "192.168.0.212", port,
                           t=_ts(base, i * 300), pkts_client=100, bytes_client=200000)):
            fired = True
    assert not fired
