#!/usr/bin/env python3
"""Dry-run Argus network egress monitor without emitting alerts."""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ARGUS_PATH = ROOT / "argus"
if str(ARGUS_PATH) not in sys.path:
    sys.path.insert(0, str(ARGUS_PATH))

from argus.monitors.network_egress import NetworkEgressConfig, NetworkEgressMonitor  # noqa: E402


def _sample(monitor: NetworkEgressMonitor) -> dict:
    connections = monitor._connections()
    signals = monitor._poll_once()
    return {
        "timestamp": time.time(),
        "connections": len(connections),
        "would_emit": len(signals),
        "signals": [
            {
                "event_type": signal.event_type,
                "title": signal.title,
                "severity": signal.severity,
                "confidence": signal.confidence,
                "details": signal.details,
            }
            for signal in signals
        ],
    }


def run_canary(*, duration_seconds: float = 0.0, interval_seconds: float = 10.0) -> dict:
    monitor = NetworkEgressMonitor(NetworkEgressConfig())
    samples = []
    if duration_seconds <= 0:
        samples.append(_sample(monitor))
    else:
        deadline = time.monotonic() + duration_seconds
        while True:
            samples.append(_sample(monitor))
            if time.monotonic() >= deadline:
                break
            time.sleep(min(max(interval_seconds, 1.0), max(0.0, deadline - time.monotonic())))
    all_signals = [signal for sample in samples for signal in sample["signals"]]
    return {
        "host": socket.gethostname(),
        "samples": samples,
        "sample_count": len(samples),
        "connections": samples[-1]["connections"] if samples else 0,
        "max_connections": max((sample["connections"] for sample in samples), default=0),
        "would_emit": len(all_signals),
        "max_would_emit_per_sample": max((sample["would_emit"] for sample in samples), default=0),
        "signals": all_signals,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--fail-on-signal", action="store_true", help="Exit nonzero if dry-run would emit signals")
    parser.add_argument("--duration", type=float, default=0.0, help="Sample for this many seconds")
    parser.add_argument("--interval", type=float, default=10.0, help="Seconds between samples in timed mode")
    args = parser.parse_args()

    result = run_canary(duration_seconds=args.duration, interval_seconds=args.interval)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(
            f"argus egress canary: host={result['host']} "
            f"samples={result['sample_count']} connections={result['connections']} "
            f"max_connections={result['max_connections']} would_emit={result['would_emit']}"
        )
        for signal in result["signals"]:
            print(f"  {signal['severity']} {signal['title']} {signal['details']}")
    return 1 if args.fail_on_signal and result["would_emit"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
