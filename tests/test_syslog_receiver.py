from __future__ import annotations

from pathlib import Path

from shallots.config import load_config
from shallots.ingest.syslog_receiver import _LowSeverityDuplicateLimiter, parse_syslog


def _parsed(message: str, priority: int = 14) -> dict:
    parsed = parse_syslog(f"<{priority}>Jul 15 10:00:00 router dnsmasq: {message}".encode())
    assert parsed is not None
    return parsed


def test_low_severity_duplicate_limiter_caps_identical_messages() -> None:
    limiter = _LowSeverityDuplicateLimiter(limit=2, window_sec=60)
    parsed = _parsed("DHCP lease renewed for 192.168.0.42")

    assert limiter.allow(parsed, "192.168.0.1") is True
    assert limiter.allow(parsed, "192.168.0.1") is True
    assert limiter.allow(parsed, "192.168.0.1") is False


def test_low_severity_duplicate_limiter_allows_distinct_messages() -> None:
    limiter = _LowSeverityDuplicateLimiter(limit=1, window_sec=60)

    assert limiter.allow(_parsed("DHCP lease renewed for 192.168.0.42"), "192.168.0.1") is True
    assert limiter.allow(_parsed("administrator password changed"), "192.168.0.1") is True


def test_low_severity_duplicate_limiter_allows_medium_and_above() -> None:
    limiter = _LowSeverityDuplicateLimiter(limit=1, window_sec=60)
    parsed = _parsed("kernel warning repeated", priority=12)

    assert parsed["severity"] == "medium"
    assert limiter.allow(parsed, "192.168.0.1") is True
    assert limiter.allow(parsed, "192.168.0.1") is True


def test_syslog_duplicate_limiter_can_be_disabled() -> None:
    limiter = _LowSeverityDuplicateLimiter(limit=0, window_sec=60)
    parsed = _parsed("same info line")

    assert all(limiter.allow(parsed, "192.168.0.1") for _ in range(5))


def test_syslog_duplicate_limiter_config_loads(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "\n".join(
            [
                "syslog:",
                "  enabled: true",
                "  udp_port: 514",
                "  tcp_port: 514",
                "  low_severity_duplicate_limit: 7",
                "  low_severity_duplicate_window_sec: 30",
            ]
        )
    )

    cfg = load_config(config_path)

    assert cfg.syslog.low_severity_duplicate_limit == 7
    assert cfg.syslog.low_severity_duplicate_window_sec == 30
