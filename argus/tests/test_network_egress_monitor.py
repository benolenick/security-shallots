from __future__ import annotations

import asyncio

from argus.config import load_config
from argus.monitors.network_egress import (
    NetworkEgressConfig,
    NetworkEgressMonitor,
    classify_connection,
    parse_ss_output,
)


def test_config_parses_network_egress_disabled_by_default(tmp_path) -> None:
    path = tmp_path / "config.toml"
    path.write_text("[argus]\n", encoding="utf-8")

    cfg = load_config(str(path))

    assert cfg.network_egress.enabled is False
    assert "qbittorrent" in cfg.network_egress.process_allowlist
    assert "qbittorrent-nox" in cfg.network_egress.process_allowlist


def test_config_parses_network_egress_overrides(tmp_path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        """
[argus]

[argus.network_egress]
enabled = true
poll_seconds = 45
suspicious_ports = [4444]
suspicious_processes = ["ngrok"]
process_allowlist = ["qbittorrent"]
""",
        encoding="utf-8",
    )

    cfg = load_config(str(path))

    assert cfg.network_egress.enabled is True
    assert cfg.network_egress.poll_seconds == 45
    assert cfg.network_egress.suspicious_ports == [4444]
    assert cfg.network_egress.suspicious_processes == ["ngrok"]


def test_qbittorrent_public_high_port_is_allowlisted() -> None:
    hit = classify_connection(
        {"remote_ip": "67.220.85.98", "remote_port": 6882, "process": "qbittorrent"},
        suspicious_ports={4444},
        suspicious_processes={"ngrok"},
        process_allowlist={"qbittorrent"},
    )

    assert hit is None


def test_qbittorrent_nox_suspicious_port_is_allowlisted() -> None:
    hit = classify_connection(
        {"remote_ip": "93.158.213.92", "remote_port": 1337, "process": "qbittorrent-nox"},
        suspicious_ports={1337},
        suspicious_processes={"ngrok"},
        process_allowlist={"qbittorrent", "qbittorrent-nox"},
    )

    assert hit is None


def test_suspicious_process_public_egress_is_flagged() -> None:
    hit = classify_connection(
        {"remote_ip": "8.8.8.8", "remote_port": 443, "process": "ngrok"},
        suspicious_ports={4444},
        suspicious_processes={"ngrok"},
        process_allowlist={"qbittorrent"},
    )

    assert hit is not None
    assert hit["reason"] == "suspicious_process_public_egress"
    assert hit["severity"] == "high"


def test_normal_public_ssh_egress_is_not_suspicious_by_default() -> None:
    hit = classify_connection(
        {"remote_ip": "203.0.113.10", "remote_port": 22, "process": "ssh"},
        suspicious_ports={4444},
        suspicious_processes={"nc", "ncat", "netcat", "socat", "plink", "chisel", "ligolo", "ngrok"},
        process_allowlist={"qbittorrent"},
    )

    assert hit is None


def test_suspicious_port_public_egress_is_flagged() -> None:
    hit = classify_connection(
        {"remote_ip": "8.8.8.8", "remote_port": 4444, "process": "python"},
        suspicious_ports={4444},
        suspicious_processes={"ngrok"},
        process_allowlist={"qbittorrent"},
    )

    assert hit is not None
    assert hit["reason"] == "suspicious_port"


def test_private_egress_is_ignored() -> None:
    hit = classify_connection(
        {"remote_ip": "192.168.0.10", "remote_port": 4444, "process": "python"},
        suspicious_ports={4444},
        suspicious_processes={"python"},
        process_allowlist=set(),
    )

    assert hit is None


def test_parse_ss_output_extracts_process_and_remote() -> None:
    rows = parse_ss_output(
        'tcp ESTAB 0 0 192.168.0.10:50100 8.8.8.8:4444 users:(("python",pid=123,fd=7))\n'
    )

    assert rows == [
        {
            "remote_ip": "8.8.8.8",
            "remote_port": 4444,
            "process": "python",
            "pid": 123,
            "state": "ESTAB",
            "raw": 'tcp ESTAB 0 0 192.168.0.10:50100 8.8.8.8:4444 users:(("python",pid=123,fd=7))',
        }
    ]


def test_parse_netstat_style_output_extracts_remote() -> None:
    rows = parse_ss_output(
        'tcp 0 0 192.168.0.10:50100 8.8.4.4:4444 ESTABLISHED 123/python\n'
    )

    assert rows[0]["remote_ip"] == "8.8.4.4"
    assert rows[0]["remote_port"] == 4444


def test_monitor_deduplicates_until_connection_disappears(monkeypatch) -> None:
    monitor = NetworkEgressMonitor(NetworkEgressConfig(suspicious_ports=[4444], process_allowlist=[]))
    monkeypatch.setattr(
        monitor,
        "_connections",
        lambda: [{"remote_ip": "8.8.8.8", "remote_port": 4444, "process": "python"}],
    )

    first = monitor._poll_once()
    second = monitor._poll_once()

    assert len(first) == 1
    assert second == []


def test_monitor_can_emit_to_queue(monkeypatch) -> None:
    async def run() -> None:
        monitor = NetworkEgressMonitor(NetworkEgressConfig(suspicious_processes=["ngrok"], process_allowlist=[]))
        monkeypatch.setattr(
            monitor,
            "_connections",
            lambda: [{"remote_ip": "8.8.8.8", "remote_port": 443, "process": "ngrok"}],
        )
        queue = asyncio.Queue()
        for signal in monitor._poll_once():
            await queue.put(signal)

        signal = await queue.get()
        assert signal.event_type == "network_egress_suspicious"
        assert signal.details["process"] == "ngrok"

    asyncio.run(run())
