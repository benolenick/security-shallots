"""Integration test: cloud-tier triage obfuscation wiring.

Proves the demo-leak case is closed: a hostname that appears only in prose
(a title/description) is masked because _build_obfuscator seeds inventory
hostnames, and model-returned tokens round-trip back to real identifiers.
"""
from __future__ import annotations

import pytest

from shallots.ai.obfuscate import Obfuscator
from shallots.ai.triage import TriageWorker
from shallots.config import AIConfig


class _FakeDB:
    """Minimal AlertDB stand-in exposing only what _build_obfuscator touches."""

    async def get_assets(self, limit: int = 200):
        return [{"hostname": "mail-server", "ip": "192.168.0.183"}]

    async def get_known_devices(self, limit: int = 200):
        return [{"hostname": "host01", "ip": "192.168.0.172"}]


def test_obfuscate_masks_prose_hostname_and_roundtrips():
    obf = Obfuscator(strict=True)
    obf.seed_assets(hostnames=["mail-server", "host01"], ips=["192.168.0.172"], users=["root"])

    alert = {
        "title": "Outbound from mail-server to 45.9.148.3 flagged",
        "description": "root ran curl on host01 (192.168.0.172); MAC aa:bb:cc:dd:ee:ff",
        "src_ip": "192.168.0.172",
        "dst_ip": "45.9.148.3",
    }
    ob = obf.obfuscate_alert(alert)
    blob = str(ob).lower()

    assert "mail-server" not in blob, "seeded hostname leaked in prose"
    assert "host01" not in blob, "seeded hostname leaked"
    assert "45.9.148.3" not in str(ob), "external IP leaked"
    assert "192.168.0.172" not in str(ob), "internal IP leaked"
    assert not obf.verify(ob), f"residual identifiers survived: {obf.verify(ob)}"

    reply = obf.deobfuscate(f"iocs: [{ob['dst_ip']}]; {ob['src_ip']} contacted external host")
    assert "45.9.148.3" in reply and "192.168.0.172" in reply, "tokens did not round-trip"


@pytest.mark.asyncio
async def test_build_obfuscator_gated_on_config():
    db = _FakeDB()

    # off by default
    w = TriageWorker(AIConfig(tier="remote_api"), db)
    assert await w._build_obfuscator([]) is None

    # wrong tier -> off even if flag set
    w = TriageWorker(AIConfig(tier="local", obfuscate_cloud=True), db)
    assert await w._build_obfuscator([]) is None

    # remote_api + flag -> active and seeded from inventory
    w = TriageWorker(AIConfig(tier="remote_api", obfuscate_cloud=True), db)
    obf = await w._build_obfuscator([{"src_ip": "10.0.0.5", "dst_dns": "printer.lan"}])
    assert obf is not None
    assert "host01" in obf._assets and "mail-server" in obf._assets
    assert "printer.lan" in obf._assets  # seeded from the batch itself
