"""Tests for the non-judgmental edge scout."""

from __future__ import annotations

import json

import pytest

from shallots.ai.scout import ScoutWorker
from shallots.config import ScoutConfig
from shallots.store.models import Alert


@pytest.mark.asyncio
async def test_scout_card_does_not_change_alert_verdict(tmp_db):
    await tmp_db.insert_alert(Alert(
        id="scout-alert-1",
        timestamp="2026-07-17T19:00:00+00:00",
        source="suricata",
        severity="medium",
        title="SURICATA STREAM excessive retransmissions",
        src_ip="192.168.0.172",
        dst_ip="192.168.0.212",
        dst_port=8000,
        proto="TCP",
        signature_id=2210054,
        verdict="pending",
    ))

    card_id = await tmp_db.insert_scout_card(
        alert_id="scout-alert-1",
        model="granite3.3:8b",
        score=2,
        reasons=["first_seen_src_dst_port_tuple_30d", "host01_local_suricata_scope"],
        extracted={"source": "suricata", "src_ip": "192.168.0.172"},
        context_facts=["Host01 Suricata sees only Host01 traffic"],
        scout_note="Candidate missed signal. No verdict made.",
    )

    alert = await tmp_db.get_alert("scout-alert-1")
    cards = await tmp_db.get_scout_cards()

    assert card_id
    assert alert["verdict"] == "pending"
    assert len(cards) == 1
    assert cards[0]["alert_id"] == "scout-alert-1"
    assert json.loads(cards[0]["reasons"]) == [
        "first_seen_src_dst_port_tuple_30d",
        "host01_local_suricata_scope",
    ]


@pytest.mark.asyncio
async def test_scout_scores_rare_internal_management_tuple(tmp_db):
    alert = Alert(
        id="rare-ssh-1",
        timestamp="2026-07-17T19:00:00+00:00",
        source="suricata",
        severity="low",
        title="Internal SSH connection",
        src_ip="192.168.0.125",
        dst_ip="192.168.0.172",
        dst_port=22,
        proto="TCP",
        verdict="suppress",
    )
    await tmp_db.insert_alert(alert)

    worker = ScoutWorker(ScoutConfig(enabled=True, min_score=2), tmp_db)
    score, reasons = await worker._score_alert((await tmp_db.get_alert("rare-ssh-1")))

    assert score >= 2
    assert "first_seen_src_dst_port_tuple_30d" in reasons
    assert "internal_management_port:22" in reasons
    assert "suppressed_but_rare" in reasons


@pytest.mark.asyncio
async def test_scout_scores_private_host_to_management_plane_asset(tmp_db, tmp_path):
    invariants = tmp_path / "data" / "scout_node_invariants.json"
    invariants.parent.mkdir()
    invariants.write_text(json.dumps({
        "management_plane_hosts": ["192.168.0.181"],
    }))
    await tmp_db.insert_alert(Alert(
        id="iptv-to-ilo-1",
        timestamp="2026-07-19T04:30:00+00:00",
        source="suricata",
        severity="low",
        title="HTTP connection to management interface",
        src_ip="192.168.0.55",
        dst_ip="192.168.0.181",
        dst_port=443,
        proto="TCP",
        verdict="suppress",
    ))

    worker = ScoutWorker(ScoutConfig(enabled=True, min_score=2), tmp_db, repo_root=tmp_path)
    score, reasons = await worker._score_alert(await tmp_db.get_alert("iptv-to-ilo-1"))

    assert score >= 2
    assert "first_seen_src_dst_port_tuple_30d" in reasons
    assert "internal_to_management_plane:443" in reasons
    assert "suppressed_but_rare" in reasons


@pytest.mark.asyncio
async def test_get_unscouted_alerts_skips_existing_card(tmp_db):
    await tmp_db.insert_alert(Alert(
        id="unscouted-1",
        timestamp="2026-07-17T19:00:00+00:00",
        source="syslog",
        title="D-Link router syslog",
        src_ip="192.168.0.1",
    ))
    await tmp_db.insert_alert(Alert(
        id="scouted-1",
        timestamp="2026-07-17T19:00:00+00:00",
        source="syslog",
        title="D-Link router syslog",
        src_ip="192.168.0.2",
    ))
    await tmp_db.insert_scout_card(
        alert_id="scouted-1",
        model="test",
        score=1,
        reasons=["test"],
        extracted={},
        context_facts=[],
        scout_note="test",
    )

    rows = await tmp_db.get_unscouted_alerts(limit=10, lookback_hours=24 * 24)
    ids = {row["id"] for row in rows}

    assert "unscouted-1" in ids
    assert "scouted-1" not in ids


@pytest.mark.asyncio
async def test_scout_ignores_suppressed_suricata_stream_noise(tmp_db):
    await tmp_db.insert_alert(Alert(
        id="stream-noise-1",
        timestamp="2026-07-17T19:00:00+00:00",
        source="suricata",
        severity="medium",
        title="SURICATA STREAM excessive retransmissions",
        category="Generic Protocol Command Decode",
        src_ip="1.1.1.1",
        src_port=53,
        dst_ip="192.168.0.172",
        dst_port=40990,
        proto="TCP",
        verdict="suppress",
    ))

    worker = ScoutWorker(ScoutConfig(enabled=True, min_score=2), tmp_db)
    score, reasons = await worker._score_alert(await tmp_db.get_alert("stream-noise-1"))

    assert score == 0
    assert reasons == []
