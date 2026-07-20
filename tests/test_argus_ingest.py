"""Tests for Argus ingest normalization."""

from __future__ import annotations

import asyncio
import json

from shallots.ingest.argus import (
    _parse_argus_event,
    argus_secret_allowed,
    argus_source_allowed,
    normalize_argus_events,
    route_argus_heartbeat,
)


def _event(title: str) -> dict:
    return {
        "timestamp": "2026-07-15T01:35:42.123+00:00",
        "host": "host02",
        "event_type": "synthetic_experiment",
        "severity": "low",
        "title": title,
        "description": "concurrent load test",
        "category": "experiment",
        "details": {"idx": title.rsplit(" ", 1)[-1]},
    }


def test_argus_dedup_hash_keeps_distinct_same_millisecond_events() -> None:
    first = _parse_argus_event(_event("Synthetic event 1"), json.dumps(_event("Synthetic event 1")))
    second = _parse_argus_event(_event("Synthetic event 2"), json.dumps(_event("Synthetic event 2")))

    assert first is not None
    assert second is not None
    assert first.dedup_hash != second.dedup_hash


def test_argus_dedup_hash_matches_exact_repeated_event() -> None:
    event = _event("Synthetic event 1")

    first = _parse_argus_event(event, json.dumps(event))
    second = _parse_argus_event(event, json.dumps(event))

    assert first is not None
    assert second is not None
    assert first.dedup_hash == second.dedup_hash


def test_argus_network_egress_maps_remote_tuple() -> None:
    event = {
        "timestamp": "2026-07-15T01:35:42.123+00:00",
        "host": "host02",
        "event_type": "network_egress_suspicious",
        "severity": "high",
        "title": "Suspicious outbound connection",
        "description": "ngrok opened public egress",
        "category": "c2",
        "details": {"remote_ip": "8.8.8.8", "remote_port": 443, "process": "ngrok"},
    }

    alert = _parse_argus_event(event, json.dumps(event))

    assert alert is not None
    assert alert.source_ref == "network_egress_suspicious"
    assert alert.dst_ip == "8.8.8.8"
    assert alert.dst_port == 443
    assert alert.signature_id == 900009


def test_argus_heartbeat_routes_to_both_agent_tables() -> None:
    class FakeDB:
        def __init__(self) -> None:
            self.agent_status = []
            self.agent_heartbeats = []

        async def upsert_agent_heartbeat(self, **kwargs):
            self.agent_status.append(kwargs)

        async def upsert_clove_heartbeat(self, **kwargs):
            self.agent_heartbeats.append(kwargs)
            return {"update": False}

    db = FakeDB()
    event = {
        "host": "host02",
        "event_type": "heartbeat",
        "state": "ARMED_HOME",
        "details": {
            "os": "linux",
            "ip_address": "192.168.0.212",
            "version": "1.2.3",
            "active_monitors": ["file_sentinel"],
            "telemetry": {
                "events_emitted": 42,
                "non_heartbeat_events_emitted": 1,
                "webhook_last_ok": True,
            },
        },
    }

    commands = asyncio.run(route_argus_heartbeat(db, event, "192.168.0.99"))

    assert commands == {"update": False}
    assert db.agent_status[0]["agent_name"] == "host02"
    assert db.agent_status[0]["ip"] == "192.168.0.212"
    health = json.loads(db.agent_status[0]["health_data"])
    assert health["telemetry"]["events_emitted"] == 42
    assert health["telemetry"]["webhook_last_ok"] is True
    assert db.agent_heartbeats[0]["agent_name"] == "host02"
    assert db.agent_heartbeats[0]["agent_type"] == "argus"


def test_argus_source_allowed_defaults_open_for_back_compat() -> None:
    assert argus_source_allowed("192.168.0.212", [])


def test_argus_source_allowed_enforces_cidrs() -> None:
    assert argus_source_allowed("192.168.0.212", ["192.168.0.212/32", "192.168.0.224/32"])
    assert not argus_source_allowed("192.168.0.99", ["192.168.0.212/32", "192.168.0.224/32"])
    assert not argus_source_allowed("", ["192.168.0.212/32"])


def test_normalize_argus_events_rejects_non_event_json_shapes() -> None:
    assert normalize_argus_events("not-an-event") is None
    assert normalize_argus_events([{"host": "host02"}, "not-an-event"]) is None
    assert normalize_argus_events({"host": "host02"}) == [{"host": "host02"}]


def test_argus_secret_allows_per_agent_secret() -> None:
    events = [{"host": "host02", "event_type": "heartbeat"}]

    assert argus_secret_allowed(
        "agent-token",
        events,
        agent_secrets={"host02": "agent-token"},
        require_per_agent=True,
    )
    assert not argus_secret_allowed(
        "shared-token",
        events,
        shared_secret="shared-token",
        agent_secrets={"host02": "agent-token"},
        require_per_agent=True,
    )


def test_argus_secret_rejects_mixed_agent_batch_when_per_agent_required() -> None:
    events = [{"host": "host02"}, {"host": "host03"}]

    assert not argus_secret_allowed(
        "agent-token",
        events,
        agent_secrets={"host02": "agent-token", "host03": "other-token"},
        require_per_agent=True,
    )
