"""Tests for shallots.agent_watchdog."""
from __future__ import annotations

import sqlite3
import time
from datetime import datetime, timedelta, timezone

import pytest

from shallots.agent_watchdog import (
    AGENT_OFFLINE_SIG_ID,
    OfflineAgent,
    detect_offline_agents,
    ensure_state_table,
    make_alert,
    mark_recovered,
    offline_alerts_to_emit,
)


SCHEMA = """
CREATE TABLE agent_status (
    agent_name TEXT PRIMARY KEY,
    agent_type TEXT,
    last_heartbeat TEXT
);
CREATE TABLE agent_heartbeats (
    agent_name TEXT PRIMARY KEY,
    agent_type TEXT,
    last_seen TEXT
);
"""


@pytest.fixture()
def db():
    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA)
    return conn


def _iso(seconds_ago: int, *, now: float | None = None) -> str:
    base = datetime.fromtimestamp(now if now is not None else time.time(), timezone.utc)
    return (base - timedelta(seconds=seconds_ago)).isoformat()


def test_detects_clove_offline_at_31_minutes(db):
    now = 1_700_000_000.0
    db.execute(
        "INSERT INTO agent_heartbeats VALUES (?, ?, ?)",
        ("host04-clove", "clove", _iso(31 * 60, now=now)),
    )
    db.commit()
    out = detect_offline_agents(db, now=now)
    assert len(out) == 1
    assert out[0].name == "host04-clove"
    assert out[0].age_seconds >= 30 * 60


def test_does_not_flag_recent_heartbeat(db):
    now = 1_700_000_000.0
    db.execute(
        "INSERT INTO agent_heartbeats VALUES (?, ?, ?)",
        ("host04-clove", "clove", _iso(60, now=now)),
    )
    db.commit()
    assert detect_offline_agents(db, now=now) == []


def test_argus_threshold_is_higher_than_clove(db):
    now = 1_700_000_000.0
    # 45 minutes — over clove threshold (30m), under argus threshold (60m)
    db.execute(
        "INSERT INTO agent_status VALUES (?, ?, ?)",
        ("host02-argus", "argus", _iso(45 * 60, now=now)),
    )
    db.commit()
    assert detect_offline_agents(db, now=now) == []


def test_uses_oldest_age_when_agent_in_both_tables(db):
    now = 1_700_000_000.0
    db.execute(
        "INSERT INTO agent_status VALUES (?, ?, ?)",
        ("dual", "clove", _iso(45 * 60, now=now)),
    )
    db.execute(
        "INSERT INTO agent_heartbeats VALUES (?, ?, ?)",
        ("dual", "clove", _iso(30 * 60 + 5, now=now)),
    )
    db.commit()
    out = detect_offline_agents(db, now=now)
    assert len(out) == 1
    # Should reflect the older of the two ages
    assert out[0].age_seconds >= 45 * 60


def test_make_alert_has_expected_shape():
    a = OfflineAgent(name="host04", kind="clove", last_seen="2026-04-18T00:00:00Z", age_seconds=3700)
    alert = make_alert(a)
    assert alert.signature_id == AGENT_OFFLINE_SIG_ID
    # Agent-offline is an operational-health signal, not a threat (see make_alert):
    # LOW + SUPPRESS keeps it recorded without polluting the escalation ladder.
    assert alert.severity == "low"
    assert "host04" in alert.title
    assert alert.src_asset == "host04"
    assert alert.dedup_hash == "agent-offline:host04"
    assert alert.verdict == "suppress"


def test_emits_once_within_cooldown(db):
    now = 1_700_000_000.0
    ensure_state_table(db)
    offline = [OfflineAgent(name="x", kind="clove", last_seen=_iso(31 * 60, now=now), age_seconds=31 * 60)]

    first = offline_alerts_to_emit(db, offline, cooldown_seconds=3600, now=now)
    assert len(first) == 1
    second = offline_alerts_to_emit(db, offline, cooldown_seconds=3600, now=now + 60)
    assert second == []


def test_emits_again_after_cooldown(db):
    now = 1_700_000_000.0
    ensure_state_table(db)
    offline = [OfflineAgent(name="x", kind="clove", last_seen="ts", age_seconds=31 * 60)]
    first = offline_alerts_to_emit(db, offline, cooldown_seconds=60, now=now)
    second = offline_alerts_to_emit(db, offline, cooldown_seconds=60, now=now + 120)
    assert len(first) == 1 and len(second) == 1
    # And a fresh dedupe hash is the same per agent
    assert first[0].dedup_hash == second[0].dedup_hash


def test_mark_recovered_resets_state(db):
    now = 1_700_000_000.0
    ensure_state_table(db)
    offline = [OfflineAgent(name="x", kind="clove", last_seen="ts", age_seconds=31 * 60)]
    offline_alerts_to_emit(db, offline, cooldown_seconds=3600, now=now)

    mark_recovered(db, "x")
    again = offline_alerts_to_emit(db, offline, cooldown_seconds=3600, now=now + 5)
    assert len(again) == 1


def test_handles_unparseable_last_seen(db):
    db.execute(
        "INSERT INTO agent_heartbeats VALUES (?, ?, ?)",
        ("garbled", "clove", "not-a-date"),
    )
    db.commit()
    out = detect_offline_agents(db, now=1_700_000_000.0)
    assert len(out) == 1
    assert out[0].name == "garbled"
    assert out[0].age_seconds == 0
