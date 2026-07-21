"""Tests for shallots.source_watchdog.

health.check_all() already existed but was only ever invoked by hand from
the CLI - a source going silent (Suricata, Wazuh, Pi-hole, execmon,
CrowdSec, disk/RAM) was invisible unless someone happened to run
`shallotctl health`. This wires it into an automatic, cooldown'd,
auto-recovering alert stream, same pattern as agent_watchdog.py."""
from __future__ import annotations

import sqlite3
import time

import pytest

from shallots.source_watchdog import (
    SOURCE_HEALTH_SIG_ID,
    ensure_state_table,
    make_alert,
    results_to_alerts,
)


@pytest.fixture()
def db():
    conn = sqlite3.connect(":memory:")
    ensure_state_table(conn)
    return conn


def test_make_alert_is_low_severity_and_suppressed():
    a = make_alert("suricata_eve_file", "file not updated in 12m: /var/log/suricata/eve.json")
    assert a.severity == "low"
    assert a.verdict == "suppress"
    assert a.category == "source_health"
    assert a.signature_id == SOURCE_HEALTH_SIG_ID
    assert "suricata_eve_file" in a.title


def test_failing_check_emits_alert(db):
    results = [("suricata_eve_file", False, "file not updated in 12m")]
    alerts = results_to_alerts(db, results)
    assert len(alerts) == 1
    assert alerts[0].source_ref == "source_watchdog:suricata_eve_file"


def test_passing_check_emits_nothing(db):
    results = [("database", True, "ok")]
    assert results_to_alerts(db, results) == []


def test_cooldown_suppresses_repeat_alert(db):
    results = [("crowdsec_lapi", False, "unreachable")]
    first = results_to_alerts(db, results, now=1000.0)
    assert len(first) == 1
    # Same failure 60s later, still inside the 6h cooldown
    second = results_to_alerts(db, results, now=1060.0)
    assert second == []


def test_recovery_then_failure_realerts_immediately(db):
    down = [("ollama", False, "connection refused")]
    up = [("ollama", True, "ok")]

    first = results_to_alerts(db, down, now=1000.0)
    assert len(first) == 1

    # Recovers - clears state
    assert results_to_alerts(db, up, now=1010.0) == []

    # Fails again seconds later - not held back by the old cooldown, because
    # the passing check in between cleared the state row.
    second = results_to_alerts(db, down, now=1020.0)
    assert len(second) == 1


def test_multiple_independent_checks_tracked_separately(db):
    results = [
        ("suricata_eve_file", False, "stale"),
        ("database", True, "ok"),
        ("ram_usage", False, "critical"),
    ]
    alerts = results_to_alerts(db, results, now=1000.0)
    names = {a.source_ref for a in alerts}
    assert names == {"source_watchdog:suricata_eve_file", "source_watchdog:ram_usage"}
