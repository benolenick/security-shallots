"""Tests for shallots.audit_log."""
from __future__ import annotations

import json
import sqlite3

import pytest

from shallots.audit_log import AuditEntry, AuditLog


@pytest.fixture()
def audit():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    return AuditLog(conn)


def test_record_returns_id(audit):
    rid = audit.record(principal="alice", action="alert.ack", target_id="a1")
    assert rid > 0


def test_record_requires_principal_and_action(audit):
    with pytest.raises(ValueError):
        audit.record(principal="", action="x")
    with pytest.raises(ValueError):
        audit.record(principal="alice", action="")


def test_query_returns_newest_first(audit):
    audit.record(principal="alice", action="alert.ack", target_id="1", ts="2026-05-06T10:00:00+00:00")
    audit.record(principal="alice", action="alert.ack", target_id="2", ts="2026-05-06T11:00:00+00:00")
    audit.record(principal="bob", action="alert.suppress", target_id="3", ts="2026-05-06T12:00:00+00:00")
    out = audit.query(limit=10)
    assert [e.target_id for e in out] == ["3", "2", "1"]


def test_query_filters(audit):
    audit.record(principal="alice", action="alert.ack", target_id="1")
    audit.record(principal="bob", action="alert.ack", target_id="2")
    audit.record(principal="alice", action="alert.suppress", target_id="3")

    by_principal = audit.query(principal="alice")
    assert len(by_principal) == 2
    assert all(e.principal == "alice" for e in by_principal)

    by_action = audit.query(action="alert.suppress")
    assert len(by_action) == 1
    assert by_action[0].target_id == "3"


def test_query_filter_by_target(audit):
    audit.record(principal="alice", action="alert.ack", target_type="alert", target_id="abc")
    audit.record(principal="alice", action="alert.ack", target_type="incident", target_id="abc")
    out = audit.query(target_type="incident", target_id="abc")
    assert len(out) == 1


def test_query_time_range(audit):
    audit.record(principal="a", action="x", ts="2026-05-01T00:00:00+00:00")
    audit.record(principal="a", action="x", ts="2026-05-15T00:00:00+00:00")
    audit.record(principal="a", action="x", ts="2026-06-01T00:00:00+00:00")
    out = audit.query(since="2026-05-10T00:00:00+00:00", until="2026-05-31T00:00:00+00:00")
    assert len(out) == 1


def test_count_matches_query(audit):
    for i in range(5):
        audit.record(principal="alice", action="alert.ack", target_id=str(i))
    audit.record(principal="bob", action="alert.ack", target_id="x")
    assert audit.count() == 6
    assert audit.count(principal="alice") == 5


def test_pagination(audit):
    for i in range(25):
        audit.record(principal="alice", action="x", target_id=str(i))
    page1 = audit.query(limit=10, offset=0)
    page2 = audit.query(limit=10, offset=10)
    page3 = audit.query(limit=10, offset=20)
    assert len(page1) == 10 and len(page2) == 10 and len(page3) == 5
    # No overlap
    ids = {e.id for e in page1} | {e.id for e in page2} | {e.id for e in page3}
    assert len(ids) == 25


def test_details_round_trip(audit):
    audit.record(
        principal="alice",
        action="alert.suppress",
        target_id="sig:2054407",
        details={"reason": "false positive", "duration_days": 30, "tags": ["lan"]},
    )
    e = audit.query(action="alert.suppress")[0]
    assert e.details == {"reason": "false positive", "duration_days": 30, "tags": ["lan"]}


def test_append_only_no_update_path():
    """The class exposes record + query only — no update or delete methods."""
    public = {m for m in dir(AuditLog) if not m.startswith("_")}
    assert "record" in public and "query" in public
    assert "update" not in public and "delete" not in public


def test_indices_present(audit):
    rows = audit.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='audit_log'"
    ).fetchall()
    names = {r[0] for r in rows}
    assert {"idx_audit_ts", "idx_audit_principal", "idx_audit_action", "idx_audit_target"} <= names


def test_entry_from_tuple_row():
    """from_row works on tuple-shaped rows too (no row_factory)."""
    conn = sqlite3.connect(":memory:")
    audit = AuditLog(conn)
    audit.record(principal="x", action="y")
    row = conn.execute("SELECT id, ts, principal, action, target_type, target_id, ip, details_json FROM audit_log").fetchone()
    e = AuditEntry.from_row(row)
    assert e.principal == "x" and e.action == "y"
