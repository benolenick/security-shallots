from __future__ import annotations

import sqlite3

from shallots.posture import engine
from shallots.posture.engine import connect, prune, simhash, stable_id


def test_simhash_is_stable_for_same_text() -> None:
    assert simhash("hello world") == simhash("hello world")


def test_stable_id_changes_with_parts() -> None:
    assert stable_id("a", "b") != stable_id("a", "c")


def test_connect_creates_core_tables(tmp_path) -> None:
    db = tmp_path / "posture.db"
    con = connect(db)
    try:
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        con.close()
    assert "sensor_coverage" in tables
    assert "alert_memory" in tables
    assert "escalation_cards" in tables


def _seed_shallots_db(path) -> None:
    db = sqlite3.connect(path)
    db.execute(
        """CREATE TABLE alerts (id TEXT, timestamp TEXT, ingested_at TEXT, source TEXT,
           severity TEXT, title TEXT, description TEXT, src_ip TEXT, dst_ip TEXT,
           category TEXT, verdict TEXT, confidence REAL, ai_reasoning TEXT)"""
    )
    db.executemany(
        "INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [
            ("a1", "2026-07-19T00:00:01+00:00", "2026-07-19T00:00:01+00:00", "syslog",
             "low", "Syslog [user]", "d", "", "", "user", "pending", 0.1, ""),
            ("a2", "2026-07-19T00:00:02+00:00", "2026-07-19T00:00:02+00:00", "syslog",
             "low", "Syslog [user]", "d", "", "", "user", "pending", 0.1, ""),
        ],
    )
    db.commit()
    db.close()


def test_alert_memory_counts_each_alert_once_across_scans(tmp_path, monkeypatch) -> None:
    """Regression: the trailing-window was re-counted every scan, inflating counts."""
    shallots_db = tmp_path / "shallots.db"
    _seed_shallots_db(shallots_db)
    monkeypatch.setattr(engine, "SHALLOTS_DB", shallots_db)
    monkeypatch.setattr(engine, "CARD_DIR", tmp_path / "cards")
    con = connect(tmp_path / "posture.db")
    try:
        engine.scan_alert_memory_and_cards(con, engine.DEFAULT_POLICY)
        engine.scan_alert_memory_and_cards(con, engine.DEFAULT_POLICY)  # second scan, same rows
        engine.scan_alert_memory_and_cards(con, engine.DEFAULT_POLICY)  # third scan, same rows
        total = con.execute("SELECT COALESCE(SUM(count),0) FROM alert_memory").fetchone()[0]
        # Two alerts, identical text -> one simhash, count must equal 2 (once each),
        # not 6 (2 rows x 3 scans).
        assert total == 2
    finally:
        con.close()


def test_persistent_egress_is_not_scored_as_beacon(tmp_path) -> None:
    """Regression: snapshot-based inter-arrival made persistent sessions look periodic."""
    con = connect(tmp_path / "posture.db")
    try:
        con.execute("UPDATE kv SET value='1' WHERE key='bootstrap_complete'")
        con.execute(
            "INSERT OR REPLACE INTO kv(key,value,updated_at) VALUES('bootstrap_complete','1','x')"
        )
        # A tuple continuously present: present_last stays 1, reconnects never grow.
        con.execute(
            "INSERT INTO egress_memory VALUES('h','9.9.9.9',443,'tcp','t','t',20,900,0,1000.0,1,0)"
        )
        row = con.execute("SELECT reconnects,present_last FROM egress_memory").fetchone()
        assert row["reconnects"] == 0 and row["present_last"] == 1
    finally:
        con.close()


def test_prune_drops_old_rows(tmp_path) -> None:
    con = connect(tmp_path / "posture.db")
    try:
        con.execute(
            "INSERT INTO dns_memory(domain,etld1,first_seen,last_seen,count,dga_score)"
            " VALUES('old.example','example','2000-01-01T00:00:00+00:00','2000-01-01T00:00:00+00:00',1,0)"
        )
        con.execute(
            "INSERT INTO dns_memory(domain,etld1,first_seen,last_seen,count,dga_score)"
            " VALUES('fresh.example','example',?,?,1,0)",
            (engine.now_iso(), engine.now_iso()),
        )
        result = prune(con, engine.DEFAULT_POLICY)
        remaining = {r[0] for r in con.execute("SELECT domain FROM dns_memory")}
        assert result["pruned_rows"] >= 1
        assert remaining == {"fresh.example"}
    finally:
        con.close()
