import sqlite3
from datetime import datetime, timezone

from tools import shallot_syslog_canary
from tools.shallot_syslog_canary import build_message, cleanup_rows, priority_for_token, run_canary


def test_build_message_contains_canary_token() -> None:
    payload = build_message("abc123", now=datetime(2026, 7, 15, 8, 0, tzinfo=timezone.utc))

    assert b"shallot-syslog-canary-test token=abc123" in payload
    assert payload.startswith(f"<{priority_for_token('abc123')}>".encode())


def test_priority_for_token_keeps_low_severity_and_varies() -> None:
    first = priority_for_token("token-a")
    second = priority_for_token("token-b")

    assert first & 0x7 == 6
    assert second & 0x7 == 6
    assert first != second


def _make_db(path):
    con = sqlite3.connect(path)
    con.execute(
        """
        CREATE TABLE alerts (
            id TEXT,
            timestamp TEXT,
            source TEXT,
            src_ip TEXT,
            src_asset TEXT,
            title TEXT,
            description TEXT,
            raw TEXT,
            verdict TEXT,
            confidence REAL,
            ai_reasoning TEXT
        )
        """
    )
    return con


def test_cleanup_rows_deletes_only_matching_local_syslog(tmp_path):
    db_path = tmp_path / "shallots.db"
    con = _make_db(db_path)
    con.execute(
        "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("match", "2026-07-15T08:00:00Z", "syslog", "127.0.0.1", "", "", "token abc", "token abc", "pending", 0.0, ""),
    )
    con.execute(
        "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("remote", "2026-07-15T08:00:00Z", "syslog", "192.168.0.1", "", "", "token abc", "token abc", "pending", 0.0, ""),
    )
    con.commit()
    con.close()

    assert cleanup_rows(str(db_path), "missing", mode="keep") == 0
    assert cleanup_rows(str(db_path), "abc", mode="delete") == 1

    con = sqlite3.connect(db_path)
    try:
        assert [row[0] for row in con.execute("SELECT id FROM alerts ORDER BY id")] == ["remote"]
    finally:
        con.close()


def test_cleanup_rows_can_suppress_matching_local_syslog(tmp_path):
    db_path = tmp_path / "shallots.db"
    con = _make_db(db_path)
    con.execute(
        "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("match", "2026-07-15T08:00:00Z", "syslog", "127.0.0.1", "", "", "token abc", "token abc", "pending", 0.0, ""),
    )
    con.commit()
    con.close()

    assert cleanup_rows(str(db_path), "abc", mode="suppress") == 1

    con = sqlite3.connect(db_path)
    try:
        verdict, confidence = con.execute("SELECT verdict, confidence FROM alerts WHERE id = 'match'").fetchone()
        assert verdict == "suppress"
        assert confidence == 1.0
    finally:
        con.close()


def test_run_canary_writes_ok_state(monkeypatch, tmp_path):
    class Config:
        class storage:
            db_path = "shallots.db"

        class syslog:
            udp_port = 5514

    monkeypatch.setattr(shallot_syslog_canary, "load_config", lambda _path: Config())
    monkeypatch.setattr(shallot_syslog_canary, "send_udp", lambda host, port, payload: None)
    monkeypatch.setattr(
        shallot_syslog_canary,
        "wait_for_rows",
        lambda db, token, timeout_seconds: [{"id": "row1", "description": token}],
    )
    monkeypatch.setattr(shallot_syslog_canary, "cleanup_rows", lambda db, token, mode: 1)

    state = tmp_path / "state.json"
    result = run_canary(config="config.yaml", state_path=str(state))

    assert result["status"] == "ok"
    assert result["matched"] == 1
    assert result["attempts"] == 3
    assert result["attempts_used"] == 1
    assert result["consecutive_failures"] == 0
    assert result["consecutive_successes"] == 1
    assert result["last_ok_at"] == result["sent_at"]
    assert state.exists()


def test_run_canary_retries_transient_miss(monkeypatch, tmp_path):
    class Config:
        class storage:
            db_path = "shallots.db"

        class syslog:
            udp_port = 5514

    sends = []
    waits = iter([[], [{"id": "row1", "description": "matched"}]])
    monkeypatch.setattr(shallot_syslog_canary, "load_config", lambda _path: Config())
    monkeypatch.setattr(shallot_syslog_canary, "send_udp", lambda host, port, payload: sends.append((host, port, payload)))
    monkeypatch.setattr(
        shallot_syslog_canary,
        "wait_for_rows",
        lambda db, token, timeout_seconds: next(waits),
    )
    monkeypatch.setattr(shallot_syslog_canary, "cleanup_rows", lambda db, token, mode: 1)

    result = run_canary(config="config.yaml", state_path=str(tmp_path / "state.json"), attempts=2)

    assert result["status"] == "ok"
    assert result["matched"] == 1
    assert result["attempts"] == 2
    assert result["attempts_used"] == 2
    assert len(sends) == 2


def test_run_canary_tracks_consecutive_failures(monkeypatch, tmp_path):
    class Config:
        class storage:
            db_path = "shallots.db"

        class syslog:
            udp_port = 5514

    monkeypatch.setattr(shallot_syslog_canary, "load_config", lambda _path: Config())
    monkeypatch.setattr(shallot_syslog_canary, "send_udp", lambda host, port, payload: None)
    monkeypatch.setattr(shallot_syslog_canary, "wait_for_rows", lambda db, token, timeout_seconds: [])

    state = tmp_path / "state.json"
    state.write_text('{"status":"fail","consecutive_failures":1,"last_ok_at":"2026-07-15T00:00:00+00:00"}')
    result = run_canary(config="config.yaml", state_path=str(state), attempts=1)

    assert result["status"] == "fail"
    assert result["consecutive_failures"] == 2
    assert result["consecutive_successes"] == 0
    assert result["last_ok_at"] == "2026-07-15T00:00:00+00:00"
    assert result["last_failure_at"] == result["sent_at"]
