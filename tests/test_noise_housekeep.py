"""Noise housekeeping tests."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
import json

import pytest

from tools.shallot_noise_housekeep import prune_synthetic, synthetic_prune_status, trim_assessment_log, write_state


def _db() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute(
        """
        CREATE TABLE alerts (
            id TEXT,
            timestamp TEXT,
            title TEXT,
            description TEXT,
            category TEXT,
            src_asset TEXT,
            dst_asset TEXT,
            source_ref TEXT
        )
        """
    )
    return con


def _insert(con: sqlite3.Connection, alert_id: str, *, hours_old: float, title: str, src_asset: str = "") -> None:
    ts = (datetime.now(timezone.utc) - timedelta(hours=hours_old)).isoformat(timespec="seconds")
    con.execute(
        "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (alert_id, ts, title, "", "", src_asset, "", ""),
    )


def _count(con: sqlite3.Connection) -> int:
    return int(con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])


def test_prune_synthetic_dry_run_counts_without_deleting() -> None:
    con = _db()
    _insert(con, "old-synthetic", hours_old=12, title="Synthetic Shallots experiment")
    _insert(con, "old-real", hours_old=12, title="ET MALWARE Possible C2 Beacon", src_asset="host02")
    _insert(con, "fresh-synthetic", hours_old=1, title="Synthetic Shallots experiment")

    count = prune_synthetic(con, older_hours=6, apply=False)

    assert count == 1
    assert _count(con) == 3


def test_prune_synthetic_deletes_only_old_synthetic_rows() -> None:
    con = _db()
    _insert(con, "old-synthetic", hours_old=12, title="Routine", src_asset="shallot-load-api")
    _insert(con, "old-real", hours_old=12, title="ET MALWARE Possible C2 Beacon", src_asset="host02")
    _insert(con, "fresh-synthetic", hours_old=1, title="Synthetic Shallots experiment")

    count = prune_synthetic(con, older_hours=6, apply=True)

    assert count == 1
    assert [row[0] for row in con.execute("SELECT id FROM alerts ORDER BY id")] == [
        "fresh-synthetic",
        "old-real",
    ]


def test_synthetic_prune_status_reports_age_and_next_eligibility() -> None:
    con = _db()
    _insert(con, "old-synthetic", hours_old=25, title="Synthetic Shallots experiment")
    _insert(con, "fresh-synthetic", hours_old=10, title="Synthetic Shallots experiment")
    _insert(con, "old-real", hours_old=25, title="ET MALWARE Possible C2 Beacon", src_asset="host02")

    status = synthetic_prune_status(con, older_hours=24)

    assert status["total_synthetic"] == 2
    assert status["timestamped_synthetic"] == 2
    assert status["prune_eligible"] == 1
    assert 24.9 <= float(status["oldest_age_hours"]) <= 25.1
    assert 9.9 <= float(status["newest_age_hours"]) <= 10.1
    assert 13.8 <= float(status["next_eligible_in_hours"]) <= 14.1


def test_prune_synthetic_refuses_short_windows() -> None:
    con = _db()

    with pytest.raises(ValueError, match="at least 6h"):
        prune_synthetic(con, older_hours=1, apply=False)


def test_trim_assessment_log_keeps_newest_sections(tmp_path) -> None:
    log = tmp_path / "assessment.md"
    log.write_text("intro\n## one\nold\n## two\nmiddle\n## three\nnew\n")

    result = trim_assessment_log(log, keep_sections=2, max_bytes=10_000, apply=True)

    assert result["trimmed"] is True
    text = log.read_text()
    assert "## one" not in text
    assert "## two" in text
    assert "## three" in text


def test_trim_assessment_log_dry_run_does_not_write(tmp_path) -> None:
    log = tmp_path / "assessment.md"
    original = "## one\nold\n## two\nnew\n"
    log.write_text(original)

    result = trim_assessment_log(log, keep_sections=1, max_bytes=10_000, apply=False)

    assert result["trimmed"] is True
    assert log.read_text() == original


def test_write_state_creates_machine_readable_json(tmp_path) -> None:
    state = tmp_path / "docs" / "NOISE_HOUSEKEEP_STATE.json"

    write_state(state, {"status": "ok", "run_at": "2026-07-15T12:00:00+00:00", "suppression_applied": 3})

    assert state.exists()
    assert '"suppression_applied": 3' in state.read_text()


def test_noise_housekeep_summary_json_is_parseable(tmp_path) -> None:
    db = tmp_path / "shallots.db"
    con = sqlite3.connect(db)
    con.execute(
        """
        CREATE TABLE alerts (
            id TEXT,
            timestamp TEXT,
            title TEXT,
            description TEXT,
            category TEXT,
            src_asset TEXT,
            dst_asset TEXT,
            source_ref TEXT,
            source TEXT,
            src_ip TEXT,
            verdict TEXT,
            confidence REAL,
            ai_reasoning TEXT
        )
        """
    )
    con.execute("CREATE TABLE agent_heartbeats (agent_name TEXT, last_seen TEXT)")
    con.execute(
        "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "synthetic",
            (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat(timespec="seconds"),
            "Synthetic Shallots experiment",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "pending",
            0.0,
            "",
        ),
    )
    con.commit()
    con.close()

    state = tmp_path / "state.json"
    completed = subprocess.run(
        [
            sys.executable,
            "tools/shallot_noise_housekeep.py",
            "--db",
            str(db),
            "--state",
            str(state),
            "--prune-synthetic-older-hours",
            "24",
            "--summary-json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(completed.stdout)
    assert payload["status"] == "ok"
    assert payload["synthetic_prune"]["status"]["prune_eligible"] == 1
    assert payload["synthetic_prune"]["matched"] == 1
    assert payload["suppression_candidates"] == 1
    assert state.exists()


def test_noise_housekeep_default_summary_reports_prune_status_without_delete(tmp_path) -> None:
    db = tmp_path / "shallots.db"
    con = sqlite3.connect(db)
    con.execute(
        """
        CREATE TABLE alerts (
            id TEXT,
            timestamp TEXT,
            title TEXT,
            description TEXT,
            category TEXT,
            src_asset TEXT,
            dst_asset TEXT,
            source_ref TEXT,
            source TEXT,
            src_ip TEXT,
            verdict TEXT,
            confidence REAL,
            ai_reasoning TEXT
        )
        """
    )
    con.execute("CREATE TABLE agent_heartbeats (agent_name TEXT, last_seen TEXT)")
    con.execute(
        "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "synthetic",
            (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat(timespec="seconds"),
            "Synthetic Shallots experiment",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "suppress",
            1.0,
            "",
        ),
    )
    con.commit()
    con.close()

    completed = subprocess.run(
        [
            sys.executable,
            "tools/shallot_noise_housekeep.py",
            "--db",
            str(db),
            "--state",
            "",
            "--summary-json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    payload = json.loads(completed.stdout)
    assert payload["synthetic_prune"]["older_hours"] == 24.0
    assert payload["synthetic_prune"]["prune_requested"] is False
    assert payload["synthetic_prune"]["status"]["prune_eligible"] == 1
    assert payload["synthetic_prune"]["matched"] == 1
    assert payload["synthetic_prune"]["deleted"] == 0

    con = sqlite3.connect(db)
    assert _count(con) == 1
