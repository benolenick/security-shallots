"""Regression test for the auth.log replay bug.

History: argus/monitors/windows_events.py used to call ``f.readlines()`` and
iterate ``lines[-2000:]`` every poll. That re-emitted every matching line
forever. On host03 in April 2026 it produced 4.6 GB of duplicated admin_logon
events from routine cron sessions and was a contributing cause of LOCKDOWN
storms.

This test pins the contract: a second poll over the SAME file must emit zero
events. Only newly-appended lines should produce signals.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

# Argus' WindowsEventsMonitor lives in argus/monitors/windows_events.py;
# the package layout is argus/argus/monitors/...
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from argus.monitors.windows_events import WindowsEventsMonitor


@pytest.fixture()
def monitor():
    m = WindowsEventsMonitor.__new__(WindowsEventsMonitor)
    m._last_seen = datetime.now(timezone.utc)
    return m


def _write(p: Path, lines: list[str]) -> None:
    with p.open("w") as f:
        f.write("\n".join(lines) + "\n")


def _append(p: Path, lines: list[str]) -> None:
    with p.open("a") as f:
        f.write("\n".join(lines) + "\n")


@pytest.fixture()
def auth_log(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text("")
    return p


def test_second_poll_with_no_new_lines_emits_nothing(tmp_path, monitor, auth_log):
    """The core regression. After a first poll, calling again with an
    UNCHANGED file must produce zero events. Used to produce N events forever."""
    _write(auth_log, ["Apr 16 10:00:00 host sshd[1]: Failed password for invalid user x from 1.2.3.4"])
    import os as _os

    real_open = open
    def fake_open(p, *a, **k):
        if p in ("/var/log/auth.log", "/var/log/secure"):
            return real_open(str(auth_log), *a, **k)
        return real_open(p, *a, **k)

    real_stat = _os.stat
    def fake_stat(p):
        if p in ("/var/log/auth.log", "/var/log/secure"):
            return real_stat(auth_log)
        return real_stat(p)

    real_exists = _os.path.exists
    def fake_exists(p):
        if p == "/var/log/auth.log":
            return True
        if p == "/var/log/secure":
            return False
        return real_exists(p)

    with patch("argus.monitors.windows_events.os.path.exists", fake_exists), \
         patch("argus.monitors.windows_events.os.stat", fake_stat), \
         patch("builtins.open", side_effect=fake_open):
        first = monitor._read_auth_log_linux()
        second = monitor._read_auth_log_linux()
        third = monitor._read_auth_log_linux()
    # First call initializes the cursor at EOF — historical lines are not replayed
    assert first == []
    assert second == []
    assert third == []


def test_only_newly_appended_lines_are_emitted(tmp_path, monitor, auth_log):
    """After init, appending new lines emits exactly those lines."""
    _write(auth_log, ["initial line"])

    real_open, real_stat, real_exists = open, __import__("os").stat, __import__("os").path.exists
    def fo(p, *a, **k): return real_open(str(auth_log) if p in ("/var/log/auth.log", "/var/log/secure") else p, *a, **k)
    def fs(p): return real_stat(auth_log) if p in ("/var/log/auth.log", "/var/log/secure") else real_stat(p)
    def fe(p):
        if p == "/var/log/auth.log": return True
        if p == "/var/log/secure": return False
        return real_exists(p)

    with patch("argus.monitors.windows_events.os.path.exists", fe), \
         patch("argus.monitors.windows_events.os.stat", fs), \
         patch("builtins.open", side_effect=fo):
        # First call: cursor at EOF, no events (initialization).
        assert monitor._read_auth_log_linux() == []

        _append(auth_log, [
            "Apr 16 10:00:00 host sshd[1]: Failed password for invalid user x from 1.2.3.4",
            "Apr 16 10:00:01 host sshd[2]: Accepted publickey for root from 5.6.7.8",
        ])

        out = monitor._read_auth_log_linux()
    assert len(out) == 2
    assert out[0].event_type == "failed_logon"
    assert out[1].event_type == "admin_logon"

    # And again — no new lines, no events.
    with patch("argus.monitors.windows_events.os.path.exists", fe), \
         patch("argus.monitors.windows_events.os.stat", fs), \
         patch("builtins.open", side_effect=fo):
        assert monitor._read_auth_log_linux() == []


def test_cron_root_session_pattern_is_no_longer_matched(tmp_path, monitor, auth_log):
    """The pattern that caused the LOCKDOWN storm — pam_unix cron root session
    opens — must NOT produce events. They are routine."""
    _write(auth_log, [""])

    real_open, real_stat, real_exists = open, __import__("os").stat, __import__("os").path.exists
    def fo(p, *a, **k): return real_open(str(auth_log) if p in ("/var/log/auth.log", "/var/log/secure") else p, *a, **k)
    def fs(p): return real_stat(auth_log) if p in ("/var/log/auth.log", "/var/log/secure") else real_stat(p)
    def fe(p):
        if p == "/var/log/auth.log": return True
        if p == "/var/log/secure": return False
        return real_exists(p)

    with patch("argus.monitors.windows_events.os.path.exists", fe), \
         patch("argus.monitors.windows_events.os.stat", fs), \
         patch("builtins.open", side_effect=fo):
        assert monitor._read_auth_log_linux() == []
        _append(auth_log, [
            "Apr 16 10:00:00 host CRON[1234]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)",
            "Apr 16 10:00:00 host CRON[1235]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)",
            "Apr 16 10:00:00 host CRON[1236]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)",
        ])
        out = monitor._read_auth_log_linux()
    assert out == [], (
        f"cron pam_unix root session pattern produced {len(out)} events — "
        "this is the bug we're regressing against"
    )
