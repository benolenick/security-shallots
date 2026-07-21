"""Tests for component-aware health checks."""

from __future__ import annotations

import pytest

import os
import time

from shallots.config import Config
from shallots.health import _sqlite_db_growing, check_all


@pytest.mark.asyncio
async def test_check_all_skips_disabled_suricata(monkeypatch, tmp_db):
    cfg = Config()
    cfg.components.suricata = False
    cfg.components.wazuh = False
    cfg.components.crowdsec = False
    cfg.ai.tier = "none"
    cfg.storage.db_path = tmp_db.db_path

    def fail_process_check(_name: str) -> bool:
        raise AssertionError("disabled Suricata should not be probed")

    def fail_file_check(_path: str, staleness_sec: int = 300) -> tuple[bool, str]:
        raise AssertionError("disabled Suricata EVE file should not be probed")

    monkeypatch.setattr("shallots.health._process_running", fail_process_check)
    monkeypatch.setattr("shallots.health._file_exists_and_growing", fail_file_check)

    checks = await check_all(cfg)
    names = {name for name, _ok, _detail in checks}

    assert "suricata_process" not in names
    assert "suricata_eve_file" not in names
    assert "database" in names


@pytest.mark.asyncio
async def test_check_all_covers_pihole_dns_and_execmon_when_enabled(tmp_db, tmp_path):
    cfg = Config()
    cfg.components.suricata = False
    cfg.components.wazuh = False
    cfg.components.crowdsec = False
    cfg.ai.tier = "none"
    cfg.storage.db_path = tmp_db.db_path

    fake_pihole_db = tmp_path / "pihole-FTL.db"
    fake_pihole_db.write_text("x")
    cfg.pihole.dns_enabled = True
    cfg.pihole.db_path = str(fake_pihole_db)

    fake_audit_log = tmp_path / "audit.log"
    fake_audit_log.write_text("x")
    cfg.execmon.enabled = True
    cfg.execmon.audit_log_path = str(fake_audit_log)

    checks = await check_all(cfg)
    by_name = {name: ok for name, ok, _detail in checks}

    assert "pihole_dns_source" in by_name and by_name["pihole_dns_source"] is True
    assert "execmon_audit_log" in by_name and by_name["execmon_audit_log"] is True


@pytest.mark.asyncio
async def test_check_all_skips_pihole_dns_and_execmon_when_disabled(tmp_db):
    cfg = Config()
    cfg.components.suricata = False
    cfg.components.wazuh = False
    cfg.components.crowdsec = False
    cfg.ai.tier = "none"
    cfg.storage.db_path = tmp_db.db_path
    cfg.pihole.dns_enabled = False
    cfg.execmon.enabled = False

    checks = await check_all(cfg)
    names = {name for name, _ok, _detail in checks}

    assert "pihole_dns_source" not in names
    assert "execmon_audit_log" not in names


def test_sqlite_db_growing_is_wal_aware(tmp_path):
    """A SQLite DB in WAL mode (Pi-hole's pihole-FTL.db, notably) only
    advances the base file's mtime on a periodic checkpoint - live activity
    lands in the -wal sidecar. Live data on 2026-07-21: the base file was 16
    minutes stale while -wal had just been written a second ago. A plain
    mtime check on the base file alone would flag an actively-written DB as
    stalled every checkpoint interval."""
    db = tmp_path / "pihole-FTL.db"
    wal = tmp_path / "pihole-FTL.db-wal"
    db.write_text("x")
    wal.write_text("y")

    old = time.time() - 900  # 15 minutes ago
    os.utime(db, (old, old))
    # wal keeps its just-written (fresh) mtime

    ok, detail = _sqlite_db_growing(str(db), staleness_sec=300)
    assert ok is True, detail


def test_sqlite_db_growing_flags_truly_stale_db(tmp_path):
    db = tmp_path / "pihole-FTL.db"
    db.write_text("x")
    old = time.time() - 900
    os.utime(db, (old, old))
    # no -wal sidecar at all - genuinely stale
    ok, detail = _sqlite_db_growing(str(db), staleness_sec=300)
    assert ok is False
