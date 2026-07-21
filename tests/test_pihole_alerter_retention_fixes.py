"""Regression tests for three gaps Codex's audit found: the Pi-hole DNS
detector was orphaned (config fields existed in the example but not the
dataclass, and the ingestor was never started), daemon._alerter was never
assigned (breaking scheduled reports), and retention could delete alerts
still referenced by an open incident."""
from __future__ import annotations

import asyncio
import json

import pytest

from shallots.config import PiHoleConfig, Config


def test_pihole_config_has_dns_detector_fields():
    cfg = PiHoleConfig()
    assert hasattr(cfg, "dns_enabled") and cfg.dns_enabled is False
    assert hasattr(cfg, "db_path") and cfg.db_path
    assert hasattr(cfg, "poll_interval_sec") and cfg.poll_interval_sec > 0


def test_daemon_wires_pihole_dns_ingestor_when_enabled():
    import inspect
    from shallots.daemon import Daemon
    src = inspect.getsource(Daemon._start_ingestors)
    assert "pihole.dns_enabled" in src
    assert "PiholeDnsIngestor" in src


def test_daemon_assigns_self_alerter():
    import inspect
    from shallots.daemon import Daemon
    src = inspect.getsource(Daemon.run)
    assert "self._alerter = _incident_alerter" in src


def test_daemon_starts_alerter_worker_for_ntfy_only():
    import inspect
    from shallots.daemon import Daemon
    src = inspect.getsource(Daemon.run)
    assert "self.cfg.alerting.ntfy.enabled" in src
    assert "self.cfg.alerting.syslog.enabled" in src


@pytest.mark.asyncio
async def test_retention_keeps_alerts_referenced_by_open_incident(tmp_path):
    from shallots.store.db import AlertDB
    from shallots.store.models import Alert, now_iso

    db = AlertDB(str(tmp_path / "test.db"))
    await db.connect()
    try:
        old_alert = Alert(
            source="test", severity="high", title="old but referenced",
            category="test", timestamp=now_iso(),
        )
        old_id = await db.insert_alert(old_alert)
        await db._db.execute(
            "UPDATE alerts SET ingested_at = datetime('now', '-90 days') WHERE id = ?",
            (old_id,),
        )
        await db._db.execute(
            """INSERT INTO incidents
               (id, title, summary, status, alert_ids, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            ("inc-1", "test incident", "", "new", json.dumps([old_id]),
             now_iso(), now_iso()),
        )
        await db._db.commit()

        deleted = await db.retention_cleanup(max_age_days=30)
        assert deleted == 0

        remaining = await db.get_alerts(limit=10)
        assert any(a["id"] == old_id for a in remaining)
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_retention_deletes_old_alerts_not_in_open_incident(tmp_path):
    from shallots.store.db import AlertDB
    from shallots.store.models import Alert, now_iso

    db = AlertDB(str(tmp_path / "test.db"))
    await db.connect()
    try:
        old_alert = Alert(
            source="test", severity="low", title="old and unreferenced",
            category="test", timestamp=now_iso(),
        )
        old_id = await db.insert_alert(old_alert)
        await db._db.execute(
            "UPDATE alerts SET ingested_at = datetime('now', '-90 days') WHERE id = ?",
            (old_id,),
        )
        await db._db.commit()

        deleted = await db.retention_cleanup(max_age_days=30)
        assert deleted == 1
    finally:
        await db.close()
