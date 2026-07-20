"""Tests for shallots.store.db.AlertDB — async SQLite backend."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest

from shallots.store.models import Alert, AlertSource, now_iso
from shallots.store.db import AlertDB


@pytest.mark.asyncio
class TestInsertAndGet:
    """Test insert_alert and get_alert roundtrip."""

    async def test_insert_and_get_roundtrip(self, tmp_db: AlertDB):
        """Insert an alert and retrieve it by ID."""
        alert = Alert(
            id="roundtrip-001",
            timestamp="2026-03-01T12:00:00+00:00",
            source="suricata",
            severity="high",
            title="Test Alert",
            description="A test alert for roundtrip",
            src_ip="10.0.0.1",
            dst_ip="93.184.216.34",
            proto="TCP",
            signature_id=12345,
        )
        returned_id = await tmp_db.insert_alert(alert)
        assert returned_id == "roundtrip-001"

        row = await tmp_db.get_alert("roundtrip-001")
        assert row is not None
        assert row["id"] == "roundtrip-001"
        assert row["source"] == "suricata"
        assert row["severity"] == "high"
        assert row["title"] == "Test Alert"
        assert row["src_ip"] == "10.0.0.1"
        assert row["dst_ip"] == "93.184.216.34"

    async def test_get_nonexistent_returns_none(self, tmp_db: AlertDB):
        result = await tmp_db.get_alert("does-not-exist")
        assert result is None

    async def test_insert_assigns_id_if_empty(self, tmp_db: AlertDB):
        """If alert.id is empty, insert_alert should assign a UUID."""
        alert = Alert(source="suricata", severity="low", title="No ID")
        returned_id = await tmp_db.insert_alert(alert)
        assert returned_id != ""
        row = await tmp_db.get_alert(returned_id)
        assert row is not None


@pytest.mark.asyncio
class TestGetAlertsFiltered:
    """Test get_alerts with source filter."""

    async def test_filter_by_source(self, tmp_db: AlertDB):
        """Filtering by source should return only matching alerts."""
        for i in range(3):
            await tmp_db.insert_alert(Alert(
                id=f"suri-{i}",
                timestamp=f"2026-03-01T12:0{i}:00+00:00",
                source="suricata",
                severity="medium",
                title=f"Suricata alert {i}",
            ))
        for i in range(2):
            await tmp_db.insert_alert(Alert(
                id=f"wazuh-{i}",
                timestamp=f"2026-03-01T13:0{i}:00+00:00",
                source="wazuh",
                severity="high",
                title=f"Wazuh alert {i}",
            ))

        suricata_only = await tmp_db.get_alerts(source="suricata")
        assert len(suricata_only) == 3
        assert all(r["source"] == "suricata" for r in suricata_only)

        wazuh_only = await tmp_db.get_alerts(source="wazuh")
        assert len(wazuh_only) == 2
        assert all(r["source"] == "wazuh" for r in wazuh_only)

    async def test_filter_by_severity(self, tmp_db: AlertDB):
        await tmp_db.insert_alert(Alert(
            id="high-1", timestamp="2026-03-01T12:00:00+00:00",
            source="suricata", severity="high", title="High severity",
        ))
        await tmp_db.insert_alert(Alert(
            id="low-1", timestamp="2026-03-01T12:01:00+00:00",
            source="suricata", severity="low", title="Low severity",
        ))
        results = await tmp_db.get_alerts(severity="high")
        assert len(results) == 1
        assert results[0]["severity"] == "high"

    async def test_get_all_no_filter(self, tmp_db: AlertDB):
        """With no filter, get_alerts should return all alerts."""
        for i in range(5):
            await tmp_db.insert_alert(Alert(
                id=f"all-{i}",
                timestamp=f"2026-03-01T12:0{i}:00+00:00",
                source="suricata",
                severity="medium",
                title=f"Alert {i}",
            ))
        results = await tmp_db.get_alerts()
        assert len(results) == 5


@pytest.mark.asyncio
class TestGetStats:
    """Test get_stats returns correct counts."""

    async def test_stats_counts(self, tmp_db: AlertDB):
        """get_stats should reflect inserted alert counts and verdicts."""
        # Insert alerts with different verdicts
        await tmp_db.insert_alert(Alert(
            id="s1", timestamp="2026-03-01T12:00:00+00:00",
            source="suricata", severity="high", title="Alert 1",
            verdict="pending",
        ))
        await tmp_db.insert_alert(Alert(
            id="s2", timestamp="2026-03-01T12:01:00+00:00",
            source="suricata", severity="medium", title="Alert 2",
            verdict="suppress",
        ))
        await tmp_db.insert_alert(Alert(
            id="w1", timestamp="2026-03-01T12:02:00+00:00",
            source="wazuh", severity="low", title="Alert 3",
            verdict="investigate",
        ))
        await tmp_db.insert_alert(Alert(
            id="w2", timestamp="2026-03-01T12:03:00+00:00",
            source="wazuh", severity="critical", title="Alert 4",
            verdict="escalate",
        ))

        stats = await tmp_db.get_stats()

        assert stats["total_alerts"] == 4
        assert stats["pending_triage"] == 1
        assert stats["suppressed"] == 1
        assert stats["investigate"] == 1
        assert stats["escalated"] == 1

        assert stats["by_source"]["suricata"] == 2
        assert stats["by_source"]["wazuh"] == 2

        assert stats["by_severity"]["high"] == 1
        assert stats["by_severity"]["medium"] == 1
        assert stats["by_severity"]["low"] == 1
        assert stats["by_severity"]["critical"] == 1

    async def test_stats_empty_db(self, tmp_db: AlertDB):
        """get_stats on empty DB should return zero counts."""
        stats = await tmp_db.get_stats()
        assert stats["total_alerts"] == 0
        assert stats["pending_triage"] == 0
        assert stats["by_source"] == {}
        assert stats["by_severity"] == {}


@pytest.mark.asyncio
class TestSearchAlerts:
    """Test search_alerts FTS."""

    async def test_fts_search_by_title(self, tmp_db: AlertDB):
        """Full-text search should match on alert title."""
        await tmp_db.insert_alert(Alert(
            id="fts-1", timestamp="2026-03-01T12:00:00+00:00",
            source="suricata", severity="high",
            title="ET SCAN Nmap SYN Scan detected",
            description="Nmap scan from external",
            category="Attempted Information Leak",
        ))
        await tmp_db.insert_alert(Alert(
            id="fts-2", timestamp="2026-03-01T12:01:00+00:00",
            source="wazuh", severity="medium",
            title="Authentication failure for root",
            description="SSH brute force attempt",
            category="authentication_failed",
        ))

        results = await tmp_db.search_alerts("Nmap")
        assert len(results) >= 1
        assert any(r["id"] == "fts-1" for r in results)

    async def test_fts_search_by_description(self, tmp_db: AlertDB):
        """Full-text search should match on description."""
        await tmp_db.insert_alert(Alert(
            id="fts-desc-1", timestamp="2026-03-01T12:00:00+00:00",
            source="suricata", severity="medium",
            title="Generic Alert",
            description="Suspicious DNS tunneling traffic detected",
            category="Potentially Bad Traffic",
        ))
        results = await tmp_db.search_alerts("tunneling")
        assert len(results) >= 1
        assert results[0]["id"] == "fts-desc-1"

    async def test_fts_no_results(self, tmp_db: AlertDB):
        """Search for a term not in any alert should return empty list."""
        await tmp_db.insert_alert(Alert(
            id="fts-no-1", timestamp="2026-03-01T12:00:00+00:00",
            source="suricata", severity="low",
            title="Simple alert", description="Nothing special",
        ))
        results = await tmp_db.search_alerts("xyznonexistent")
        assert results == []


@pytest.mark.asyncio
class TestExecuteSql:
    """Test execute_sql blocks non-SELECT statements."""

    async def test_valid_select(self, tmp_db: AlertDB):
        """A plain SELECT should succeed."""
        await tmp_db.insert_alert(Alert(
            id="sql-1", timestamp="2026-03-01T12:00:00+00:00",
            source="suricata", severity="medium", title="Test",
        ))
        rows = await tmp_db.execute_sql("SELECT COUNT(*) as cnt FROM alerts")
        assert rows[0]["cnt"] == 1

    async def test_rejects_insert(self, tmp_db: AlertDB):
        with pytest.raises(ValueError, match="Only SELECT"):
            await tmp_db.execute_sql("INSERT INTO alerts (id) VALUES ('bad')")

    async def test_rejects_update(self, tmp_db: AlertDB):
        with pytest.raises(ValueError, match="Only SELECT"):
            await tmp_db.execute_sql("UPDATE alerts SET severity='low'")

    async def test_rejects_delete(self, tmp_db: AlertDB):
        with pytest.raises(ValueError, match="Only SELECT"):
            await tmp_db.execute_sql("DELETE FROM alerts")

    async def test_rejects_drop(self, tmp_db: AlertDB):
        with pytest.raises(ValueError, match="Only SELECT"):
            await tmp_db.execute_sql("DROP TABLE alerts")


@pytest.mark.asyncio
class TestRetentionCleanup:
    """Test retention_cleanup deletes old alerts."""

    async def test_deletes_old_alerts(self, tmp_db: AlertDB):
        """Alerts older than max_age_days should be deleted."""
        old_time = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
        recent_time = datetime.now(timezone.utc).isoformat()

        await tmp_db.insert_alert(Alert(
            id="old-1", timestamp=old_time,
            source="suricata", severity="low", title="Old alert",
            ingested_at=old_time,
        ))
        await tmp_db.insert_alert(Alert(
            id="recent-1", timestamp=recent_time,
            source="suricata", severity="low", title="Recent alert",
            ingested_at=recent_time,
        ))

        deleted = await tmp_db.retention_cleanup(max_age_days=30)
        assert deleted >= 1

        # Old alert should be gone
        assert await tmp_db.get_alert("old-1") is None
        # Recent alert should still exist
        assert await tmp_db.get_alert("recent-1") is not None

    async def test_cleanup_returns_zero_when_nothing_to_delete(self, tmp_db: AlertDB):
        """If no alerts are old enough, cleanup should return 0."""
        recent_time = datetime.now(timezone.utc).isoformat()
        await tmp_db.insert_alert(Alert(
            id="fresh-1", timestamp=recent_time,
            source="suricata", severity="low", title="Fresh",
            ingested_at=recent_time,
        ))
        deleted = await tmp_db.retention_cleanup(max_age_days=30)
        assert deleted == 0
