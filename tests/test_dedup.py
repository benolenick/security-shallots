"""Tests for shallots.pipeline.dedup.Deduplicator."""

from __future__ import annotations

from shallots.store.models import Alert
from shallots.pipeline.dedup import Deduplicator


class TestDeduplicator:
    """Test the in-memory hash-based deduplicator."""

    def _make_alert(self, source="suricata", sig_id=100,
                    src_ip="10.0.0.1", dst_ip="10.0.0.2", proto="TCP") -> Alert:
        """Helper to create an Alert with a computed dedup hash."""
        alert = Alert(
            source=source,
            signature_id=sig_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            proto=proto,
        )
        alert.compute_dedup_hash()
        return alert

    def test_first_alert_is_not_duplicate(self):
        """The first alert seen should never be flagged as duplicate."""
        dd = Deduplicator(window_seconds=600)
        alert = self._make_alert()
        assert dd.is_duplicate(alert) is False

    def test_same_hash_within_window_is_duplicate(self):
        """An alert with the same dedup hash within the window IS a duplicate."""
        dd = Deduplicator(window_seconds=600)
        alert1 = self._make_alert()
        alert2 = self._make_alert()  # identical fields -> same hash

        assert dd.is_duplicate(alert1) is False
        assert dd.is_duplicate(alert2) is True

    def test_different_hash_is_not_duplicate(self):
        """Alerts with different dedup hashes should not be duplicates."""
        dd = Deduplicator(window_seconds=600)
        alert1 = self._make_alert(sig_id=100)
        alert2 = self._make_alert(sig_id=200)

        assert dd.is_duplicate(alert1) is False
        assert dd.is_duplicate(alert2) is False

    def test_different_source_not_duplicate(self):
        """Same sig_id but different source should produce different hash."""
        dd = Deduplicator(window_seconds=600)
        alert1 = self._make_alert(source="suricata")
        alert2 = self._make_alert(source="wazuh")

        assert dd.is_duplicate(alert1) is False
        assert dd.is_duplicate(alert2) is False

    def test_no_hash_not_duplicate(self):
        """An alert with no dedup_hash should not be flagged as duplicate."""
        dd = Deduplicator(window_seconds=600)
        alert = Alert(source="suricata")  # dedup_hash is ""
        assert dd.is_duplicate(alert) is False

    def test_max_entries_eviction(self):
        """When max_entries is exceeded, oldest entries should be evicted."""
        dd = Deduplicator(window_seconds=600, max_entries=5)

        # Insert 6 unique alerts
        for i in range(6):
            alert = self._make_alert(sig_id=i)
            dd.is_duplicate(alert)

        # The first one should have been evicted (max_entries=5)
        first_alert = self._make_alert(sig_id=0)
        assert dd.is_duplicate(first_alert) is False
