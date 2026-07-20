"""Tests for shallots.pipeline.normalizer."""

from __future__ import annotations

from shallots.store.models import Alert
from shallots.pipeline.normalizer import normalize, SEVERITY_MAP


class TestNormalize:
    """Test the normalize() function."""

    def test_sets_ingested_at(self):
        """normalize should populate ingested_at if empty."""
        alert = Alert(source="suricata", severity="high")
        assert alert.ingested_at == ""
        result = normalize(alert)
        assert result.ingested_at != ""

    def test_sets_dedup_hash(self):
        """normalize should compute and set dedup_hash."""
        alert = Alert(source="suricata", signature_id=100,
                      src_ip="10.0.0.1", dst_ip="10.0.0.2", proto="TCP",
                      severity="medium")
        assert alert.dedup_hash == ""
        result = normalize(alert)
        assert result.dedup_hash != ""
        assert len(result.dedup_hash) == 16

    def test_sets_id_if_empty(self):
        """normalize should assign a UUID if id is empty."""
        alert = Alert(source="suricata", severity="medium")
        assert alert.id == ""
        result = normalize(alert)
        assert result.id != ""

    def test_preserves_existing_id(self):
        """normalize should not overwrite an existing id."""
        alert = Alert(id="keep-me", source="suricata", severity="medium")
        result = normalize(alert)
        assert result.id == "keep-me"

    def test_sets_timestamp_if_empty(self):
        """normalize should set timestamp if empty."""
        alert = Alert(source="suricata", severity="medium")
        result = normalize(alert)
        assert result.timestamp != ""

    def test_normalizes_proto_to_upper(self):
        """normalize should uppercase the protocol."""
        alert = Alert(source="suricata", severity="medium", proto="tcp")
        result = normalize(alert)
        assert result.proto == "TCP"

    def test_strips_ip_whitespace(self):
        """normalize should strip leading/trailing whitespace from IPs."""
        alert = Alert(source="suricata", severity="medium",
                      src_ip="  10.0.0.1  ", dst_ip=" 10.0.0.2\t")
        result = normalize(alert)
        assert result.src_ip == "10.0.0.1"
        assert result.dst_ip == "10.0.0.2"


class TestSeverityMapping:
    """Test severity normalization from aliases."""

    def test_info_maps_to_low(self):
        alert = Alert(source="suricata", severity="info")
        result = normalize(alert)
        assert result.severity == "low"

    def test_informational_maps_to_low(self):
        alert = Alert(source="suricata", severity="informational")
        result = normalize(alert)
        assert result.severity == "low"

    def test_warning_maps_to_medium(self):
        alert = Alert(source="suricata", severity="warning")
        result = normalize(alert)
        assert result.severity == "medium"

    def test_warn_maps_to_medium(self):
        alert = Alert(source="suricata", severity="warn")
        result = normalize(alert)
        assert result.severity == "medium"

    def test_error_maps_to_high(self):
        alert = Alert(source="suricata", severity="error")
        result = normalize(alert)
        assert result.severity == "high"

    def test_crit_maps_to_critical(self):
        alert = Alert(source="suricata", severity="crit")
        result = normalize(alert)
        assert result.severity == "critical"

    def test_emergency_maps_to_critical(self):
        alert = Alert(source="suricata", severity="emergency")
        result = normalize(alert)
        assert result.severity == "critical"

    def test_unknown_severity_defaults_to_medium(self):
        """An unrecognized severity string should fall back to medium."""
        alert = Alert(source="suricata", severity="banana")
        result = normalize(alert)
        assert result.severity == "medium"

    def test_valid_severity_passes_through(self):
        """A valid severity value should pass through unchanged."""
        for sev in ("low", "medium", "high", "critical"):
            alert = Alert(source="suricata", severity=sev)
            result = normalize(alert)
            assert result.severity == sev

    def test_severity_case_insensitive(self):
        """Severity lookup should be case-insensitive."""
        alert = Alert(source="suricata", severity="WARNING")
        result = normalize(alert)
        assert result.severity == "medium"
