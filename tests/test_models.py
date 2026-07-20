"""Tests for shallots.store.models - Alert dataclass and enums."""

from __future__ import annotations

from shallots.store.models import Alert, AlertSource, Severity


class TestAlertSource:
    """Verify AlertSource enum values."""

    def test_suricata_value(self):
        assert AlertSource.SURICATA.value == "suricata"

    def test_wazuh_value(self):
        assert AlertSource.WAZUH.value == "wazuh"

    def test_crowdsec_value(self):
        assert AlertSource.CROWDSEC.value == "crowdsec"

    def test_syslog_value(self):
        assert AlertSource.SYSLOG.value == "syslog"

    def test_pfsense_value(self):
        assert AlertSource.PFSENSE.value == "pfsense"

    def test_pihole_value(self):
        assert AlertSource.PIHOLE.value == "pihole"

    def test_enum_is_str(self):
        """AlertSource members should be usable as plain strings."""
        assert isinstance(AlertSource.SURICATA, str)
        assert AlertSource.SURICATA == "suricata"


class TestSeverity:
    """Verify Severity enum values."""

    def test_all_values(self):
        expected = {"low", "medium", "high", "critical"}
        actual = {s.value for s in Severity}
        assert actual == expected


class TestComputeDedupHash:
    """Test Alert.compute_dedup_hash produces consistent hashes."""

    def test_consistent_hash(self):
        """Same fields should always produce the same hash."""
        a = Alert(source="suricata", signature_id=100, src_ip="10.0.0.1",
                  dst_ip="10.0.0.2", proto="TCP")
        h1 = a.compute_dedup_hash()

        b = Alert(source="suricata", signature_id=100, src_ip="10.0.0.1",
                  dst_ip="10.0.0.2", proto="TCP")
        h2 = b.compute_dedup_hash()

        assert h1 == h2
        assert len(h1) == 16  # sha256 truncated to 16 hex chars

    def test_different_fields_different_hash(self):
        """Changing any key field should change the hash."""
        a = Alert(source="suricata", signature_id=100, src_ip="10.0.0.1",
                  dst_ip="10.0.0.2", proto="TCP")
        h1 = a.compute_dedup_hash()

        b = Alert(source="wazuh", signature_id=100, src_ip="10.0.0.1",
                  dst_ip="10.0.0.2", proto="TCP")
        h2 = b.compute_dedup_hash()

        assert h1 != h2

    def test_hash_stored_on_instance(self):
        """compute_dedup_hash should set self.dedup_hash."""
        a = Alert(source="suricata", signature_id=100, src_ip="1.1.1.1",
                  dst_ip="2.2.2.2", proto="UDP")
        result = a.compute_dedup_hash()
        assert a.dedup_hash == result

    def test_distinct_syslog_messages_do_not_collapse(self):
        """Syslog priority is too broad to be the whole signature."""
        a = Alert(source="syslog", signature_id=14, src_ip="127.0.0.1",
                  title="Syslog [user] dlink", description="router status ok")
        b = Alert(source="syslog", signature_id=14, src_ip="127.0.0.1",
                  title="Syslog [user] shallot", description="local canary ok")

        assert a.compute_dedup_hash() != b.compute_dedup_hash()

    def test_identical_syslog_messages_still_dedupe(self):
        """Repeated identical syslog rows should keep a stable dedup hash."""
        a = Alert(source="syslog", signature_id=14, src_ip="127.0.0.1",
                  title="Syslog [user] shallot", description="local canary ok")
        b = Alert(source="syslog", signature_id=14, src_ip="127.0.0.1",
                  title="Syslog [user] shallot", description="local canary ok")

        assert a.compute_dedup_hash() == b.compute_dedup_hash()

    def test_syslog_kernel_timestamps_do_not_defeat_dedup(self):
        """Router kernel uptime prefixes should not make spam look unique."""
        a = Alert(source="syslog", signature_id=14, src_ip="192.168.0.1",
                  title="Syslog [user]",
                  description="<12>kernel: [372912.236331] nf_conntrack: table full, dropping packet")
        b = Alert(source="syslog", signature_id=14, src_ip="192.168.0.1",
                  title="Syslog [user]",
                  description="<12>kernel: [372917.468011] nf_conntrack: table full, dropping packet")

        assert a.compute_dedup_hash() == b.compute_dedup_hash()

    def test_distinct_syslog_kernel_messages_remain_distinct(self):
        a = Alert(source="syslog", signature_id=14, src_ip="192.168.0.1",
                  title="Syslog [user]",
                  description="<12>kernel: [372912.236331] nf_conntrack: table full, dropping packet")
        b = Alert(source="syslog", signature_id=14, src_ip="192.168.0.1",
                  title="Syslog [user]",
                  description="<12>kernel: [372917.463101] net_ratelimit: 57 callbacks suppressed")

        assert a.compute_dedup_hash() != b.compute_dedup_hash()


class TestToDictFromDict:
    """Test Alert serialization roundtrip."""

    def test_roundtrip(self, sample_alert):
        """to_dict -> from_dict should produce an equivalent Alert."""
        d = sample_alert.to_dict()
        restored = Alert.from_dict(d)

        assert restored.id == sample_alert.id
        assert restored.source == sample_alert.source
        assert restored.severity == sample_alert.severity
        assert restored.title == sample_alert.title
        assert restored.src_ip == sample_alert.src_ip
        assert restored.dst_ip == sample_alert.dst_ip
        assert restored.dedup_hash == sample_alert.dedup_hash
        assert restored.signature_id == sample_alert.signature_id

    def test_to_dict_returns_dict(self, sample_alert):
        d = sample_alert.to_dict()
        assert isinstance(d, dict)
        assert "id" in d
        assert "dedup_hash" in d

    def test_from_dict_ignores_extra_keys(self):
        """from_dict should silently ignore fields not in the dataclass."""
        data = {
            "id": "abc",
            "source": "suricata",
            "nonexistent_field": "should be ignored",
        }
        alert = Alert.from_dict(data)
        assert alert.id == "abc"
        assert alert.source == "suricata"
        assert not hasattr(alert, "nonexistent_field")

    def test_to_json(self, sample_alert):
        """to_json should return valid JSON that can roundtrip."""
        import json
        j = sample_alert.to_json()
        d = json.loads(j)
        restored = Alert.from_dict(d)
        assert restored.id == sample_alert.id
