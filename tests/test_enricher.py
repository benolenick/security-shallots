"""Tests for shallots.pipeline.enricher - IP classification and hash extraction."""

from __future__ import annotations

from shallots.store.models import Alert
from shallots.pipeline.enricher import is_private, _extract_hash_from_alert


class TestIsPrivate:
    """Test the is_private() function for RFC 1918 and special addresses."""

    # ── RFC 1918 private ranges ──

    def test_10_x_is_private(self):
        assert is_private("10.0.0.1") is True
        assert is_private("10.255.255.255") is True

    def test_172_16_x_is_private(self):
        assert is_private("172.16.0.1") is True
        assert is_private("172.31.255.255") is True

    def test_192_168_x_is_private(self):
        assert is_private("192.168.0.1") is True
        assert is_private("192.168.255.255") is True

    # ── Public IPs ──

    def test_8_8_8_8_is_public(self):
        assert is_private("8.8.8.8") is False

    def test_1_1_1_1_is_public(self):
        assert is_private("1.1.1.1") is False

    def test_93_184_216_34_is_public(self):
        assert is_private("93.184.216.34") is False

    # ── Edge cases ──

    def test_empty_string_returns_true(self):
        """Empty string should be treated as private (no enrichment needed)."""
        assert is_private("") is True

    def test_loopback_is_private(self):
        assert is_private("127.0.0.1") is True

    def test_link_local_is_private(self):
        assert is_private("169.254.1.1") is True

    def test_invalid_ip_returns_true(self):
        """An unparseable IP should be treated as private (safe default)."""
        assert is_private("not-an-ip") is True

    def test_ipv6_loopback_is_private(self):
        assert is_private("::1") is True

    def test_ipv6_ula_is_private(self):
        """fd00::/8 (ULA) should be private."""
        assert is_private("fd12:3456:789a::1") is True

    # ── Boundary: 172.16-172.31 is private, 172.15/172.32 is not ──

    def test_172_15_is_public(self):
        assert is_private("172.15.255.255") is False

    def test_172_32_is_public(self):
        assert is_private("172.32.0.1") is False


class TestExtractHashFromAlert:
    """Test _extract_hash_from_alert for Wazuh FIM alerts."""

    def test_extracts_sha256_from_description(self):
        """Should extract sha256 hash from Wazuh alert description."""
        sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        alert = Alert(
            source="wazuh",
            description=f"Rule 550 (level 7): Integrity checksum changed. | "
                        f"File: /etc/passwd | Hashes: sha256:{sha256}, "
                        f"sha1:aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d, "
                        f"md5:5d41402abc4b2a76b9719d911017c592",
        )
        result = _extract_hash_from_alert(alert)
        assert result == sha256

    def test_prefers_sha256_over_sha1(self):
        """When all hashes are present, sha256 should be preferred."""
        alert = Alert(
            source="wazuh",
            description="Hashes: sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234, "
                        "sha1:1234567890123456789012345678901234567890, "
                        "md5:12345678901234567890123456789012",
        )
        result = _extract_hash_from_alert(alert)
        assert result == "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"

    def test_falls_back_to_sha1(self):
        """If no sha256, should fall back to sha1."""
        sha1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        alert = Alert(
            source="wazuh",
            description=f"File: /etc/shadow | Hashes: sha1:{sha1}, "
                        f"md5:5d41402abc4b2a76b9719d911017c592",
        )
        result = _extract_hash_from_alert(alert)
        assert result == sha1

    def test_falls_back_to_md5(self):
        """If no sha256 or sha1, should fall back to md5."""
        md5 = "5d41402abc4b2a76b9719d911017c592"
        alert = Alert(
            source="wazuh",
            description=f"File: /etc/shadow | Hashes: md5:{md5}",
        )
        result = _extract_hash_from_alert(alert)
        assert result == md5

    def test_non_wazuh_source_returns_empty(self):
        """Alerts from non-wazuh sources should return empty string."""
        alert = Alert(
            source="suricata",
            description="sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
        )
        result = _extract_hash_from_alert(alert)
        assert result == ""

    def test_no_hashes_in_description_returns_empty(self):
        """Wazuh alert without hash data should return empty string."""
        alert = Alert(
            source="wazuh",
            description="Rule 5710 (level 5): sshd: Attempt to login using a denied user.",
        )
        result = _extract_hash_from_alert(alert)
        assert result == ""
