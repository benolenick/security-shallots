"""Shared pytest fixtures for Security Shallots test suite."""

from __future__ import annotations

import json
import os
import tempfile

import pytest
import pytest_asyncio

from shallots.store.models import Alert, AlertSource, Severity
from shallots.store.db import AlertDB


# ---------------------------------------------------------------------------
# Suricata EVE JSON fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_eve_event() -> dict:
    """Return a dict matching Suricata EVE JSON alert format."""
    return {
        "timestamp": "2026-03-01T12:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "10.0.0.50",
        "src_port": 54321,
        "dest_ip": "93.184.216.34",
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2024897,
            "rev": 3,
            "signature": "ET SCAN Suspicious inbound to port 443",
            "category": "Attempted Information Leak",
            "severity": 2,
        },
        "flow_id": 1234567890,
        "in_iface": "eth0",
    }


# ---------------------------------------------------------------------------
# Wazuh JSON alert fixture (with FIM / syscheck hashes)
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_wazuh_event() -> dict:
    """Return a dict matching Wazuh JSON alert format with FIM syscheck data."""
    return {
        "timestamp": "2026-03-01T13:00:00.000+0000",
        "id": "1614600000.12345",
        "rule": {
            "id": "550",
            "level": 7,
            "description": "Integrity checksum changed.",
            "groups": ["ossec", "syscheck", "syscheck_entry_modified"],
            "mitre": {
                "technique": ["T1565.001"],
                "tactic": ["Impact"],
            },
        },
        "agent": {
            "id": "001",
            "name": "web-server-01",
            "ip": "192.168.1.100",
        },
        "data": {
            "srcip": "",
            "dstip": "",
        },
        "syscheck": {
            "path": "/etc/passwd",
            "event": "modified",
            "md5_before": "d41d8cd98f00b204e9800998ecf8427e",
            "md5_after": "5d41402abc4b2a76b9719d911017c592",
            "sha1_before": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "sha1_after": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
            "sha256_before": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sha256_after": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        },
        "location": "/var/ossec/logs/alerts/alerts.json",
    }


# ---------------------------------------------------------------------------
# Populated Alert instance fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_alert() -> Alert:
    """Return a populated Alert instance for testing."""
    alert = Alert(
        id="test-alert-001",
        timestamp="2026-03-01T12:00:00+00:00",
        source=AlertSource.SURICATA.value,
        source_ref="2024897",
        severity=Severity.HIGH.value,
        title="ET SCAN Suspicious inbound to port 443",
        description="Category: Attempted Information Leak",
        src_ip="10.0.0.50",
        src_port=54321,
        dst_ip="93.184.216.34",
        dst_port=443,
        proto="TCP",
        category="Attempted Information Leak",
        signature_id=2024897,
        raw='{"event_type":"alert","src_ip":"10.0.0.50"}',
        verdict="pending",
        ingested_at="2026-03-01T12:00:01+00:00",
    )
    alert.compute_dedup_hash()
    return alert


# ---------------------------------------------------------------------------
# Temporary async SQLite database fixture
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def tmp_db(tmp_path):
    """Create a temporary SQLite DB using AlertDB, yield it, close after test."""
    db_path = str(tmp_path / "test_shallots.db")
    db = AlertDB(db_path)
    await db.connect()
    yield db
    await db.close()
