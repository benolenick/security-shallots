"""Alert normalization — ensures consistent schema."""

from __future__ import annotations

import uuid

from shallots.store.models import Alert, Severity, now_iso


# Known severity aliases
SEVERITY_MAP = {
    "info": "low",
    "informational": "low",
    "warning": "medium",
    "warn": "medium",
    "error": "high",
    "critical": "critical",
    "crit": "critical",
    "emergency": "critical",
    "emerg": "critical",
    "alert": "high",
}


def normalize(alert: Alert) -> Alert:
    """Normalize an alert to consistent schema."""
    # Ensure ID
    if not alert.id:
        alert.id = str(uuid.uuid4())

    # Normalize timestamp
    if not alert.timestamp:
        alert.timestamp = now_iso()

    # Normalize severity
    sev = alert.severity.lower().strip()
    alert.severity = SEVERITY_MAP.get(sev, sev)
    if alert.severity not in {s.value for s in Severity}:
        alert.severity = "medium"

    # Normalize IP fields
    alert.src_ip = alert.src_ip.strip() if alert.src_ip else ""
    alert.dst_ip = alert.dst_ip.strip() if alert.dst_ip else ""

    # Normalize protocol
    if alert.proto:
        alert.proto = alert.proto.upper()

    # Compute dedup hash
    alert.compute_dedup_hash()

    # Set ingestion time
    if not alert.ingested_at:
        alert.ingested_at = now_iso()

    return alert
