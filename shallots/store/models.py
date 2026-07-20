"""Data models for Security Shallots."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class AlertSource(str, Enum):
    SURICATA = "suricata"
    WAZUH = "wazuh"
    CROWDSEC = "crowdsec"
    SYSLOG = "syslog"
    PFSENSE = "pfsense"
    PIHOLE = "pihole"
    ARGUS = "argus"
    WEBAPP = "webapp"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TriageVerdict(str, Enum):
    SUPPRESS = "suppress"
    INVESTIGATE = "investigate"
    ESCALATE = "escalate"
    PENDING = "pending"


def _normalize_syslog_dedup_text(text: str) -> str:
    """Remove volatile prefixes from syslog text before de-dup hashing."""
    text = str(text or "").strip()
    text = re.sub(r"^<\d+>", "", text)
    text = re.sub(r"\bkernel:\s*\[[\d.]+\]\s*", "kernel: ", text)
    text = re.sub(r"\[[\d.]+\]\s*", "", text)
    text = re.sub(r"\s+", " ", text)
    return text


@dataclass
class Alert:
    """Normalized alert from any source."""
    id: str = ""
    timestamp: str = ""
    source: str = ""          # AlertSource value
    source_ref: str = ""      # Original alert ID/ref from source system
    severity: str = "medium"  # Severity value
    title: str = ""
    description: str = ""
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    proto: str = ""
    category: str = ""        # e.g. "ET SCAN", "Authentication Failure"
    signature_id: int = 0
    raw: str = ""              # Original JSON
    # Enrichment fields
    src_geo: str = ""
    dst_geo: str = ""
    src_dns: str = ""
    dst_dns: str = ""
    src_asset: str = ""
    dst_asset: str = ""
    # Triage
    verdict: str = "pending"   # TriageVerdict value
    confidence: float = 0.0
    ai_reasoning: str = ""
    # Metadata
    ingested_at: str = ""
    dedup_hash: str = ""

    def compute_dedup_hash(self) -> str:
        """Hash for deduplication.

        If the hash was already set by the ingestor (e.g. Argus uses
        timestamp-based hashing), keep it.
        """
        if self.dedup_hash:
            return self.dedup_hash
        key = f"{self.source}:{self.signature_id}:{self.src_ip}:{self.dst_ip}:{self.proto}"
        if self.source == AlertSource.SYSLOG or str(self.source) == AlertSource.SYSLOG.value:
            message_key = _normalize_syslog_dedup_text(f"{self.title}:{self.description or self.raw}")
            key = f"{key}:{message_key}"
        self.dedup_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
        return self.dedup_hash

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Alert:
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


@dataclass
class TriageResult:
    """AI triage result for an alert."""
    alert_id: str = ""
    verdict: str = "pending"
    confidence: float = 0.0
    reasoning: str = ""
    iocs: list[str] = field(default_factory=list)
    suggested_action: str = ""
    model: str = ""
    latency_ms: int = 0
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["iocs"] = json.dumps(d["iocs"])
        return d


@dataclass
class Correlation:
    """Cross-alert correlation group."""
    id: str = ""
    alert_ids: list[str] = field(default_factory=list)
    pattern: str = ""
    summary: str = ""
    severity: str = "medium"
    created_at: str = ""


@dataclass
class QueryLog:
    """Log of NL queries."""
    id: str = ""
    question: str = ""
    generated_sql: str = ""
    result_summary: str = ""
    created_at: str = ""


@dataclass
class Incident:
    """Actionable security incident for human operators."""
    id: str = ""
    title: str = ""
    summary: str = ""
    severity: str = "medium"
    status: str = "new"
    category: str = ""
    affected_ips: list[str] = field(default_factory=list)
    affected_hosts: list[str] = field(default_factory=list)
    alert_count: int = 0
    correlation_id: str = ""
    cluster_ids: list[str] = field(default_factory=list)
    alert_ids: list[str] = field(default_factory=list)
    runbook: list[str] = field(default_factory=list)
    ai_analysis: str = ""
    created_at: str = ""
    updated_at: str = ""
    resolved_at: str = ""
    resolved_by: str = ""


@dataclass
class MLPrediction:
    """ML anomaly detection result."""
    alert_id: str = ""
    model: str = ""
    is_anomaly: bool = False
    anomaly_score: float = 0.0
    explanation: str = ""
    created_at: str = ""


def now_iso() -> str:
    """Current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()
