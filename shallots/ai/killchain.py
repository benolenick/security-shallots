"""Kill chain detector for multi-stage attack tracking.

Maps correlations and alerts to Cyber Kill Chain / MITRE ATT&CK stages,
tracks progression per entity, and fires critical incidents when multiple
stages activate.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any

from shallots.store.models import now_iso

log = logging.getLogger(__name__)

# Kill chain stages with mapped correlation patterns and MITRE tactics
KILL_CHAIN_STAGES = {
    "reconnaissance": {
        "order": 1,
        "patterns": ["port_scan", "recon"],
        "mitre": ["TA0043"],
        "keywords": ["scan", "probe", "enumerate", "discovery", "nmap"],
        "description": "Attacker is scanning and probing the network",
    },
    "delivery": {
        "order": 2,
        "patterns": ["phishing", "malware_download"],
        "mitre": ["TA0001"],
        "keywords": ["phish", "dropper", "download", "payload", "exploit kit"],
        "description": "Malicious payload delivered to target",
    },
    "exploitation": {
        "order": 3,
        "patterns": ["exploit_attempt"],
        "mitre": ["TA0002"],
        "keywords": ["exploit", "shellcode", "overflow", "rce", "injection", "cve-"],
        "description": "Vulnerability exploitation attempt",
    },
    "installation": {
        "order": 4,
        "patterns": ["persistence_detected", "malware"],
        "mitre": ["TA0003", "TA0005"],
        "keywords": ["persistence", "backdoor", "trojan", "rootkit", "registry run",
                      "scheduled task", "startup", "service install"],
        "description": "Malware installed or persistence established",
    },
    "command_control": {
        "order": 5,
        "patterns": ["c2_beacon", "dns_tunnel"],
        "mitre": ["TA0011"],
        "keywords": ["beacon", "c2", "command and control", "callback", "tunnel",
                      "covert channel", "dns tunnel"],
        "description": "Command & control channel established",
    },
    "lateral_movement": {
        "order": 6,
        "patterns": ["lateral_movement", "brute_force"],
        "mitre": ["TA0008"],
        "keywords": ["lateral", "pass the hash", "psexec", "wmi remote",
                      "rdp brute", "ssh brute", "mimikatz"],
        "description": "Attacker moving laterally through the network",
    },
    "actions_on_objectives": {
        "order": 7,
        "patterns": ["data_exfil", "privilege_escalation"],
        "mitre": ["TA0009", "TA0010", "TA0040"],
        "keywords": ["exfil", "ransomware", "encrypt", "data theft", "credential dump",
                      "privilege escalation", "admin access"],
        "description": "Attacker achieving final objectives",
    },
}


@dataclass
class KillChainHit:
    """A single stage activation in a kill chain."""
    stage: str
    order: int
    mitre: list[str]
    evidence: str            # description of what triggered this stage
    alert_ids: list[str] = field(default_factory=list)
    correlation_id: str = ""
    timestamp: str = ""


@dataclass
class KillChainTracker:
    """Tracks kill chain progression for a single entity."""
    id: str = ""
    entity: str = ""              # IP address or campaign ID
    entity_type: str = "src_ip"   # src_ip, campaign
    stages_hit: dict[str, KillChainHit] = field(default_factory=dict)
    first_seen: str = ""
    last_seen: str = ""
    severity: str = "medium"
    status: str = "active"        # active, escalated, dismissed

    @property
    def stage_count(self) -> int:
        return len(self.stages_hit)

    @property
    def max_stage_order(self) -> int:
        if not self.stages_hit:
            return 0
        return max(h.order for h in self.stages_hit.values())

    def to_dict(self) -> dict[str, Any]:
        d = {
            "id": self.id,
            "entity": self.entity,
            "entity_type": self.entity_type,
            "stages_hit": {
                stage: {
                    "stage": hit.stage,
                    "order": hit.order,
                    "mitre": hit.mitre,
                    "evidence": hit.evidence,
                    "alert_ids": hit.alert_ids,
                    "correlation_id": hit.correlation_id,
                    "timestamp": hit.timestamp,
                }
                for stage, hit in self.stages_hit.items()
            },
            "stage_count": self.stage_count,
            "max_stage": self.max_stage_order,
            "all_stages": list(KILL_CHAIN_STAGES.keys()),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "severity": self.severity,
            "status": self.status,
        }
        # Add all alert IDs across stages
        all_ids = []
        for hit in self.stages_hit.values():
            all_ids.extend(hit.alert_ids)
        d["all_alert_ids"] = list(set(all_ids))
        return d


class KillChainDetector:
    """Detects multi-stage attacks by tracking kill chain progression."""

    def __init__(self):
        self.active_chains: dict[str, KillChainTracker] = {}  # entity → tracker
        self._chain_history: list[dict] = []  # completed/escalated chains
        self._max_history = 100

    def evaluate_correlation(self, correlation: dict[str, Any]) -> KillChainTracker | None:
        """Check if a correlation advances any kill chain. Returns tracker if escalated."""
        pattern = correlation.get("pattern", "")
        summary = (correlation.get("summary") or "").lower()
        alert_ids = correlation.get("alert_ids", [])
        if isinstance(alert_ids, str):
            try:
                alert_ids = json.loads(alert_ids)
            except (json.JSONDecodeError, TypeError):
                alert_ids = []
        corr_id = correlation.get("id", "")

        # Determine which stage this correlation maps to
        stage = self._match_stage(pattern, summary)
        if not stage:
            return None

        # Determine the entity (source IP from correlation summary or alert context)
        entity = self._extract_entity(correlation)
        if not entity:
            return None

        # Get or create tracker
        if entity not in self.active_chains:
            self.active_chains[entity] = KillChainTracker(
                id=str(uuid.uuid4()),
                entity=entity,
                entity_type="src_ip",
                first_seen=now_iso(),
                last_seen=now_iso(),
            )

        tracker = self.active_chains[entity]
        stage_def = KILL_CHAIN_STAGES[stage]

        # Add stage hit (if not already present)
        if stage not in tracker.stages_hit:
            tracker.stages_hit[stage] = KillChainHit(
                stage=stage,
                order=stage_def["order"],
                mitre=stage_def["mitre"],
                evidence=correlation.get("summary", ""),
                alert_ids=alert_ids[:20],  # cap
                correlation_id=corr_id,
                timestamp=now_iso(),
            )
            tracker.last_seen = now_iso()
            log.info("Kill chain: %s advanced to stage '%s' (%d/%d stages)",
                     entity, stage, tracker.stage_count, len(KILL_CHAIN_STAGES))

        # Update severity based on progression
        if tracker.stage_count >= 4:
            tracker.severity = "critical"
        elif tracker.stage_count >= 3:
            tracker.severity = "high"
        elif tracker.stage_count >= 2:
            tracker.severity = "medium"

        # Escalate if 3+ stages hit
        if tracker.stage_count >= 3 and tracker.status == "active":
            tracker.status = "escalated"
            log.warning("Kill chain ESCALATED: %s hit %d stages: %s",
                        entity, tracker.stage_count,
                        list(tracker.stages_hit.keys()))
            return tracker

        return None

    def evaluate_alert(self, alert: dict[str, Any]) -> KillChainTracker | None:
        """Check if a single high-severity alert advances a kill chain."""
        title = (alert.get("title") or "").lower()
        category = (alert.get("category") or "").lower()
        combined = f"{title} {category}"

        stage = None
        for stage_name, stage_def in KILL_CHAIN_STAGES.items():
            for kw in stage_def["keywords"]:
                if kw in combined:
                    stage = stage_name
                    break
            if stage:
                break

        if not stage:
            return None

        entity = alert.get("src_ip") or ""
        if not entity:
            return None

        # Only track if we already have a chain for this entity, or severity is high+
        severity = alert.get("severity", "medium")
        if entity not in self.active_chains and severity not in ("high", "critical"):
            return None

        # Create synthetic correlation dict and delegate
        return self.evaluate_correlation({
            "pattern": stage,
            "summary": alert.get("title", ""),
            "alert_ids": [alert.get("id", "")],
            "id": "",
        })

    def get_active_chains(self) -> list[dict]:
        """Return all active kill chain trackers."""
        return [t.to_dict() for t in self.active_chains.values()
                if t.status in ("active", "escalated")]

    def get_history(self) -> list[dict]:
        """Return completed/dismissed chains."""
        return list(self._chain_history)

    def dismiss_chain(self, entity: str) -> bool:
        """Dismiss a kill chain tracker."""
        if entity in self.active_chains:
            tracker = self.active_chains[entity]
            tracker.status = "dismissed"
            self._chain_history.append(tracker.to_dict())
            if len(self._chain_history) > self._max_history:
                self._chain_history = self._chain_history[-self._max_history:]
            del self.active_chains[entity]
            return True
        return False

    def cleanup_stale(self, hours: int = 24) -> int:
        """Remove chains that haven't been updated in N hours."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        stale = [e for e, t in self.active_chains.items() if t.last_seen < cutoff]
        for entity in stale:
            tracker = self.active_chains[entity]
            tracker.status = "expired"
            self._chain_history.append(tracker.to_dict())
            del self.active_chains[entity]
        if stale:
            log.info("Kill chain: cleaned up %d stale trackers", len(stale))
        if len(self._chain_history) > self._max_history:
            self._chain_history = self._chain_history[-self._max_history:]
        return len(stale)

    # ── Internal ──────────────────────────────────────────────

    def _match_stage(self, pattern: str, summary: str) -> str | None:
        """Map a correlation pattern + summary text to a kill chain stage."""
        # First try direct pattern match
        for stage_name, stage_def in KILL_CHAIN_STAGES.items():
            if pattern in stage_def["patterns"]:
                return stage_name

        # Fall back to keyword matching in summary
        for stage_name, stage_def in KILL_CHAIN_STAGES.items():
            for kw in stage_def["keywords"]:
                if kw in summary:
                    return stage_name

        return None

    def _extract_entity(self, correlation: dict) -> str:
        """Extract the primary entity (IP) from a correlation."""
        summary = correlation.get("summary", "")

        # Try to find IP in summary
        import re
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', summary)
        if ips:
            # Prefer internal IPs as the "victim/pivot point"
            for ip in ips:
                if _is_rfc1918(ip):
                    return ip
            return ips[0]

        return ""


def _is_rfc1918(ip: str) -> bool:
    if not ip:
        return False
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        return (a == 10) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
    except (ValueError, IndexError):
        return False
