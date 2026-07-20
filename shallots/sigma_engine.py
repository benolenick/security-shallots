"""Basic Sigma rule engine for matching YAML detection rules against alerts."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

# Map Sigma field names to alert dict keys
_FIELD_MAP: dict[str, str] = {
    "SourceIP": "src_ip",
    "source.ip": "src_ip",
    "src_ip": "src_ip",
    "DestinationIP": "dst_ip",
    "destination.ip": "dst_ip",
    "dst_ip": "dst_ip",
    "SourcePort": "src_port",
    "source.port": "src_port",
    "src_port": "src_port",
    "DestinationPort": "dst_port",
    "destination.port": "dst_port",
    "dst_port": "dst_port",
    "Protocol": "proto",
    "proto": "proto",
    "Title": "title",
    "title": "title",
    "Description": "description",
    "description": "description",
    "Category": "category",
    "category": "category",
    # process_creation rules (community Sigma): the exec ingestor stashes the
    # command line in the alert description, so these map there.
    "CommandLine": "description",
    "process.command_line": "description",
    "Image": "description",
    "process.executable": "description",
    "ParentImage": "description",
    "Severity": "severity",
    "severity": "severity",
    "Source": "source",
    "source": "source",
    "SignatureID": "signature_id",
    "signature_id": "signature_id",
    "raw": "raw",
}


@dataclass
class SigmaRule:
    """Parsed Sigma rule."""
    id: str = ""
    title: str = ""
    description: str = ""
    level: str = "medium"  # informational, low, medium, high, critical
    status: str = "experimental"
    logsource_category: str = ""
    logsource_product: str = ""
    detection: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    filename: str = ""


class SigmaEngine:
    """Load and match Sigma YAML rules against alert dicts."""

    def __init__(self, rules_dir: str = "") -> None:
        self.rules_dir = rules_dir
        self.rules: list[SigmaRule] = []

    def load_rules(self) -> int:
        """Load all .yml files from rules_dir. Returns count loaded."""
        self.rules.clear()
        if not self.rules_dir:
            return 0

        rules_path = Path(self.rules_dir)
        if not rules_path.is_dir():
            log.warning("Sigma rules_dir does not exist: %s", self.rules_dir)
            return 0

        count = 0
        for yml_file in sorted(rules_path.glob("*.yml")):
            try:
                raw = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
                if not isinstance(raw, dict):
                    log.warning("Sigma file %s did not parse as dict, skipping", yml_file.name)
                    continue

                detection = raw.get("detection", {})
                if not detection:
                    log.debug("Sigma file %s has no detection block, skipping", yml_file.name)
                    continue

                logsource = raw.get("logsource", {})
                rule = SigmaRule(
                    id=raw.get("id", yml_file.stem),
                    title=raw.get("title", yml_file.stem),
                    description=raw.get("description", ""),
                    level=raw.get("level", "medium"),
                    status=raw.get("status", "experimental"),
                    logsource_category=logsource.get("category", ""),
                    logsource_product=logsource.get("product", ""),
                    detection=detection,
                    tags=raw.get("tags", []),
                    filename=yml_file.name,
                )
                self.rules.append(rule)
                count += 1
            except Exception:
                log.exception("Failed to parse Sigma rule %s", yml_file.name)

        log.info("Loaded %d Sigma rules from %s", count, self.rules_dir)
        return count

    def match(self, alert: dict) -> list[SigmaRule]:
        """Check alert against all loaded rules, return list of matching rules."""
        matched: list[SigmaRule] = []
        for rule in self.rules:
            try:
                if self._match_detection(rule.detection, alert):
                    matched.append(rule)
            except Exception:
                log.debug("Error matching Sigma rule %s", rule.id, exc_info=True)
        return matched

    def _match_detection(self, detection: dict, alert: dict) -> bool:
        """Implement basic Sigma detection logic.

        Supports:
        - condition: "selection"
        - condition: "selection and not filter"
        - selection/filter blocks with field: value, field|contains, field|startswith,
          field|endswith, field|re, and plain keyword lists.
        """
        condition = detection.get("condition", "selection")

        if condition == "selection":
            return self._match_block(detection.get("selection", {}), alert)

        if condition == "selection and not filter":
            sel = self._match_block(detection.get("selection", {}), alert)
            if not sel:
                return False
            filt = self._match_block(detection.get("filter", {}), alert)
            return not filt

        # Fallback: try to evaluate simple "X and not Y" patterns
        m = re.match(r"^(\w+)\s+and\s+not\s+(\w+)$", condition.strip())
        if m:
            sel_name, filt_name = m.group(1), m.group(2)
            sel = self._match_block(detection.get(sel_name, {}), alert)
            if not sel:
                return False
            filt = self._match_block(detection.get(filt_name, {}), alert)
            return not filt

        # Fallback: try single named block
        m2 = re.match(r"^(\w+)$", condition.strip())
        if m2:
            block_name = m2.group(1)
            if block_name in detection:
                return self._match_block(detection[block_name], alert)

        # If we can't parse the condition, try "selection" anyway
        if "selection" in detection:
            return self._match_block(detection["selection"], alert)

        return False

    def _match_block(self, block: dict | list | None, alert: dict) -> bool:
        """Match a single detection block (selection or filter) against alert.

        Block can be:
        - dict of field conditions (all must match - AND logic)
        - list of keyword strings (any must appear somewhere in alert - OR logic)
        """
        if block is None:
            return False

        # Keyword list: any keyword must appear in any alert value
        if isinstance(block, list):
            alert_text = " ".join(str(v) for v in alert.values()).lower()
            return any(str(kw).lower() in alert_text for kw in block)

        if not isinstance(block, dict):
            return False

        # Dict of field conditions - all must match (AND)
        for sigma_field, expected in block.items():
            if not self._match_field_condition(sigma_field, expected, alert):
                return False
        return True

    def _match_field_condition(self, sigma_field: str, expected: Any, alert: dict) -> bool:
        """Match a single field condition.

        sigma_field can be "FieldName" or "FieldName|modifier" where modifier is
        contains, startswith, endswith, re.
        """
        # Parse modifier
        parts = sigma_field.split("|")
        base_field = parts[0]
        modifier = parts[1] if len(parts) > 1 else ""

        # Map Sigma field to alert key
        alert_key = _FIELD_MAP.get(base_field, base_field)
        alert_val = str(alert.get(alert_key, "") or "").lower()

        # Handle list of possible values (OR logic)
        if isinstance(expected, list):
            return any(
                self._compare(alert_val, str(v).lower(), modifier)
                for v in expected
            )

        # Single value
        expected_str = str(expected).lower()
        return self._compare(alert_val, expected_str, modifier)

    @staticmethod
    def _compare(alert_val: str, expected: str, modifier: str) -> bool:
        """Compare alert value against expected using modifier."""
        if modifier == "contains":
            return expected in alert_val
        elif modifier == "startswith":
            return alert_val.startswith(expected)
        elif modifier == "endswith":
            return alert_val.endswith(expected)
        elif modifier == "re":
            try:
                return bool(re.search(expected, alert_val, re.IGNORECASE))
            except re.error:
                return False
        else:
            # Default: exact match (case-insensitive) or substring for keywords
            if not modifier:
                return alert_val == expected or expected in alert_val
            return alert_val == expected
