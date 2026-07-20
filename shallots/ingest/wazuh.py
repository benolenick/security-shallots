"""Wazuh alert JSON tailer.

Wazuh (the maintained fork of OSSEC) writes alerts in JSON format.
The alert format is backwards-compatible with OSSEC but includes
additional fields for file integrity monitoring (FIM) with hashes,
vulnerability detection, and agent metadata.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shallots.config import WazuhConfig

from shallots.store.models import Alert, AlertSource, now_iso

log = logging.getLogger(__name__)


# Wazuh rule level → severity
# Levels 0-3: low, 4-7: medium, 8-11: high, 12+: critical
def _level_to_severity(level: int) -> str:
    if level <= 3:
        return "low"
    elif level <= 7:
        return "medium"
    elif level <= 11:
        return "high"
    return "critical"


class WazuhIngestor:
    """Async file tailer for Wazuh JSON alert logs.

    Wazuh writes one JSON object per line to alerts.json.
    Follows the file like `tail -F`: handles rotation by detecting
    inode changes or file truncation.

    Extracts additional Wazuh-specific data:
    - FIM (syscheck) events with file hashes (md5, sha1, sha256)
    - Vulnerability detection alerts
    - Agent name/IP for multi-agent deployments
    """

    def __init__(self, config: WazuhConfig, queue: asyncio.Queue):
        self.alerts_path = config.alerts_path
        self.queue = queue
        self._position = 0
        self._inode = 0

    async def run(self) -> None:
        """Main loop: tail the Wazuh alerts file and push to queue."""
        log.info("Wazuh ingestor watching: %s", self.alerts_path)

        # Wait for file to exist
        while not os.path.exists(self.alerts_path):
            log.debug("Waiting for Wazuh alerts file: %s", self.alerts_path)
            await asyncio.sleep(5)

        # Start at end of existing file so we don't replay history on startup
        try:
            stat = os.stat(self.alerts_path)
            self._inode = stat.st_ino
            self._position = stat.st_size
        except OSError:
            pass

        while True:
            try:
                await self._tail_once()
            except asyncio.CancelledError:
                return
            except Exception:
                log.exception("Wazuh tailer error")
            await asyncio.sleep(0.5)

    async def _tail_once(self) -> None:
        """Read new lines from Wazuh alerts file."""
        try:
            stat = os.stat(self.alerts_path)
        except FileNotFoundError:
            await asyncio.sleep(5)
            return

        # Detect rotation: inode changed or file got smaller
        if stat.st_ino != self._inode or stat.st_size < self._position:
            log.info("Wazuh alerts file rotated, resetting position")
            self._inode = stat.st_ino
            self._position = 0

        if stat.st_size <= self._position:
            return

        loop = asyncio.get_running_loop()
        lines = await loop.run_in_executor(None, self._read_lines)

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
                alert = self._parse_event(evt, line)
                if alert:
                    await self.queue.put(alert)
            except json.JSONDecodeError:
                log.debug("Wazuh: skipping non-JSON line")

    def _read_lines(self) -> list[str]:
        """Read new lines from file (called in executor)."""
        try:
            with open(self.alerts_path, "r", errors="replace") as f:
                f.seek(self._position)
                lines = f.readlines()
                self._position = f.tell()
                return lines
        except OSError as e:
            log.warning("Error reading Wazuh alerts file: %s", e)
            return []

    def _parse_event(self, evt: dict, raw_line: str) -> Alert | None:
        """Parse a Wazuh JSON alert into an Alert object.

        Wazuh JSON alert fields:
          rule.id, rule.level, rule.description, rule.groups, rule.mitre
          agent.name, agent.ip, agent.id
          data.srcip, data.dstip, data.dstport
          syscheck.path, syscheck.md5_after, syscheck.sha1_after, syscheck.sha256_after
          data.vulnerability.cve, data.vulnerability.severity
          timestamp, id, location
        """
        rule = evt.get("rule", {})
        data = evt.get("data", {})
        agent = evt.get("agent", {})
        syscheck = evt.get("syscheck", {})

        level = int(rule.get("level", 0))
        rule_id = int(rule.get("id", 0))
        description = rule.get("description", "Wazuh Alert")
        groups = rule.get("groups", [])
        category = ", ".join(groups) if isinstance(groups, list) else str(groups)

        # Source IP: prefer data.srcip, fall back to agent.ip
        src_ip = data.get("srcip", "") or agent.get("ip", "")
        dst_ip = data.get("dstip", "")

        dst_port_raw = data.get("dstport", 0)
        try:
            dst_port = int(dst_port_raw)
        except (ValueError, TypeError):
            dst_port = 0

        proto = data.get("protocol", "").upper()

        # Build a human-readable title
        title = description
        agent_name = agent.get("name", "")
        if agent_name:
            title = f"{description} ({agent_name})"

        # Wazuh alert ID from the envelope
        source_ref = str(evt.get("id", rule_id))

        # Build extended description with FIM hash data if present
        desc_parts = [f"Rule {rule_id} (level {level}): {description}"]

        # FIM (syscheck) data - file integrity with hashes
        if syscheck:
            fim_path = syscheck.get("path", "")
            if fim_path:
                desc_parts.append(f"File: {fim_path}")
                event_type = syscheck.get("event", "")
                if event_type:
                    desc_parts.append(f"FIM event: {event_type}")
            # Collect file hashes
            hashes = _extract_fim_hashes(syscheck)
            if hashes:
                desc_parts.append(f"Hashes: {hashes}")

        # Vulnerability data
        vuln = data.get("vulnerability", {})
        if vuln:
            cve = vuln.get("cve", "")
            vuln_sev = vuln.get("severity", "")
            package = vuln.get("package", {}).get("name", "")
            if cve:
                desc_parts.append(f"CVE: {cve} (severity: {vuln_sev})")
            if package:
                desc_parts.append(f"Package: {package}")

        # MITRE ATT&CK mapping
        mitre = rule.get("mitre", {})
        if mitre:
            techniques = mitre.get("technique", [])
            tactics = mitre.get("tactic", [])
            if techniques:
                desc_parts.append(f"MITRE: {', '.join(techniques)}")
            if tactics:
                desc_parts.append(f"Tactics: {', '.join(tactics)}")

        return Alert(
            timestamp=evt.get("timestamp", now_iso()),
            source=AlertSource.WAZUH,
            source_ref=source_ref,
            severity=_level_to_severity(level),
            title=title,
            description=" | ".join(desc_parts),
            src_ip=src_ip,
            src_port=0,
            dst_ip=dst_ip,
            dst_port=dst_port,
            proto=proto,
            category=category,
            signature_id=rule_id,
            raw=raw_line,
        )


def _extract_fim_hashes(syscheck: dict) -> str:
    """Extract file hashes from Wazuh FIM (syscheck) event.

    Wazuh FIM provides before/after hashes for file changes:
    - md5_before, md5_after
    - sha1_before, sha1_after
    - sha256_before, sha256_after

    Returns a compact string of available hashes.
    """
    parts = []
    for algo in ("sha256", "sha1", "md5"):
        after = syscheck.get(f"{algo}_after", "")
        if after:
            parts.append(f"{algo}:{after}")
    return ", ".join(parts)
