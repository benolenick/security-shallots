"""Suricata EVE JSON log tailer."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shallots.config import SuricataConfig

from shallots.store.models import Alert, AlertSource, now_iso

log = logging.getLogger(__name__)

# Severity mapping from Suricata priority
PRIORITY_TO_SEVERITY = {
    1: "critical",
    2: "high",
    3: "medium",
    4: "low",
}


class EveIngestor:
    """Async file tailer for Suricata EVE JSON logs.

    Follows the file like `tail -F`: handles rotation by detecting
    inode changes or file truncation.
    """

    def __init__(self, config: SuricataConfig, queue: asyncio.Queue, flow_detector=None):
        self.eve_path = config.eve_path
        self.queue = queue
        self._position = 0
        self._inode = 0
        self._last_rules_failed = 0
        # Optional FlowScanDetector: turns Suricata's `flow` records (which carry
        # no IDS signature) into port-scan / host-sweep alerts. None => flow events
        # are skipped as before.
        self.flow_detector = flow_detector

    async def run(self) -> None:
        """Main loop: tail the EVE file and push alerts to queue."""
        log.info("EVE ingestor watching: %s", self.eve_path)

        # Wait for file to exist
        while not os.path.exists(self.eve_path):
            log.debug("Waiting for EVE file: %s", self.eve_path)
            await asyncio.sleep(5)

        # Start at end of file
        try:
            stat = os.stat(self.eve_path)
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
                log.exception("EVE tailer error")
            await asyncio.sleep(0.5)

    async def _tail_once(self) -> None:
        """Read new lines from EVE file."""
        try:
            stat = os.stat(self.eve_path)
        except FileNotFoundError:
            await asyncio.sleep(5)
            return

        # Detect rotation: inode changed or file got smaller
        if stat.st_ino != self._inode or stat.st_size < self._position:
            log.info("EVE file rotated, resetting position")
            self._inode = stat.st_ino
            self._position = 0

        if stat.st_size <= self._position:
            return

        # Read new data
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
                log.debug("Skipping non-JSON line")

    def _read_lines(self) -> list[str]:
        """Read new COMPLETE lines from file (called in executor).

        Suricata may be mid-write on the last line; consuming it would parse a
        truncated JSON blob and silently drop a real alert. Only advance the
        position past the final newline - the partial tail is re-read next poll.
        """
        try:
            with open(self.eve_path, "r") as f:
                f.seek(self._position)
                lines = f.readlines()
                pos = f.tell()
                if lines and not lines[-1].endswith("\n"):
                    pos -= len(lines[-1].encode("utf-8", "replace"))
                    lines = lines[:-1]
                self._position = pos
                return lines
        except OSError as e:
            log.warning("Error reading EVE file: %s", e)
            return []

    def _parse_event(self, evt: dict, raw_line: str) -> Alert | None:
        """Parse a Suricata EVE event into an Alert.

        Suricata EVE can emit various event types. We primarily care about:
        - alert: IDS signature matches
        - anomaly: protocol anomalies
        - flow: connection records (for correlation, not alerts)
        """
        event_type = evt.get("event_type", "")

        if event_type == "alert":
            return self._parse_alert(evt, raw_line)
        elif event_type == "anomaly":
            return self._parse_anomaly(evt, raw_line)
        elif event_type == "stats":
            return self._parse_stats(evt, raw_line)
        elif event_type == "flow" and self.flow_detector is not None:
            # Fan-out scan/sweep detection over connection records - the east-west
            # signal no IDS signature fires on.
            return self.flow_detector.observe(evt)
        # Skip dns, http, tls, etc. - useful for correlation but not alerts
        return None

    def _parse_alert(self, evt: dict, raw_line: str) -> Alert:
        """Parse a Suricata alert event."""
        alert_data = evt.get("alert", {})
        priority = alert_data.get("severity", 3)

        return Alert(
            timestamp=evt.get("timestamp", now_iso()),
            source=AlertSource.SURICATA,
            source_ref=str(alert_data.get("signature_id", "")),
            severity=PRIORITY_TO_SEVERITY.get(priority, "medium"),
            title=alert_data.get("signature", "Unknown Suricata Alert"),
            description=f"Category: {alert_data.get('category', 'unknown')}",
            src_ip=evt.get("src_ip", ""),
            src_port=evt.get("src_port", 0),
            dst_ip=evt.get("dest_ip", ""),
            dst_port=evt.get("dest_port", 0),
            proto=evt.get("proto", ""),
            category=alert_data.get("category", ""),
            signature_id=alert_data.get("signature_id", 0),
            raw=raw_line,
        )

    def _parse_anomaly(self, evt: dict, raw_line: str) -> Alert:
        """Parse a Suricata anomaly event."""
        anomaly = evt.get("anomaly", {})
        return Alert(
            timestamp=evt.get("timestamp", now_iso()),
            source=AlertSource.SURICATA,
            source_ref=f"anomaly-{anomaly.get('type', 'unknown')}",
            severity="low",
            title=f"Protocol anomaly: {anomaly.get('type', 'unknown')}",
            description=anomaly.get("event", ""),
            src_ip=evt.get("src_ip", ""),
            src_port=evt.get("src_port", 0),
            dst_ip=evt.get("dest_ip", ""),
            dst_port=evt.get("dest_port", 0),
            proto=evt.get("proto", ""),
            category="anomaly",
            raw=raw_line,
        )

    def _parse_stats(self, evt: dict, raw_line: str) -> Alert | None:
        """Parse Suricata stats event - detect rule load failures."""
        stats = evt.get("stats", {})
        detect = stats.get("detect", {})

        # Check all engine entries for failed rules
        engines = detect.get("engines", [])
        total_failed = 0
        for engine in engines:
            failed = engine.get("rules_failed", 0)
            total_failed += failed

        # Also check top-level rules_failed
        total_failed += detect.get("rules_failed", 0)

        # Stats events fire every few seconds - only alert when the failure
        # count CHANGES, otherwise one bad rule floods an alert per interval.
        if total_failed == self._last_rules_failed:
            return None
        self._last_rules_failed = total_failed
        if total_failed <= 0:
            return None

        rules_loaded = detect.get("rules_loaded", 0)
        for engine in engines:
            rules_loaded += engine.get("rules_loaded", 0)

        return Alert(
            timestamp=evt.get("timestamp", now_iso()),
            source=AlertSource.SURICATA,
            source_ref="stats-rule-failure",
            severity="high",
            title=f"Suricata rule load failure: {total_failed} rules failed",
            description=f"{total_failed} rules failed to load ({rules_loaded} loaded successfully). "
                        f"Run 'suricata -T' to validate rules.",
            category="rule_health",
            signature_id=999002,
            raw=raw_line,
        )
