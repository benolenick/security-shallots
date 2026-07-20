"""Web application access log tailer.

Parses werkzeug/Flask HTTP access logs and generates security alerts for
suspicious activity: vulnerability scans, auth failures, error spikes, etc.
Normal 200/302 traffic is ignored to avoid noise.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shallots.config import WebAppIngestConfig

from shallots.store.models import Alert, AlertSource, now_iso

log = logging.getLogger(__name__)

# werkzeug log line:  IP - - [DD/Mon/YYYY HH:MM:SS] "METHOD /path HTTP/1.1" STATUS -
WERKZEUG_RE = re.compile(
    r'(?P<ip>[\d.]+)\s+-\s+-\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+(?P<status>\d+)'
)

# Known vulnerability scan paths - instant alert
SCAN_PATHS = re.compile(
    r'(?i)('
    r'\.env|\.git|wp-login|wp-admin|wp-config|wp-content|wp-includes'
    r'|\.aws|\.ssh|\.bash_history|\.htaccess|\.htpasswd'
    r'|/admin/|/phpmyadmin|/pma/|/myadmin'
    r'|config\.php|config\.js|config\.bak|config\.old'
    r'|/cgi-bin/|/shell|/cmd|/exec'
    r'|/api/v1/pods|/actuator|/swagger|/graphql'
    r'|/solr/|/jenkins|/manager/html'
    r'|/backup|/dump|/debug|/trace|/console'
    r'|/aws-config|/credentials|/secret'
    r'|_ignition/execute-solution'
    r'|/\.well-known/security\.txt'  # not malicious but scanner indicator
    r'|sitemap\.xml|robots\.txt'  # benign alone, but part of scan patterns
    r')'
)

# Paths that are always benign - never alert
BENIGN_PATHS = re.compile(
    r'^/(login|static/|favicon\.ico|api/(chat|write-lesson|read-lessons|governance-roles))$'
)

# Scan burst detection: if we see N scan-like requests within WINDOW seconds, escalate
SCAN_BURST_WINDOW = 60  # seconds
SCAN_BURST_THRESHOLD = 5


class WebAppIngestor:
    """Async file tailer for werkzeug/Flask access logs.

    Only generates alerts for suspicious activity - normal traffic is silent.
    """

    def __init__(self, config: WebAppIngestConfig, queue: asyncio.Queue):
        self.log_paths = config.log_paths
        self.app_name = config.app_name
        self.server_ip = config.server_ip
        self.server_port = config.server_port
        self.queue = queue
        # Per-file state
        self._positions: dict[str, int] = {}
        self._inodes: dict[str, int] = {}
        # Scan burst tracking per source IP
        self._scan_history: dict[str, list[float]] = {}

    async def run(self) -> None:
        """Main loop: tail all configured log files."""
        log.info("WebApp ingestor started: %s (%d log files)",
                 self.app_name, len(self.log_paths))

        # Wait for at least one file to exist
        while not any(os.path.exists(p) for p in self.log_paths):
            log.debug("Waiting for webapp log files")
            await asyncio.sleep(10)

        # Initialize positions at end of file
        for path in self.log_paths:
            if os.path.exists(path):
                try:
                    stat = os.stat(path)
                    self._inodes[path] = stat.st_ino
                    self._positions[path] = stat.st_size
                except OSError:
                    pass

        while True:
            try:
                for path in self.log_paths:
                    await self._tail_file(path)
            except asyncio.CancelledError:
                return
            except Exception:
                log.exception("WebApp tailer error")
            await asyncio.sleep(1.0)

    async def _tail_file(self, path: str) -> None:
        """Read new lines from a log file."""
        if not os.path.exists(path):
            return

        try:
            stat = os.stat(path)
        except FileNotFoundError:
            return

        prev_inode = self._inodes.get(path, 0)
        prev_pos = self._positions.get(path, 0)

        # Detect rotation
        if stat.st_ino != prev_inode or stat.st_size < prev_pos:
            log.info("WebApp log rotated: %s", path)
            self._inodes[path] = stat.st_ino
            self._positions[path] = 0
            prev_pos = 0

        if stat.st_size <= prev_pos:
            return

        loop = asyncio.get_running_loop()
        lines = await loop.run_in_executor(None, self._read_lines, path, prev_pos)

        import time
        now = time.time()

        for line in lines:
            line = line.strip()
            if not line:
                continue
            alert = self._parse_line(line, now)
            if alert:
                await self.queue.put(alert)

    def _read_lines(self, path: str, position: int) -> list[str]:
        """Read new lines from file (called in executor)."""
        try:
            with open(path, "r") as f:
                f.seek(position)
                lines = f.readlines()
                self._positions[path] = f.tell()
                return lines
        except OSError as e:
            log.warning("Error reading webapp log: %s: %s", path, e)
            return []

    def _parse_line(self, line: str, now_ts: float) -> Alert | None:
        """Parse a werkzeug log line and decide whether to alert."""
        # Skip non-request lines (startup messages, warnings, etc.)
        if "HTTP/" not in line:
            return None

        m = WERKZEUG_RE.search(line)
        if not m:
            return None

        ip = m.group("ip")
        method = m.group("method")
        path = m.group("path")
        status = int(m.group("status"))
        ts_str = m.group("ts")

        # Parse timestamp: "18/Mar/2026 01:37:30"
        try:
            from datetime import datetime, timezone
            dt = datetime.strptime(ts_str, "%d/%b/%Y %H:%M:%S")
            dt = dt.replace(tzinfo=timezone.utc)
            timestamp = dt.isoformat()
        except ValueError:
            timestamp = now_iso()

        # Skip benign paths
        if BENIGN_PATHS.match(path):
            return None

        # Check for vulnerability scan paths
        is_scan = bool(SCAN_PATHS.search(path))

        # Check for scan burst
        is_burst = False
        if is_scan:
            history = self._scan_history.setdefault(ip, [])
            history.append(now_ts)
            # Prune old entries
            history[:] = [t for t in history if now_ts - t < SCAN_BURST_WINDOW]
            if not history:
                # Drop the IP key once the window has expired so the dict
                # does not accumulate one entry per scanner forever.
                self._scan_history.pop(ip, None)
            elif len(history) >= SCAN_BURST_THRESHOLD:
                is_burst = True

        # Determine what to alert on
        if is_burst:
            count = len(self._scan_history.get(ip, []))
            return Alert(
                timestamp=timestamp,
                source=AlertSource.WEBAPP,
                source_ref=f"webapp-scan-burst-{ip}",
                severity="high",
                title=f"[{self.app_name}] Vulnerability scan burst from {ip}",
                description=(
                    f"Detected {count} scan probes in {SCAN_BURST_WINDOW}s from {ip}. "
                    f"Latest: {method} {path} → {status}. "
                    f"Probed paths include sensitive files (.env, .git, wp-config, etc.)"
                ),
                src_ip=ip,
                dst_ip=self.server_ip,
                dst_port=self.server_port,
                proto="HTTP",
                category="web/scan",
                signature_id=900001,
                raw=line,
            )
        elif is_scan:
            return Alert(
                timestamp=timestamp,
                source=AlertSource.WEBAPP,
                source_ref=f"webapp-scan-{hashlib.md5((ip + method + path).encode()).hexdigest()[:12]}",
                severity="medium",
                title=f"[{self.app_name}] Scan probe: {method} {path}",
                description=f"Suspicious path probed by {ip}: {method} {path} → {status}",
                src_ip=ip,
                dst_ip=self.server_ip,
                dst_port=self.server_port,
                proto="HTTP",
                category="web/scan",
                signature_id=900002,
                raw=line,
            )
        elif status >= 500:
            return Alert(
                timestamp=timestamp,
                source=AlertSource.WEBAPP,
                source_ref=f"webapp-5xx-{hashlib.md5((ip + method + path + str(status)).encode()).hexdigest()[:12]}",
                severity="high",
                title=f"[{self.app_name}] Server error: {method} {path} → {status}",
                description=f"HTTP {status} from {ip} on {method} {path}",
                src_ip=ip,
                dst_ip=self.server_ip,
                dst_port=self.server_port,
                proto="HTTP",
                category="web/error",
                signature_id=900003,
                raw=line,
            )
        elif status == 401 or status == 403:
            return Alert(
                timestamp=timestamp,
                source=AlertSource.WEBAPP,
                source_ref=f"webapp-auth-{hashlib.md5((ip + method + path + str(status)).encode()).hexdigest()[:12]}",
                severity="medium",
                title=f"[{self.app_name}] Auth failure: {method} {path} → {status}",
                description=f"HTTP {status} (unauthorized/forbidden) from {ip} on {method} {path}",
                src_ip=ip,
                dst_ip=self.server_ip,
                dst_port=self.server_port,
                proto="HTTP",
                category="web/auth",
                signature_id=900004,
                raw=line,
            )

        # Normal 200/302/404 on non-scan paths - no alert
        return None
