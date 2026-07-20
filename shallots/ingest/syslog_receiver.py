"""Lightweight asyncio syslog receiver (UDP + TCP).

Parses RFC 3164 and RFC 5424 syslog messages. Detects pfSense filterlog
lines and routes them to the pfSense parser.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shallots.config import SyslogConfig

from shallots.store.models import Alert, AlertSource, now_iso

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Priority / facility decoding
# ---------------------------------------------------------------------------

FACILITIES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon",
    4: "auth", 5: "syslog", 6: "lpr", 7: "news",
    8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}

SEVERITIES = {
    0: "critical",   # Emergency
    1: "critical",   # Alert
    2: "critical",   # Critical
    3: "high",       # Error
    4: "medium",     # Warning
    5: "low",        # Notice
    6: "low",        # Informational
    7: "low",        # Debug
}

# RFC 3164: <PRI>TIMESTAMP HOST TAG: MSG
_RFC3164 = re.compile(
    r"^<(\d{1,3})>"                           # priority
    r"([A-Z][a-z]{2}\s+\d{1,2}\s[\d:]+)\s+"  # timestamp (e.g. Jan  1 00:00:00)
    r"(\S+)\s+"                                # hostname
    r"(\S+?):\s*"                              # tag (process[pid]:)
    r"(.*)"                                    # message
)

# RFC 5424: <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID SD MSG
_RFC5424 = re.compile(
    r"^<(\d{1,3})>(\d)\s+"                    # priority + version
    r"(\S+)\s+"                                # timestamp
    r"(\S+)\s+"                                # hostname
    r"(\S+)\s+"                                # app-name
    r"(\S+)\s+"                                # procid
    r"(\S+)\s+"                                # msgid
    r"(-|\[.*?\])\s*"                          # structured data
    r"(.*)"                                    # message
)

# pfSense filterlog detection
_FILTERLOG_RE = re.compile(r"\bfilterlog\b", re.IGNORECASE)

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _decode_priority(pri: int) -> tuple[int, int, str, str]:
    """Return (facility_num, severity_num, facility_name, severity_str)."""
    facility_num = pri >> 3
    severity_num = pri & 0x7
    facility_name = FACILITIES.get(facility_num, f"local{facility_num}")
    severity_str = SEVERITIES.get(severity_num, "low")
    return facility_num, severity_num, facility_name, severity_str


def parse_syslog(data: bytes) -> dict[str, Any] | None:
    """Parse a raw syslog message (bytes) into a structured dict.

    Returns None if the message cannot be parsed at all.
    """
    try:
        text = data.decode("utf-8", errors="replace").strip()
    except Exception:
        return None

    if not text:
        return None

    # Try RFC 5424 first (has version digit after priority)
    m = _RFC5424.match(text)
    if m:
        pri = int(m.group(1))
        _, _, facility, severity = _decode_priority(pri)
        return {
            "format": "rfc5424",
            "priority": pri,
            "facility": facility,
            "severity": severity,
            "timestamp": m.group(3),
            "hostname": m.group(4),
            "appname": m.group(5),
            "procid": m.group(6),
            "msgid": m.group(7),
            "structured_data": m.group(8),
            "message": m.group(9),
            "raw": text,
        }

    # Try RFC 3164
    m = _RFC3164.match(text)
    if m:
        pri = int(m.group(1))
        _, _, facility, severity = _decode_priority(pri)
        return {
            "format": "rfc3164",
            "priority": pri,
            "facility": facility,
            "severity": severity,
            "timestamp": m.group(2),
            "hostname": m.group(3),
            "appname": m.group(4),
            "procid": "",
            "msgid": "",
            "structured_data": "",
            "message": m.group(5),
            "raw": text,
        }

    # Fallback: no priority header — treat entire text as message
    return {
        "format": "raw",
        "priority": 14,  # user.info
        "facility": "user",
        "severity": "low",
        "timestamp": now_iso(),
        "hostname": "",
        "appname": "",
        "procid": "",
        "msgid": "",
        "structured_data": "",
        "message": text,
        "raw": text,
    }


def syslog_to_alert(parsed: dict[str, Any], src_addr: str = "") -> Alert:
    """Convert a parsed syslog dict to an Alert."""
    host = parsed.get("hostname", "") or ""
    return Alert(
        timestamp=now_iso(),
        source=AlertSource.SYSLOG,
        source_ref="",
        severity=parsed["severity"],
        title=f"Syslog [{parsed['facility']}] {parsed['appname']}".strip(),
        description=parsed["message"],
        src_ip=src_addr,
        src_asset=host,
        src_port=0,
        dst_ip="",
        dst_port=0,
        proto="",
        category=f"syslog/{parsed['facility']}",
        signature_id=parsed["priority"],
        raw=parsed["raw"],
    )


class _LowSeverityDuplicateLimiter:
    """Bound repeated low-severity syslog duplicates without hiding new events."""

    def __init__(self, limit: int = 20, window_sec: int = 60):
        self.limit = max(0, int(limit))
        self.window_sec = max(1, int(window_sec))
        self._max_buckets = 20000
        self._buckets: dict[tuple[str, str, str, str], tuple[float, int]] = {}

    def _sweep(self, now: float) -> None:
        """Drop expired buckets so a stream of distinct low-sev messages can't
        grow the map without bound (one permanent entry per unique message)."""
        for k in [k for k, (ws, _) in self._buckets.items()
                  if now - ws >= self.window_sec]:
            del self._buckets[k]
        if len(self._buckets) > self._max_buckets:
            oldest = sorted(self._buckets.items(), key=lambda kv: kv[1][0])
            for k, _ in oldest[: len(self._buckets) // 2]:
                del self._buckets[k]

    def allow(self, parsed: dict[str, Any], src_ip: str) -> bool:
        if self.limit <= 0:
            return True
        severity = str(parsed.get("severity") or "low")
        if _SEVERITY_RANK.get(severity, 0) >= _SEVERITY_RANK["medium"]:
            return True

        key = (
            src_ip,
            str(parsed.get("facility") or ""),
            str(parsed.get("appname") or ""),
            str(parsed.get("message") or ""),
        )
        now = time.monotonic()
        if len(self._buckets) > self._max_buckets:
            self._sweep(now)
        window_start, count = self._buckets.get(key, (now, 0))
        if now - window_start >= self.window_sec:
            self._buckets[key] = (now, 1)
            return True
        if count >= self.limit:
            return False
        self._buckets[key] = (window_start, count + 1)
        return True


# ---------------------------------------------------------------------------
# asyncio UDP protocol
# ---------------------------------------------------------------------------

class _SyslogUDPProtocol(asyncio.DatagramProtocol):
    """asyncio UDP protocol that receives syslog datagrams."""

    def __init__(
        self,
        queue: asyncio.Queue,
        pfsense_queue: asyncio.Queue | None,
        duplicate_limiter: _LowSeverityDuplicateLimiter,
    ):
        self.queue = queue
        self.pfsense_queue = pfsense_queue
        self.duplicate_limiter = duplicate_limiter

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        src_ip = addr[0]
        parsed = parse_syslog(data)
        if not parsed:
            return

        message = parsed.get("message", "")

        # Route pfSense filterlog to dedicated queue
        if self.pfsense_queue and _FILTERLOG_RE.search(message):
            try:
                self.pfsense_queue.put_nowait((message, src_ip, parsed))
            except asyncio.QueueFull:
                log.debug("pfSense queue full, dropping filterlog line")
            return

        if not self.duplicate_limiter.allow(parsed, src_ip):
            log.debug("Dropping repeated low-severity syslog duplicate from %s", src_ip)
            return

        alert = syslog_to_alert(parsed, src_ip)
        try:
            self.queue.put_nowait(alert)
        except asyncio.QueueFull:
            log.debug("Alert queue full, dropping syslog message from %s", src_ip)

    def error_received(self, exc: Exception) -> None:
        log.warning("UDP syslog error: %s", exc)


# ---------------------------------------------------------------------------
# TCP connection handler
# ---------------------------------------------------------------------------

async def _handle_tcp_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    queue: asyncio.Queue,
    pfsense_queue: asyncio.Queue | None,
    duplicate_limiter: _LowSeverityDuplicateLimiter,
) -> None:
    """Handle a single TCP syslog connection."""
    addr = writer.get_extra_info("peername", ("", 0))
    src_ip = addr[0] if addr else ""

    try:
        while True:
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=60.0)
            except asyncio.TimeoutError:
                break
            except (ValueError, asyncio.LimitOverrunError):
                # Oversized line (no newline within the buffer limit) — log
                # and drop this connection rather than dying silently.
                log.warning("Oversized TCP syslog line from %s; closing conn", src_ip)
                break
            if not line:
                break

            parsed = parse_syslog(line)
            if not parsed:
                continue

            message = parsed.get("message", "")

            if pfsense_queue and _FILTERLOG_RE.search(message):
                try:
                    pfsense_queue.put_nowait((message, src_ip, parsed))
                except asyncio.QueueFull:
                    pass
                continue

            if not duplicate_limiter.allow(parsed, src_ip):
                log.debug(
                    "Dropping repeated low-severity TCP syslog duplicate from %s",
                    src_ip,
                )
                continue

            alert = syslog_to_alert(parsed, src_ip)
            try:
                queue.put_nowait(alert)
            except asyncio.QueueFull:
                log.debug("Alert queue full, dropping TCP syslog from %s", src_ip)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        log.debug("TCP syslog client error from %s: %s", src_ip, e)
    finally:
        try:
            writer.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Main receiver
# ---------------------------------------------------------------------------

class SyslogReceiver:
    """Async UDP + TCP syslog listener.

    Parses RFC 3164 and RFC 5424 messages. pfSense filterlog lines are
    routed to a dedicated queue for the pfSense parser (if running).
    """

    def __init__(
        self,
        config: SyslogConfig,
        queue: asyncio.Queue,
        pfsense_queue: asyncio.Queue | None = None,
    ):
        self.udp_port = config.udp_port
        self.tcp_port = config.tcp_port
        self.queue = queue
        self.pfsense_queue = pfsense_queue
        self.duplicate_limiter = _LowSeverityDuplicateLimiter(
            config.low_severity_duplicate_limit,
            config.low_severity_duplicate_window_sec,
        )

    async def run(self) -> None:
        """Start UDP and TCP listeners."""
        log.info(
            "Syslog receiver starting (UDP:%d, TCP:%d)",
            self.udp_port, self.tcp_port,
        )
        loop = asyncio.get_running_loop()

        # UDP listener
        udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: _SyslogUDPProtocol(
                self.queue,
                self.pfsense_queue,
                self.duplicate_limiter,
            ),
            local_addr=("0.0.0.0", self.udp_port),
        )

        # TCP listener
        tcp_server = await asyncio.start_server(
            # 256 KiB line limit so legitimately large structured-data syslog
            # lines fit (default 64 KiB was easy to trip).
            lambda r, w: _handle_tcp_client(
                r,
                w,
                self.queue,
                self.pfsense_queue,
                self.duplicate_limiter,
            ),
            host="0.0.0.0",
            port=self.tcp_port,
        )

        log.info("Syslog receiver ready")

        try:
            async with tcp_server:
                await tcp_server.serve_forever()
        except asyncio.CancelledError:
            pass
        finally:
            udp_transport.close()
            tcp_server.close()
            log.info("Syslog receiver stopped")
