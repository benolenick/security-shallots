from __future__ import annotations

import asyncio
import json
import socket
from datetime import datetime, timezone

from argus.core.events import ArgusEvent


class SyslogSink:
    def __init__(self, enabled: bool, host: str, port: int = 5514, protocol: str = "udp") -> None:
        self.enabled = bool(enabled) and bool(host.strip())
        self.host = host.strip()
        self.port = int(port)
        proto = protocol.strip().lower()
        self.protocol = proto if proto in {"udp", "tcp"} else "udp"

    async def emit(self, event: ArgusEvent) -> None:
        if not self.enabled:
            return
        msg = self._format_message(event)
        await asyncio.to_thread(self._send_message, msg)

    def _format_message(self, event: ArgusEvent) -> bytes:
        sev_map = {"critical": 2, "high": 3, "medium": 4, "low": 6}
        severity = sev_map.get(str(event.severity).lower(), 5)
        facility = 16  # local0
        pri = facility * 8 + severity
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        host = event.host or "argus-host"
        payload = json.dumps(event.to_dict(), separators=(",", ":"), ensure_ascii=True)
        line = f"<{pri}>1 {ts} {host} argus - - - {payload}"
        return line.encode("utf-8", "replace")

    def _send_message(self, message: bytes) -> None:
        try:
            if self.protocol == "tcp":
                with socket.create_connection((self.host, self.port), timeout=2.0) as sock:
                    sock.sendall(message + b"\n")
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.sendto(message, (self.host, self.port))
        except OSError:
            return
