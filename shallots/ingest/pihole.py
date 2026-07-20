"""Pi-hole DNS query log poller.

Polls Pi-hole's API for recently blocked queries and converts them to alerts.
Only blocked queries generate alerts - permitted queries are ignored to avoid
flooding the alert pipeline.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shallots.config import PiHoleConfig

from shallots.store.models import Alert, AlertSource, now_iso

log = logging.getLogger(__name__)

POLL_INTERVAL = 60  # seconds - Pi-hole updates once per second but we batch

# Pi-hole block reason codes (from FTL) that indicate a block
_BLOCKED_STATUSES = {
    1,   # gravity (blocklist)
    4,   # regex deny
    5,   # exact deny
    6,   # external blocked (CNAME)
    7,   # external blocked (IP)
    8,   # external blocked (NULL)
    9,   # regex deny (CNAME)
    10,  # exact deny (CNAME)
    11,  # special domain
}

# Map block status to a human-readable reason
_STATUS_NAMES = {
    1: "blocklist (gravity)",
    4: "regex deny",
    5: "exact deny",
    6: "CNAME blocked (external)",
    7: "IP blocked (external)",
    8: "NULL blocked (external)",
    9: "regex deny (CNAME)",
    10: "exact deny (CNAME)",
    11: "special domain",
}


class PiHoleIngestor:
    """Polls Pi-hole API for blocked DNS queries.

    Uses GET /admin/api.php?getAllQueries=N&auth=TOKEN or the newer
    /api/queries endpoint (Pi-hole v6+).  Falls back gracefully.

    Only blocked queries are emitted as alerts - we don't care about
    permitted DNS traffic for the security pipeline.
    """

    def __init__(self, config: PiHoleConfig, queue: asyncio.Queue):
        self.api_url = config.api_url.rstrip("/")
        self.api_key = config.api_key
        self.queue = queue
        # Track timestamp of last seen query to avoid duplicates
        self._last_ts: float = 0.0

    async def run(self) -> None:
        """Main loop: poll Pi-hole every POLL_INTERVAL seconds."""
        log.info("Pi-hole ingestor polling: %s", self.api_url)

        try:
            import aiohttp
        except ImportError:
            log.error("aiohttp not installed - Pi-hole ingestor disabled")
            return

        # On first start, only look at queries from now onwards
        self._last_ts = datetime.now(timezone.utc).timestamp()

        async with aiohttp.ClientSession() as session:
            while True:
                try:
                    await self._poll(session)
                except asyncio.CancelledError:
                    return
                except Exception:
                    log.exception("Pi-hole poll error")
                await asyncio.sleep(POLL_INTERVAL)

    async def _poll(self, session: Any) -> None:
        """Fetch recent blocked queries from Pi-hole."""
        import aiohttp

        # Try v5 API first (most common deployment)
        url = f"{self.api_url}/admin/api.php"
        params = {
            "getAllQueries": "100",  # last 100 queries
            "auth": self.api_key,
        }

        try:
            async with session.get(
                url, params=params, timeout=aiohttp.ClientTimeout(total=10),
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    queries = data.get("data", [])
                    await self._process_v5_queries(queries)
                    return
                elif resp.status == 401:
                    log.error("Pi-hole auth failed - check api_key")
                    return
        except aiohttp.ClientConnectorError:
            log.warning("Cannot connect to Pi-hole at %s", self.api_url)
            return

    async def _process_v5_queries(self, queries: list) -> None:
        """Process Pi-hole v5 API query results.

        Each query is a list:
        [timestamp, type, domain, client, status, ?, ?, reply_type, reply_time, CNAME]
        """
        new_count = 0
        for row in queries:
            if len(row) < 5:
                continue

            ts = float(row[0])
            if ts <= self._last_ts:
                continue

            status = int(row[4])
            if status not in _BLOCKED_STATUSES:
                continue

            domain = row[2]
            client = row[3]
            query_type = row[1]
            reason = _STATUS_NAMES.get(status, f"blocked (status {status})")

            alert = Alert(
                timestamp=datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                source=AlertSource.PIHOLE,
                source_ref=f"pihole-{int(ts)}-{domain}",
                severity="low",
                title=f"DNS blocked: {domain}",
                description=(
                    f"Pi-hole blocked DNS query for {domain} "
                    f"(type: {query_type}, reason: {reason}) "
                    f"from client {client}"
                ),
                src_ip=client,
                src_port=0,
                dst_ip="",
                dst_port=53,
                proto="dns",
                category=f"pihole/{reason.split('(')[0].strip()}",
                signature_id=0,
                raw=str(row),
            )
            await self.queue.put(alert)
            new_count += 1

        if new_count:
            log.debug("Pi-hole: enqueued %d blocked queries", new_count)

        # Advance watermark
        if queries:
            latest_ts = max(float(r[0]) for r in queries if len(r) >= 1)
            if latest_ts > self._last_ts:
                self._last_ts = latest_ts
