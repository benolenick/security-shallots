"""Remote log shipper - sends alerts to Elasticsearch or VictoriaLogs."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import aiohttp

if TYPE_CHECKING:
    from shallots.config import StorageConfig
    from shallots.store.db import AlertDB

log = logging.getLogger(__name__)


class Shipper:
    """Batches alerts and ships them to remote Elasticsearch or VictoriaLogs."""

    def __init__(self, config: StorageConfig, db: AlertDB):
        self.config = config
        self.db = db
        self._session: aiohttp.ClientSession | None = None
        self._last_shipped_id = ""
        self._batch_size = 100
        self._interval = 30  # seconds

    async def run(self, shutdown: asyncio.Event) -> None:
        """Main shipping loop."""
        if not self.config.elasticsearch_url and not self.config.victorialogs_url:
            log.info("No remote shipping configured, shipper disabled")
            return

        self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30))
        log.info("Shipper started (ES=%s, VL=%s)",
                 self.config.elasticsearch_url or "disabled",
                 self.config.victorialogs_url or "disabled")

        try:
            while not shutdown.is_set():
                try:
                    await self._ship_batch()
                except Exception:
                    log.exception("Shipper batch error")
                await asyncio.sleep(self._interval)
        finally:
            await self._session.close()

    async def _ship_batch(self) -> None:
        """Ship a batch of new alerts."""
        # Get alerts newer than last shipped
        alerts = await self.db.get_alerts(limit=self._batch_size)
        if not alerts:
            return

        # Filter to only unshipped
        new_alerts = []
        for a in alerts:
            if a["id"] > self._last_shipped_id:
                new_alerts.append(a)

        if not new_alerts:
            return

        if self.config.elasticsearch_url:
            await self._ship_elasticsearch(new_alerts)

        if self.config.victorialogs_url:
            await self._ship_victorialogs(new_alerts)

        self._last_shipped_id = new_alerts[0]["id"]
        log.debug("Shipped %d alerts", len(new_alerts))

    async def _ship_elasticsearch(self, alerts: list[dict]) -> None:
        """Ship alerts to Elasticsearch using bulk API."""
        url = self.config.elasticsearch_url.rstrip("/")
        index = f"shallots-alerts-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"

        lines = []
        for alert in alerts:
            meta = json.dumps({"index": {"_index": index, "_id": alert["id"]}})
            doc = json.dumps(alert, default=str)
            lines.append(meta)
            lines.append(doc)

        body = "\n".join(lines) + "\n"

        try:
            async with self._session.post(
                f"{url}/_bulk",
                data=body,
                headers={"Content-Type": "application/x-ndjson"},
            ) as resp:
                if resp.status >= 400:
                    text = await resp.text()
                    log.error("ES bulk error: %d %s", resp.status, text[:500])
                else:
                    result = await resp.json()
                    if result.get("errors"):
                        log.warning("ES bulk had errors: %s",
                                    json.dumps(result.get("items", [])[:3]))
        except aiohttp.ClientError as e:
            log.error("ES connection error: %s", e)

    async def _ship_victorialogs(self, alerts: list[dict]) -> None:
        """Ship alerts to VictoriaLogs using JSON line ingestion."""
        url = self.config.victorialogs_url.rstrip("/")

        lines = []
        for alert in alerts:
            entry = {
                "_time": alert.get("timestamp", ""),
                "_msg": alert.get("title", ""),
                "source": alert.get("source", ""),
                "severity": alert.get("severity", ""),
                "src_ip": alert.get("src_ip", ""),
                "dst_ip": alert.get("dst_ip", ""),
                "category": alert.get("category", ""),
                "verdict": alert.get("verdict", ""),
                "signature_id": str(alert.get("signature_id", "")),
                "alert_id": alert.get("id", ""),
            }
            lines.append(json.dumps(entry))

        body = "\n".join(lines)

        try:
            async with self._session.post(
                f"{url}/insert/jsonline",
                data=body,
                headers={"Content-Type": "application/stream+json"},
                params={"_stream_fields": "source,severity,verdict"},
            ) as resp:
                if resp.status >= 400:
                    text = await resp.text()
                    log.error("VictoriaLogs error: %d %s", resp.status, text[:500])
        except aiohttp.ClientError as e:
            log.error("VictoriaLogs connection error: %s", e)
