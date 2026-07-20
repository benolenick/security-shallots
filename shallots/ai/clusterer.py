"""Alert clusterer — assigns alerts to hard clusters by (src_ip, title)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shallots.store.db import AlertDB
    from shallots.store.models import Alert

log = logging.getLogger(__name__)


class AlertClusterer:
    """Assigns incoming alerts to clusters keyed by (src_ip, title).

    Each unique (src_ip, title) pair gets exactly one cluster. New alerts
    matching an existing cluster are added to it. If the cluster has a
    non-pending verdict (e.g. 'suppress'), the new alert inherits it.
    """

    def __init__(self, db: AlertDB):
        self._db = db

    async def assign(self, alert: Alert) -> str | None:
        """Assign an alert to its cluster. Returns cluster_id.

        If the cluster already has a verdict != 'pending', the alert's
        verdict is updated to match (auto-suppress on assignment).
        """
        if not alert.id:
            return None

        cluster_id = await self._db.assign_alert_to_cluster(
            alert_id=alert.id,
            src_ip=alert.src_ip or "",
            title=alert.title or "",
            severity=alert.severity or "medium",
            timestamp=alert.timestamp or "",
        )

        # Auto-apply cluster verdict to new alerts
        cluster = await self._db.get_cluster(cluster_id)
        if cluster and cluster["verdict"] not in ("pending", ""):
            await self._db.update_verdict(
                alert_id=alert.id,
                verdict=cluster["verdict"],
                confidence=1.0,
                reasoning=f"Auto-applied from cluster verdict: {cluster['verdict']}",
            )
            log.debug("Clusterer: auto-applied verdict '%s' to alert %s from cluster %s",
                       cluster["verdict"], alert.id, cluster_id)

        return cluster_id

    async def backfill(self) -> int:
        """Backfill all unassigned alerts into clusters. Returns count."""
        count = await self._db.backfill_clusters()
        if count:
            log.info("Clusterer: backfilled %d alerts into clusters", count)
        return count
