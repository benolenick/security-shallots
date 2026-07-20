"""CrowdSec Local API poller."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shallots.config import CrowdSecConfig

from shallots.store.models import Alert, AlertSource, now_iso

log = logging.getLogger(__name__)

POLL_INTERVAL = 30  # seconds

# CrowdSec decision type → severity
_TYPE_SEVERITY: dict[str, str] = {
    "ban": "high",
    "captcha": "medium",
    "throttle": "low",
    "challenge": "medium",
}


def _decision_severity(decision_type: str, duration: str) -> str:
    """Map decision type (and optionally duration) to severity."""
    base = _TYPE_SEVERITY.get(decision_type.lower(), "medium")
    # Escalate bans longer than 24h to critical
    if decision_type.lower() == "ban" and duration:
        try:
            # Duration format: "24h0m0s" or "87600h0m0s"
            hours = 0
            if "h" in duration:
                hours = float(duration.split("h")[0])
            if hours >= 168:  # 1 week+
                return "critical"
        except (ValueError, IndexError):
            pass
    return base


class CrowdSecIngestor:
    """Polls CrowdSec Local API for new decisions.

    Uses GET /v1/decisions with an API key header.
    Tracks the last poll timestamp to avoid re-processing decisions.
    Only retrieves new decisions added since last poll using the `since`
    query parameter.
    """

    def __init__(self, config: CrowdSecConfig, queue: asyncio.Queue):
        self.api_url = config.api_url.rstrip("/")
        self.api_key = config.api_key
        self.queue = queue
        self._last_poll: str = ""  # ISO timestamp of last successful poll
        self._session: Any = None  # aiohttp.ClientSession
        self._seen_decision_ids: set[str] = set()

    async def run(self) -> None:
        """Main loop: poll CrowdSec LAPI every POLL_INTERVAL seconds."""
        log.info("CrowdSec ingestor polling: %s", self.api_url)

        try:
            import aiohttp
        except ImportError:
            log.error("aiohttp not installed — CrowdSec ingestor disabled")
            return

        headers = {
            "X-Api-Key": self.api_key,
            "Content-Type": "application/json",
        }

        async with aiohttp.ClientSession(headers=headers) as session:
            self._session = session
            # On first start, record current time as baseline so we only
            # get decisions created after startup.
            self._last_poll = datetime.now(timezone.utc).isoformat()
            await self._seed_existing_decisions(session)

            while True:
                try:
                    await self._poll(session)
                except asyncio.CancelledError:
                    return
                except Exception:
                    log.exception("CrowdSec poll error")
                await asyncio.sleep(POLL_INTERVAL)

    async def _seed_existing_decisions(self, session: Any) -> None:
        """Record active decisions at startup without emitting alerts."""
        import aiohttp

        url = f"{self.api_url}/v1/decisions"
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return
                decisions = await resp.json()
        except aiohttp.ClientError:
            return
        if not decisions:
            return
        for decision in decisions:
            decision_id = str((decision or {}).get("id") or "")
            if decision_id:
                self._seen_decision_ids.add(decision_id)
        log.info("CrowdSec: baselined %d existing active decisions", len(self._seen_decision_ids))

    async def _poll(self, session: Any) -> None:
        """Fetch new decisions from LAPI and enqueue as Alerts."""
        import aiohttp

        params: dict[str, str] = {}
        if self._last_poll:
            params["since"] = self._last_poll

        url = f"{self.api_url}/v1/decisions"
        poll_time = datetime.now(timezone.utc).isoformat()

        try:
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    decisions = await resp.json()
                    if decisions:  # may be null/None when no new decisions
                        log.debug("CrowdSec: received %d new decisions", len(decisions))
                        for decision in decisions:
                            decision_id = str((decision or {}).get("id") or "")
                            if decision_id and decision_id in self._seen_decision_ids:
                                continue
                            if decision_id:
                                self._seen_decision_ids.add(decision_id)
                            alert = self._decision_to_alert(decision)
                            if alert:
                                await self.queue.put(alert)
                    self._last_poll = poll_time
                elif resp.status == 204:
                    # No content — no new decisions, still advance timestamp
                    self._last_poll = poll_time
                elif resp.status == 403:
                    log.error("CrowdSec LAPI auth failed — check api_key in config")
                else:
                    body = await resp.text()
                    log.warning("CrowdSec LAPI returned %d: %s", resp.status, body[:200])
        except aiohttp.ClientConnectorError:
            log.warning("Cannot connect to CrowdSec LAPI at %s", self.api_url)

    def _decision_to_alert(self, decision: dict[str, Any]) -> Alert | None:
        """Convert a CrowdSec decision dict to an Alert."""
        if not decision:
            return None

        decision_type = decision.get("type", "ban")
        value = decision.get("value", "")       # IP or CIDR
        scope = decision.get("scope", "Ip")     # Ip, Range, Country, etc.
        scenario = decision.get("scenario", "")
        origin = decision.get("origin", "crowdsec")
        duration = decision.get("duration", "")
        decision_id = str(decision.get("id", ""))
        created_at = decision.get("start_at", now_iso())

        # CAPI/community decisions are already-enforced CrowdSec intelligence.
        # Storing every active community ban as a Shallots alert floods the tiny
        # hub without improving operator awareness. Local decisions still become
        # alerts because they describe this network's own observed behavior.
        if str(origin).upper() == "CAPI":
            return None

        # Extract IP from value (may be IP, CIDR, or country)
        src_ip = ""
        if scope.lower() in ("ip", "range"):
            src_ip = value

        title = f"CrowdSec {decision_type.upper()}: {value}"
        if scenario:
            title += f" ({scenario})"

        description = (
            f"CrowdSec decision: {decision_type} {scope} {value}. "
            f"Scenario: {scenario}. Origin: {origin}. Duration: {duration}."
        )

        return Alert(
            timestamp=created_at,
            source=AlertSource.CROWDSEC,
            source_ref=decision_id,
            severity=_decision_severity(decision_type, duration),
            title=title,
            description=description,
            src_ip=src_ip,
            src_port=0,
            dst_ip="",
            dst_port=0,
            proto="",
            category=f"crowdsec/{decision_type}",
            signature_id=0,
            raw=str(decision),
        )
