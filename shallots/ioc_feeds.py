"""IoC (Indicator of Compromise) feed ingestion and matching."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import aiohttp

if TYPE_CHECKING:
    from shallots.store.db import AlertDB

log = logging.getLogger(__name__)

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\.?$")

DEFAULT_FEEDS = [
    {
        "name": "feodo_tracker",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "type": "ip",
        "format": "txt",
        "interval_hours": 24,
    },
    {
        "name": "urlhaus_recent",
        "url": "https://urlhaus.abuse.ch/downloads/text_recent/",
        "type": "domain",
        "format": "txt",
        "interval_hours": 24,
    },
]


@dataclass
class IocFeedConfig:
    enabled: bool = False
    feeds: list[dict] = field(default_factory=list)


class IocFeedWorker:
    """Fetches threat-intel feeds on a schedule and stores indicators in the DB."""

    def __init__(self, cfg: IocFeedConfig, db: AlertDB):
        self.cfg = cfg
        self.db = db
        self._feeds = cfg.feeds if cfg.feeds else list(DEFAULT_FEEDS)
        # Track last refresh per feed name
        self._last_refresh: dict[str, float] = {}

    async def run(self, shutdown: asyncio.Event) -> None:
        """Loop that refreshes feeds at their configured interval."""
        log.info("IoC feed worker started with %d feeds", len(self._feeds))
        # Small startup delay so the DB is fully ready
        await asyncio.sleep(5)

        while not shutdown.is_set():
            now = asyncio.get_event_loop().time()

            for feed in self._feeds:
                name = feed.get("name", "unknown")
                interval_sec = feed.get("interval_hours", 24) * 3600
                last = self._last_refresh.get(name, 0.0)

                if now - last < interval_sec:
                    continue

                try:
                    indicators = await self._fetch_feed(feed)
                    if indicators:
                        feed_type = feed.get("type", "ip")
                        await self._store_indicators(name, feed_type, indicators)
                        log.info("IoC feed '%s': ingested %d indicators", name, len(indicators))
                    else:
                        log.debug("IoC feed '%s': no indicators returned", name)
                    self._last_refresh[name] = now
                except Exception:
                    log.exception("IoC feed '%s': fetch failed", name)

            # Check every 5 minutes whether any feed needs a refresh
            try:
                await asyncio.wait_for(shutdown.wait(), timeout=300)
                return  # shutdown was set
            except asyncio.TimeoutError:
                pass

    async def _fetch_feed(self, feed: dict) -> list[str]:
        """Download a feed URL and parse lines (skip comments starting with #)."""
        url = feed.get("url", "")
        if not url:
            return []

        timeout = aiohttp.ClientTimeout(total=60)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    log.warning("IoC feed '%s': HTTP %d from %s",
                                feed.get("name", "?"), resp.status, url)
                    return []
                text = await resp.text()

        indicators: list[str] = []
        seen: set[str] = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # For CSV format, take the first column
            fmt = feed.get("format", "txt")
            if fmt == "csv":
                parts = line.split(",")
                val = parts[0].strip().strip('"')
            else:
                val = line
            for indicator in normalize_indicator_values(feed.get("type", "ip"), val):
                if indicator not in seen:
                    indicators.append(indicator)
                    seen.add(indicator)

        return indicators

    async def _store_indicators(self, feed_name: str, feed_type: str, indicators: list[str]) -> None:
        """Store indicators in the ioc_indicators table."""
        for value in indicators:
            await self.db.upsert_ioc_indicator(
                feed_name=feed_name,
                indicator_type=feed_type,
                value=value,
                context=f"Feed: {feed_name}",
                ttl_hours=48,
            )

    async def match_alert(self, alert: dict) -> list[dict]:
        """Check an alert against stored IoC indicators.

        Checks src_ip/dst_ip against IP indicators and
        title/description against domain indicators.
        """
        matches: list[dict] = []

        # Check IPs
        for ip_field in ("src_ip", "dst_ip"):
            ip_val = alert.get(ip_field, "")
            if ip_val:
                hits = await self.db.check_ioc(ip_val)
                for hit in hits:
                    matches.append({
                        "field": ip_field,
                        "value": ip_val,
                        "feed": hit["feed_name"],
                        "indicator_type": hit["indicator_type"],
                        "indicator": hit["value"],
                        "context": hit.get("context", ""),
                    })

        text_blob = " ".join([
            alert.get("title", ""),
            alert.get("description", ""),
        ]).lower()

        # Check domain candidates from title / description. Avoid scanning the
        # entire feed table; URLHaus alone can contribute thousands of hosts.
        for domain in extract_domain_candidates(text_blob):
            if _is_mega_platform(domain):
                # urlhaus_recent_hosts extracts URL hostnames, not domain-level
                # indicators; free text merely mentioning google.com/github.com
                # (e.g. a benign "curl drive.google.com" in an exec-monitoring
                # alert) is not evidence of compromise. See pihole_dns.py for
                # the same false positive caught live against DNS lookups.
                continue
            hits = await self.db.check_ioc(domain)
            for hit in hits:
                if hit["indicator_type"] != "domain":
                    continue
                matches.append({
                    "field": "title/description",
                    "value": domain,
                    "feed": hit["feed_name"],
                    "indicator_type": "domain",
                    "indicator": hit["value"],
                    "context": hit.get("context", ""),
                })

        return matches

    async def refresh_all(self) -> dict:
        """Manually trigger a refresh of all feeds. Returns summary."""
        results: dict[str, int] = {}
        for feed in self._feeds:
            name = feed.get("name", "unknown")
            try:
                indicators = await self._fetch_feed(feed)
                if indicators:
                    feed_type = feed.get("type", "ip")
                    await self._store_indicators(name, feed_type, indicators)
                results[name] = len(indicators) if indicators else 0
                self._last_refresh[name] = asyncio.get_event_loop().time()
            except Exception as exc:
                log.exception("IoC feed '%s': manual refresh failed", name)
                results[name] = -1
        return results


def normalize_indicator_values(feed_type: str, raw_value: str) -> list[str]:
    """Normalize a raw feed value into one or more stored indicators."""
    value = raw_value.strip().strip('"').strip("'")
    if not value or len(value) >= 256:
        return []

    if feed_type == "ip":
        return _normalize_ip_indicator(value)
    if feed_type == "domain":
        return _normalize_domain_indicator(value)
    return [value]


def _normalize_ip_indicator(value: str) -> list[str]:
    try:
        return [str(ipaddress.ip_address(value))]
    except ValueError:
        return []


def _normalize_domain_indicator(value: str) -> list[str]:
    candidate = value
    if "://" in candidate:
        parsed = urlparse(candidate)
        candidate = parsed.hostname or ""
    elif "/" in candidate:
        candidate = candidate.split("/", 1)[0]

    candidate = candidate.strip().strip(".").lower()
    if not candidate:
        return []

    try:
        ipaddress.ip_address(candidate)
        return []
    except ValueError:
        pass

    if not _DOMAIN_RE.match(candidate):
        return []
    return [candidate]


# The malware-domain feed (urlhaus_recent_hosts) extracts the HOSTNAME of
# malicious URLs, not domain-level indicators - see the matching note above
# match_alert's domain-candidate loop and shallots/ingest/pihole_dns.py,
# which caught this same feed flagging www.google.com live in production.
_MEGA_PLATFORM_APEX = {
    "google.com", "googleapis.com", "gmail.com", "youtube.com", "goo.gl",
    "github.com", "githubusercontent.com", "raw.githubusercontent.com",
    "microsoft.com", "live.com", "office.com", "outlook.com", "msn.com",
    "apple.com", "icloud.com", "amazon.com", "cloudflare.com",
    "facebook.com", "instagram.com", "whatsapp.com", "fbcdn.net",
    "twitter.com", "x.com", "linkedin.com", "dropbox.com",
}


def _is_mega_platform(domain: str) -> bool:
    return any(domain == p or domain.endswith("." + p) for p in _MEGA_PLATFORM_APEX)


def extract_domain_candidates(text: str) -> list[str]:
    """Extract plausible domain names from alert text for exact IoC lookup."""
    seen: set[str] = set()
    candidates: list[str] = []
    for raw in re.findall(r"[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,63}", text):
        domain = raw.strip(".").lower()
        if domain in seen:
            continue
        if normalize_indicator_values("domain", domain):
            candidates.append(domain)
            seen.add(domain)
    return candidates
