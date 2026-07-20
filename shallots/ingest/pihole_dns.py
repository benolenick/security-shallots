"""Pi-hole DNS ingest + detection.

Tails Pi-hole v6's query log (pihole-FTL.db `queries` view) and turns SUSPICIOUS
DNS lookups into Shallots alerts — without flooding on ordinary browsing. Two
detections in v1:

  1. Malware-domain lookup — the queried domain (or a parent) matches a loaded
     threat-intel DOMAIN indicator (e.g. URLHaus). A host resolving a known
     malware/C2 domain is a strong callback signal. -> high.
  2. DGA-looking domain — long, high-entropy, consonant-heavy label with no
     dictionary shape (classic domain-generation-algorithm C2). -> medium.

Only these are emitted as alerts; the ~thousands of normal daily queries are not.
Runs as a daemon worker; Pi-hole and Shallots must be co-located on the same host
so this reads the FTL DB locally (the service user must be in the `pihole` group).
"""
from __future__ import annotations

import logging
import math
import asyncio
import sqlite3

log = logging.getLogger(__name__)


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _looks_dga(label: str) -> bool:
    """Heuristic: long, high-entropy, vowel-poor label with digits mixed in."""
    if len(label) < 12 or len(label) > 63:
        return False
    if _shannon(label) < 3.6:
        return False
    letters = [c for c in label if c.isalpha()]
    if not letters:
        return False
    vowels = sum(1 for c in letters if c in "aeiou")
    vowel_ratio = vowels / len(letters)
    digits = sum(1 for c in label if c.isdigit())
    # DGA domains are vowel-poor and/or digit-speckled with no real words
    return vowel_ratio < 0.26 or (digits >= 3 and vowel_ratio < 0.40)


# Legit high-entropy parents (CDN/cloud) — their random-looking SUBDOMAINS are
# not DGA. Malware-domain MATCHING is exact/IoC-based and unaffected by this list.
_CDN_PARENTS = {
    "googlevideo.com", "ggpht.com", "gvt1.com", "gvt2.com", "1e100.net",
    "googleusercontent.com", "gstatic.com", "akamai.net", "akamaiedge.net",
    "akamaihd.net", "edgekey.net", "edgesuite.net", "akadns.net", "cloudfront.net",
    "fastly.net", "fastlylb.net", "azureedge.net", "azurefd.net", "trafficmanager.net",
    "windows.net", "cloudapp.net", "cloudflare.net", "cloudflare.com", "llnwd.net",
    "cdn77.org", "b-cdn.net", "stackpathdns.com", "msedge.net", "amazonaws.com",
    "github.io", "herokuapp.com", "sharepoint.com", "office365.com", "live.com",
}


def _is_cdn(domain: str) -> bool:
    return any(domain == p or domain.endswith("." + p) for p in _CDN_PARENTS)


def _parent_domains(domain: str):
    """Yield the domain and each parent suffix: a.b.evil.com -> a.b.evil.com, b.evil.com, evil.com."""
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        yield ".".join(parts[i:])


class PiholeDnsIngestor:
    """Reads new Pi-hole queries and emits alerts for suspicious lookups."""

    def __init__(self, cfg, db, alert_queue):
        self.cfg = cfg              # PiholeConfig
        self.db = db               # AlertDB (for IoC domain set)
        self.alert_queue = alert_queue
        self._last_id = 0
        self._malware_domains: set[str] = set()
        self._domains_loaded_at = 0.0
        self._seen_hits: set[tuple] = set()   # (client, domain) dedup within a run

    async def _load_malware_domains(self) -> None:
        try:
            rows = await self.db.execute_sql(
                "SELECT value FROM ioc_indicators WHERE indicator_type = 'domain'",
                (), max_rows=100000,
            )
            self._malware_domains = {(_r["value"] or "").strip().lower() for _r in rows}
            log.info("Pi-hole DNS: loaded %d malware-domain indicators", len(self._malware_domains))
        except Exception:
            log.debug("Pi-hole DNS: could not load domain indicators", exc_info=True)

    def _read_new_queries(self) -> list[tuple]:
        """Local read of new Pi-hole queries (blocking; called in executor)."""
        try:
            conn = sqlite3.connect(f"file:{self.cfg.db_path}?mode=ro", uri=True, timeout=5)
            try:
                cur = conn.execute(
                    "SELECT id, timestamp, client, domain, status, reply_type "
                    "FROM queries WHERE id > ? ORDER BY id ASC LIMIT 5000",
                    (self._last_id,),
                )
                return cur.fetchall()
            finally:
                conn.close()
        except Exception as e:
            log.debug("Pi-hole DNS: read failed: %s", e)
            return []

    def _max_id(self) -> int:
        try:
            conn = sqlite3.connect(f"file:{self.cfg.db_path}?mode=ro", uri=True, timeout=5)
            try:
                r = conn.execute("SELECT MAX(id) FROM queries").fetchone()
                return int(r[0]) if r and r[0] else 0
            finally:
                conn.close()
        except Exception:
            return 0

    def _match_malware(self, domain: str) -> str | None:
        for d in _parent_domains(domain):
            if d in self._malware_domains:
                return d
        return None

    async def run(self, shutdown) -> None:
        from shallots.store.models import Alert, now_iso
        loop = asyncio.get_running_loop()
        await self._load_malware_domains()
        # start from the current tail so we don't replay history on first boot
        self._last_id = await loop.run_in_executor(None, self._max_id)
        log.info("Pi-hole DNS ingestor started (from query id %d, %s)",
                 self._last_id, self.cfg.db_path)

        cycles = 0
        while not shutdown.is_set():
            await asyncio.sleep(max(5, int(self.cfg.poll_interval_sec)))
            cycles += 1
            if cycles % 120 == 0:      # refresh IoC domains ~hourly
                await self._load_malware_domains()
            rows = await loop.run_in_executor(None, self._read_new_queries)
            if not rows:
                continue
            for qid, ts, client, domain, status, reply_type in rows:
                self._last_id = max(self._last_id, qid)
                domain = (domain or "").strip().lower().rstrip(".")
                if not domain or "." not in domain:
                    continue
                client = client or ""
                key = (client, domain)

                hit = self._match_malware(domain)
                if hit:
                    if key in self._seen_hits:
                        continue
                    self._seen_hits.add(key)
                    await self._emit(Alert(
                        timestamp=now_iso(), source="pihole", source_ref=f"dns:{domain}",
                        severity="high", category="dns",
                        title=f"DNS lookup of known-malware domain ({domain})",
                        description=(f"{client} asked Pi-hole to resolve {domain}, which matches "
                                     f"threat-intel domain indicator '{hit}'. This is a common "
                                     f"malware/C2 callback signal."),
                        src_ip=client, verdict="investigate", confidence=0.9,
                        ai_reasoning="Pi-hole DNS: queried domain matches a loaded malware-domain feed.",
                    ))
                    continue

                first_label = domain.split(".")[0]
                if _looks_dga(first_label) and not _is_cdn(domain):
                    if key in self._seen_hits:
                        continue
                    self._seen_hits.add(key)
                    await self._emit(Alert(
                        timestamp=now_iso(), source="pihole", source_ref=f"dga:{domain}",
                        severity="medium", category="dns",
                        title=f"Suspicious algorithm-generated domain lookup ({domain})",
                        description=(f"{client} looked up {domain}, whose name looks machine-generated "
                                     f"(high-entropy, dictionary-less) — a pattern used by malware that "
                                     f"rotates C2 domains."),
                        src_ip=client, verdict="investigate", confidence=0.55,
                        ai_reasoning="Pi-hole DNS: DGA-style high-entropy domain.",
                    ))
            # bound the dedup set
            if len(self._seen_hits) > 20000:
                self._seen_hits.clear()

    async def _emit(self, alert) -> None:
        try:
            self.alert_queue.put_nowait(alert)
        except asyncio.QueueFull:
            log.warning("Alert queue full, dropped Pi-hole DNS alert")
