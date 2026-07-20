"""Alert enrichment: GeoIP, reverse DNS, asset lookup."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shallots.config import Config

from shallots.store.models import Alert

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# RFC 1918 / private address check
# ---------------------------------------------------------------------------

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),          # ULA
    ipaddress.ip_network("fe80::/10"),         # link-local v6
]


def is_private(ip: str) -> bool:
    """Return True if ip is an RFC 1918 / loopback / link-local address."""
    if not ip:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return True


# ---------------------------------------------------------------------------
# GeoIP lookup (MaxMind GeoLite2-City)
# ---------------------------------------------------------------------------

_geoip_reader: Any = None  # maxminddb.Reader instance


def _get_geoip_reader(db_path: str) -> Any:
    """Load (and cache) the MaxMind DB reader."""
    global _geoip_reader
    if _geoip_reader is not None:
        return _geoip_reader
    try:
        import maxminddb
        _geoip_reader = maxminddb.open_database(db_path)
        log.info("GeoIP database loaded: %s", db_path)
    except ImportError:
        log.warning("maxminddb not installed — GeoIP enrichment disabled")
    except FileNotFoundError:
        log.warning("GeoIP database not found: %s", db_path)
    except Exception as e:
        log.warning("Failed to open GeoIP database: %s", e)
    return _geoip_reader


def geoip_lookup(ip: str, db_path: str) -> str:
    """Return a human-readable location string for an IP.

    Returns empty string if lookup fails or IP is private.
    """
    if is_private(ip):
        return ""
    reader = _get_geoip_reader(db_path)
    if reader is None:
        return ""
    try:
        record = reader.get(ip)
        if not record:
            return ""
        parts: list[str] = []
        city = record.get("city", {})
        if city:
            names = city.get("names", {})
            city_name = names.get("en", "")
            if city_name:
                parts.append(city_name)
        country = record.get("country", {})
        if country:
            iso = country.get("iso_code", "")
            if iso:
                parts.append(iso)
        return ", ".join(parts) if parts else ""
    except Exception as e:
        log.debug("GeoIP lookup failed for %s: %s", ip, e)
        return ""


# ---------------------------------------------------------------------------
# Reverse DNS (async, with simple in-process cache)
# ---------------------------------------------------------------------------

# Cache: ip -> hostname (empty string = no PTR record or lookup failed)
_dns_cache: dict[str, str] = {}
_DNS_CACHE_MAX = 5000
# Dedicated bounded pool for blocking PTR lookups. run_in_executor(None, ...)
# let a burst of novel public IPs with slow/hung resolvers saturate the
# process-wide default pool and starve other executor work.
_dns_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="rdns")
_DNS_TIMEOUT_SEC = 3.0


async def rdns_lookup(ip: str) -> str:
    """Async reverse DNS lookup with in-process cache.

    Uses asyncio's run_in_executor to avoid blocking the event loop.
    Returns empty string if no PTR record found.
    """
    if not ip:
        return ""

    if ip in _dns_cache:
        return _dns_cache[ip]

    loop = asyncio.get_running_loop()
    try:
        # Own bounded pool + hard timeout: a hung resolver can neither block
        # the enrichment pipeline nor poison the shared default executor.
        result = await asyncio.wait_for(
            loop.run_in_executor(_dns_executor, socket.gethostbyaddr, ip),
            timeout=_DNS_TIMEOUT_SEC,
        )
        hostname = result[0]
    except (socket.herror, socket.gaierror, OSError):
        hostname = ""
    except asyncio.TimeoutError:
        hostname = ""  # negative-cached below; don't re-block on this IP
    except Exception as e:
        log.debug("rDNS error for %s: %s", ip, e)
        hostname = ""

    # Simple cache eviction: if too large, drop half the entries
    if len(_dns_cache) >= _DNS_CACHE_MAX:
        to_remove = list(_dns_cache.keys())[: _DNS_CACHE_MAX // 2]
        for k in to_remove:
            del _dns_cache[k]

    _dns_cache[ip] = hostname
    return hostname


# ---------------------------------------------------------------------------
# Asset lookup (from config.assets CIDRs)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1024)
def _asset_lookup_cached(ip: str, assets_key: str) -> str:
    """Look up an IP in the asset CIDR list.

    assets_key is a frozen repr of the assets list for cache invalidation.
    """
    # This is a placeholder; the real lookup is in asset_lookup()
    return ""


def asset_lookup(ip: str, cfg: Config) -> str:
    """Return asset name/role for an IP address from config.assets.

    Checks each AssetNetwork CIDR in order and returns the first match's
    name (or role if name is empty). Returns empty string if no match.
    """
    if not ip or not cfg.assets:
        return ""

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""

    for asset in cfg.assets:
        if not asset.cidr:
            continue
        try:
            network = ipaddress.ip_network(asset.cidr, strict=False)
            if addr in network:
                return asset.name or asset.role or asset.cidr
        except ValueError:
            continue

    return ""


# ---------------------------------------------------------------------------
# Main enrichment entry point
# ---------------------------------------------------------------------------

async def enrich(alert: Alert, cfg: Config) -> Alert:
    """Enrich an alert in-place with GeoIP, rDNS, asset names, and VirusTotal.

    GeoIP is only performed for non-private (public) IP addresses.
    rDNS lookups are performed concurrently for src and dst.
    Asset lookups are synchronous (in-memory).
    VirusTotal hash lookups run for Wazuh FIM alerts that contain file hashes.

    Returns the mutated Alert.
    """
    geoip_db = cfg.geoip.db_path

    # Run src + dst rDNS concurrently
    src_dns_task = asyncio.create_task(rdns_lookup(alert.src_ip))
    dst_dns_task = asyncio.create_task(rdns_lookup(alert.dst_ip))

    # GeoIP (synchronous but fast — mmdb is memory-mapped)
    if alert.src_ip and not is_private(alert.src_ip):
        alert.src_geo = geoip_lookup(alert.src_ip, geoip_db)

    if alert.dst_ip and not is_private(alert.dst_ip):
        alert.dst_geo = geoip_lookup(alert.dst_ip, geoip_db)

    # Asset names from config
    if alert.src_ip:
        alert.src_asset = asset_lookup(alert.src_ip, cfg)
    if alert.dst_ip:
        alert.dst_asset = asset_lookup(alert.dst_ip, cfg)

    # VirusTotal hash enrichment for Wazuh FIM alerts
    if cfg.virustotal.enabled and cfg.virustotal.api_key:
        vt_result = await virustotal_enrich(alert, cfg.virustotal.api_key)
        if vt_result:
            alert.description = f"{alert.description} | VT: {vt_result}"

    # Await rDNS results
    try:
        alert.src_dns = await src_dns_task
    except Exception:
        alert.src_dns = ""
    try:
        alert.dst_dns = await dst_dns_task
    except Exception:
        alert.dst_dns = ""

    return alert


# ---------------------------------------------------------------------------
# VirusTotal hash enrichment
# ---------------------------------------------------------------------------

_VT_API_URL = "https://www.virustotal.com/api/v3/files"

# Rate limiter: free tier = 4 requests/minute
_vt_last_requests: list[float] = []
_VT_RATE_LIMIT = 4
_VT_RATE_WINDOW = 60  # seconds

# Cache: hash → VT result string (avoids re-querying known hashes)
_vt_cache: dict[str, str] = {}
_VT_CACHE_MAX = 2000


def _extract_hash_from_alert(alert: Alert) -> str:
    """Extract a file hash from a Wazuh FIM alert.

    Looks for sha256:, sha1:, or md5: patterns in the description.
    Prefers SHA256 > SHA1 > MD5.
    """
    if alert.source != "wazuh":
        return ""

    desc = alert.description
    if "sha256:" not in desc and "sha1:" not in desc and "md5:" not in desc:
        return ""

    # Parse hash values from description
    import re
    for pattern in [r"sha256:([a-fA-F0-9]{64})", r"sha1:([a-fA-F0-9]{40})", r"md5:([a-fA-F0-9]{32})"]:
        m = re.search(pattern, desc)
        if m:
            return m.group(1)

    return ""


async def _vt_rate_check() -> bool:
    """Check if we're within VT rate limits. Returns True if OK to proceed."""
    import time
    now = time.monotonic()

    # Clean old entries
    while _vt_last_requests and now - _vt_last_requests[0] > _VT_RATE_WINDOW:
        _vt_last_requests.pop(0)

    if len(_vt_last_requests) >= _VT_RATE_LIMIT:
        return False

    _vt_last_requests.append(now)
    return True


async def virustotal_enrich(alert: Alert, api_key: str) -> str:
    """Look up file hash from a Wazuh FIM alert on VirusTotal.

    Returns a human-readable verdict string, or empty string if:
    - Alert has no hash
    - Rate limit exceeded
    - VT lookup failed
    - Hash not found on VT
    """
    file_hash = _extract_hash_from_alert(alert)
    if not file_hash:
        return ""

    # Check cache
    if file_hash in _vt_cache:
        return _vt_cache[file_hash]

    # Rate limit
    if not await _vt_rate_check():
        log.debug("VT rate limit reached, skipping hash %s", file_hash[:16])
        return ""

    try:
        import aiohttp
    except ImportError:
        return ""

    url = f"{_VT_API_URL}/{file_hash}"
    headers = {"x-apikey": api_key}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 404:
                    result = "not found on VT"
                elif resp.status == 200:
                    data = await resp.json()
                    result = _parse_vt_response(data, file_hash)
                elif resp.status == 429:
                    log.warning("VT rate limit hit (HTTP 429)")
                    return ""
                else:
                    log.debug("VT returned %d for hash %s", resp.status, file_hash[:16])
                    return ""
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        log.debug("VT lookup error: %s", e)
        return ""

    # Cache the result
    if len(_vt_cache) >= _VT_CACHE_MAX:
        # Evict oldest half
        keys = list(_vt_cache.keys())[:_VT_CACHE_MAX // 2]
        for k in keys:
            del _vt_cache[k]
    _vt_cache[file_hash] = result

    return result


# ---------------------------------------------------------------------------
# VirusTotal IP reputation lookup
# ---------------------------------------------------------------------------

_VT_IP_API_URL = "https://www.virustotal.com/api/v3/ip_addresses"


async def vt_ip_lookup(ip: str, api_key: str) -> dict:
    """Look up an IP address on VirusTotal.

    Returns a dict with vt_malicious, vt_suspicious, vt_total, country, isp,
    verdict, and details fields.
    """
    if not await _vt_rate_check():
        log.debug("VT rate limit reached, skipping IP %s", ip)
        return {}

    try:
        import aiohttp
    except ImportError:
        return {}

    url = f"{_VT_IP_API_URL}/{ip}"
    headers = {"x-apikey": api_key}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return _parse_vt_ip_response(data)
                elif resp.status == 429:
                    log.warning("VT rate limit hit (HTTP 429) for IP %s", ip)
                else:
                    log.debug("VT returned %d for IP %s", resp.status, ip)
    except Exception as e:
        log.debug("VT IP lookup error for %s: %s", ip, e)

    return {}


def _parse_vt_ip_response(data: dict) -> dict:
    """Parse VirusTotal IP address API response."""
    import json as _json

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected

    country = attrs.get("country", "")
    isp = attrs.get("as_owner", "")

    if malicious > 0:
        verdict = "malicious"
    elif suspicious > 0:
        verdict = "suspicious"
    elif total > 0:
        verdict = "clean"
    else:
        verdict = "unknown"

    return {
        "vt_malicious": malicious,
        "vt_suspicious": suspicious,
        "vt_total": total,
        "country": country,
        "isp": isp,
        "verdict": verdict,
        "details": _json.dumps({
            "stats": stats,
            "country": country,
            "as_owner": isp,
            "network": attrs.get("network", ""),
            "reputation": attrs.get("reputation", 0),
        }),
    }


# ---------------------------------------------------------------------------
# AbuseIPDB lookup
# ---------------------------------------------------------------------------

_ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"


async def abuseipdb_lookup(ip: str, api_key: str) -> dict:
    """Look up an IP address on AbuseIPDB.

    Returns a dict with abuse_score, country, isp, and details fields.
    """
    try:
        import aiohttp
    except ImportError:
        return {}

    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    params = {"ipAddress": ip, "maxAgeInDays": "90"}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                _ABUSEIPDB_API_URL,
                headers=headers,
                params=params,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return _parse_abuseipdb_response(data)
                elif resp.status == 429:
                    log.warning("AbuseIPDB rate limit hit for IP %s", ip)
                else:
                    log.debug("AbuseIPDB returned %d for IP %s", resp.status, ip)
    except Exception as e:
        log.debug("AbuseIPDB lookup error for %s: %s", ip, e)

    return {}


def _parse_abuseipdb_response(data: dict) -> dict:
    """Parse AbuseIPDB API response."""
    import json as _json

    d = data.get("data", {})
    score = d.get("abuseConfidenceScore", 0)
    country = d.get("countryCode", "")
    isp = d.get("isp", "")

    return {
        "abuse_score": score,
        "country": country,
        "isp": isp,
        "details": _json.dumps({
            "abuse_score": score,
            "total_reports": d.get("totalReports", 0),
            "num_distinct_users": d.get("numDistinctUsers", 0),
            "last_reported_at": d.get("lastReportedAt", ""),
            "usage_type": d.get("usageType", ""),
            "domain": d.get("domain", ""),
        }),
    }


# ---------------------------------------------------------------------------
# Shodan InternetDB (free, no API key, no rate limit documented)
# ---------------------------------------------------------------------------

_SHODAN_INTERNETDB_URL = "https://internetdb.shodan.io"


async def shodan_internetdb_lookup(ip: str) -> dict:
    """Look up an IP on Shodan's InternetDB (free, no API key needed).

    Returns dict with ports, vulns, hostnames, cpes, and tags.
    Returns empty dict on error or if IP not found.
    """
    try:
        import aiohttp
    except ImportError:
        return {}

    url = f"{_SHODAN_INTERNETDB_URL}/{ip}"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "ports": data.get("ports", []),
                        "vulns": data.get("vulns", []),
                        "hostnames": data.get("hostnames", []),
                        "cpes": data.get("cpes", []),
                        "tags": data.get("tags", []),
                    }
                elif resp.status == 404:
                    # IP not in Shodan's database
                    return {}
                else:
                    log.debug("Shodan InternetDB returned %d for IP %s", resp.status, ip)
    except Exception as e:
        log.debug("Shodan InternetDB lookup error for %s: %s", ip, e)

    return {}


# ---------------------------------------------------------------------------
# GreyNoise Community API (free tier: 50/day for community, no key = IP lookup)
# ---------------------------------------------------------------------------

_GREYNOISE_COMMUNITY_URL = "https://api.greynoise.io/v3/community"

# Budget tracking
_greynoise_daily_count = 0
_greynoise_day_start = None


async def greynoise_lookup(ip: str, api_key: str = "") -> dict:
    """Look up an IP on GreyNoise Community API.

    Free community tier: needs API key, 50 queries/day.
    Returns dict with classification, noise, riot, name, link.
    Classifications: "benign", "malicious", "unknown".
    """
    global _greynoise_daily_count, _greynoise_day_start
    from datetime import datetime, timezone

    try:
        import aiohttp
    except ImportError:
        return {}

    # Daily budget tracking
    today = datetime.now(timezone.utc).date()
    if _greynoise_day_start != today:
        _greynoise_daily_count = 0
        _greynoise_day_start = today

    if _greynoise_daily_count >= 50:
        log.debug("GreyNoise daily limit reached (50/day)")
        return {}

    url = f"{_GREYNOISE_COMMUNITY_URL}/{ip}"
    headers = {"Accept": "application/json"}
    if api_key:
        headers["key"] = api_key

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                _greynoise_daily_count += 1
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "classification": data.get("classification", "unknown"),
                        "noise": data.get("noise", False),
                        "riot": data.get("riot", False),
                        "name": data.get("name", ""),
                        "link": data.get("link", ""),
                        "last_seen": data.get("last_seen", ""),
                        "message": data.get("message", ""),
                    }
                elif resp.status == 404:
                    return {"classification": "unknown", "noise": False, "riot": False}
                else:
                    log.debug("GreyNoise returned %d for IP %s", resp.status, ip)
    except Exception as e:
        log.debug("GreyNoise lookup error for %s: %s", ip, e)

    return {}


def _parse_vt_response(data: dict, file_hash: str) -> str:
    """Parse VirusTotal API v3 response into a human-readable string."""
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + undetected

    if total == 0:
        return "no scan results"

    if malicious == 0 and suspicious == 0:
        return f"clean ({total} engines)"

    # Include some detection names for context
    results = attrs.get("last_analysis_results", {})
    detections = []
    for engine, result in results.items():
        if result.get("category") == "malicious" and result.get("result"):
            detections.append(f"{engine}: {result['result']}")
            if len(detections) >= 3:
                break

    verdict = f"{malicious}/{total} malicious"
    if suspicious:
        verdict += f", {suspicious} suspicious"
    if detections:
        verdict += f" [{'; '.join(detections)}]"

    return verdict
