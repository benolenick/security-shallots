"""pfSense integration: filterlog parser + optional API poller."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shallots.config import PfSenseConfig, SyslogConfig

from shallots.store.models import Alert, AlertSource, now_iso

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Filterlog CSV parser
#
# pfSense filterlog format (space/CSV-separated, varies by IP version):
#
# Common prefix fields (indices 0-6):
#   0  rule_number
#   1  sub_rule_number
#   2  anchor
#   3  tracker
#   4  interface
#   5  reason
#   6  action        (pass/block/reject)
#   7  direction     (in/out)
#   8  ip_version    (4/6)
#
# IPv4 fields continue from index 9:
#   9  tos
#   10 ecn
#   11 ttl
#   12 id
#   13 offset
#   14 flags
#   15 proto_id
#   16 proto_text    (tcp/udp/icmp/...)
#   17 length
#   18 src_ip
#   19 dst_ip
#   20 src_port      (TCP/UDP only)
#   21 dst_port      (TCP/UDP only)
#   ...
#
# IPv6 fields continue from index 9:
#   9  class
#   10 flow_label
#   11 hop_limit
#   12 proto_text
#   13 proto_id
#   14 length
#   15 src_ip
#   16 dst_ip
#   17 src_port      (TCP/UDP only)
#   18 dst_port      (TCP/UDP only)
# ---------------------------------------------------------------------------

_BLOCKED_ACTIONS = {"block", "reject"}
_PORT_PROTOS = {"tcp", "udp"}


def parse_filterlog(line: str) -> Alert | None:
    """Parse a pfSense filterlog CSV line into an Alert.

    Returns None for non-blocked traffic or unparseable lines.
    The `line` argument should be just the CSV payload after the syslog
    header has been stripped (i.e., everything after "filterlog: ").
    """
    # Strip any leading/trailing whitespace
    line = line.strip()

    # If the caller passed the full syslog message, extract the CSV portion
    if "filterlog:" in line:
        idx = line.index("filterlog:")
        line = line[idx + len("filterlog:"):].strip()

    parts = line.split(",")

    if len(parts) < 9:
        log.debug("filterlog: too few fields (%d): %s", len(parts), line[:80])
        return None

    try:
        action = parts[6].lower()
        direction = parts[7].lower()
        ip_version = parts[8].strip()
    except IndexError:
        return None

    # Only create alerts for blocked/rejected traffic
    if action not in _BLOCKED_ACTIONS:
        return None

    src_ip = ""
    dst_ip = ""
    src_port = 0
    dst_port = 0
    proto = ""

    try:
        if ip_version == "4":
            # IPv4 layout
            if len(parts) < 20:
                return None
            proto = parts[16].lower()
            src_ip = parts[18]
            dst_ip = parts[19]
            if proto in _PORT_PROTOS and len(parts) > 21:
                src_port = int(parts[20])
                dst_port = int(parts[21])
        elif ip_version == "6":
            # IPv6 layout
            if len(parts) < 17:
                return None
            proto = parts[12].lower()
            src_ip = parts[15]
            dst_ip = parts[16]
            if proto in _PORT_PROTOS and len(parts) > 18:
                src_port = int(parts[17])
                dst_port = int(parts[18])
        else:
            log.debug("filterlog: unknown ip_version: %s", ip_version)
            return None
    except (IndexError, ValueError) as e:
        log.debug("filterlog: parse error (%s): %s", e, line[:120])
        return None

    rule_num = parts[0]
    interface = parts[4] if len(parts) > 4 else ""
    reason = parts[5] if len(parts) > 5 else ""

    title = (
        f"pfSense {action.upper()} {proto.upper()} "
        f"{src_ip}:{src_port} → {dst_ip}:{dst_port}"
    )
    description = (
        f"pfSense filterlog: action={action} direction={direction} "
        f"interface={interface} reason={reason} rule={rule_num} "
        f"ipv{ip_version} {proto} {src_ip}:{src_port} → {dst_ip}:{dst_port}"
    )

    return Alert(
        timestamp=now_iso(),
        source=AlertSource.PFSENSE,
        source_ref=f"pfsense-rule-{rule_num}",
        severity="low",   # Firewall blocks are informational by default;
                          # the classifier can escalate based on context.
        title=title,
        description=description,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        proto=proto.upper(),
        category="firewall/block",
        signature_id=0,
        raw=line,
    )


# ---------------------------------------------------------------------------
# Optional pfSense API poller (asset enrichment)
# ---------------------------------------------------------------------------

DHCP_POLL_INTERVAL = 300  # seconds


async def poll_pfsense_assets(
    config: PfSenseConfig,
) -> dict[str, dict[str, str]]:
    """Poll pfSense API for DHCP leases.

    Returns a dict mapping IP address → {hostname, mac, interface}.
    Requires the pfsense-api package installed on the pfSense box.

    GET /api/v1/services/dhcpd/leases
    """
    try:
        import aiohttp
    except ImportError:
        log.warning("aiohttp not available — skipping pfSense asset poll")
        return {}

    url = f"{config.api_url.rstrip('/')}/api/v1/services/dhcpd/leases"
    headers = {
        "Authorization": f"{config.api_key} {config.api_secret}",
        "Content-Type": "application/json",
    }

    assets: dict[str, dict[str, str]] = {}

    try:
        connector = aiohttp.TCPConnector(ssl=config.verify_ssl)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(
                url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)
            ) as resp:
                if resp.status != 200:
                    log.warning("pfSense API returned %d for DHCP leases", resp.status)
                    return {}
                data = await resp.json()

                leases = data.get("data", [])
                for lease in leases:
                    ip = lease.get("ip", "")
                    if not ip:
                        continue
                    assets[ip] = {
                        "hostname": lease.get("hostname", ""),
                        "mac": lease.get("mac", ""),
                        "interface": lease.get("if", ""),
                        "type": lease.get("type", ""),
                    }

                log.debug("pfSense: loaded %d DHCP leases", len(assets))
    except aiohttp.ClientConnectorError:
        log.warning("Cannot connect to pfSense API at %s", config.api_url)
    except Exception:
        log.exception("Error polling pfSense DHCP leases")

    return assets


# ---------------------------------------------------------------------------
# PfSenseIngestor: combines filterlog (via syslog queue) + API polling
# ---------------------------------------------------------------------------

class PfSenseIngestor:
    """Consumes pfSense filterlog lines routed by SyslogReceiver.

    If pfSense API is configured, also polls periodically for DHCP leases
    to provide an asset map for enrichment.

    The syslog_queue must be the same pfsense_queue that SyslogReceiver
    is configured with. If not using SyslogReceiver, pass None and this
    ingestor will only do API polling.
    """

    def __init__(
        self,
        config: PfSenseConfig,
        syslog_config: SyslogConfig,
        queue: asyncio.Queue,
        pfsense_queue: asyncio.Queue | None = None,
    ):
        self.config = config
        self.syslog_config = syslog_config
        self.queue = queue          # destination: normalized alert queue
        self.pfsense_queue = pfsense_queue  # source: filterlog lines from syslog
        self.assets: dict[str, dict[str, str]] = {}

    async def run(self) -> None:
        """Start filterlog consumer and optional API poller."""
        log.info("pfSense ingestor started (api=%s)", bool(self.config.api_url))

        tasks: list[asyncio.Task] = []

        if self.pfsense_queue is not None:
            tasks.append(asyncio.create_task(self._consume_filterlog()))

        if self.config.api_url:
            tasks.append(asyncio.create_task(self._poll_assets_loop()))

        if not tasks:
            log.warning(
                "pfSense ingestor: no syslog queue and no API URL configured; "
                "nothing to do"
            )
            return

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for t in tasks:
                t.cancel()

    async def _consume_filterlog(self) -> None:
        """Consume filterlog entries from the syslog pfsense_queue."""
        assert self.pfsense_queue is not None
        while True:
            try:
                item = await self.pfsense_queue.get()
                # item = (message, src_addr, parsed_syslog)
                message, _src_addr, _parsed = item
                alert = parse_filterlog(message)
                if alert:
                    await self.queue.put(alert)
            except asyncio.CancelledError:
                return
            except Exception:
                log.exception("pfSense filterlog consumer error")

    async def _poll_assets_loop(self) -> None:
        """Periodically refresh the pfSense DHCP lease table."""
        while True:
            try:
                self.assets = await poll_pfsense_assets(self.config)
            except asyncio.CancelledError:
                return
            except Exception:
                log.exception("pfSense asset poll error")
            await asyncio.sleep(DHCP_POLL_INTERVAL)

    def get_asset_name(self, ip: str) -> str:
        """Look up hostname for an IP from the DHCP table."""
        entry = self.assets.get(ip, {})
        return entry.get("hostname", "")
