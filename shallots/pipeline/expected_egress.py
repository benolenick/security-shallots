"""Expected-egress allowlist.

Marks hosts whose heavy OUTBOUND internet activity is legitimate and expected -
scrapers, crawlers, backup jobs, or proxied automation you run on purpose.
Their outbound-network alerts are auto-suppressed so they don't false-trigger the
beacon detector, IoC destination-matches, or burn reputation-API quota on the
thousands of sites they hit.

IMPORTANT: this only touches OUTBOUND-NETWORK categories (default: network_egress).
Host-level events on the same host - persistence changes, logins, file-integrity,
anti-tamper - are NOT affected, so a genuine compromise of a scraper box still alerts.
"""
from __future__ import annotations

import ipaddress


def _networks(cidrs):
    nets = []
    for c in cidrs or []:
        try:
            nets.append(ipaddress.ip_network(str(c), strict=False))
        except ValueError:
            pass
    return nets


def is_expected_egress(alert, cfg) -> bool:
    """True when this alert is expected outbound activity from an allowlisted host.

    `cfg` is the ExpectedEgressConfig (enabled, hosts, src_ips, proxy_cidrs, categories).
    """
    if not getattr(cfg, "enabled", False):
        return False

    cat = (getattr(alert, "category", "") or "").strip().lower()
    allowed_cats = {c.strip().lower() for c in (getattr(cfg, "categories", None) or ["network_egress"])}
    if cat not in allowed_cats:
        return False

    src_asset = (getattr(alert, "src_asset", "") or "").strip().lower()
    if src_asset and src_asset in {h.strip().lower() for h in (getattr(cfg, "hosts", None) or [])}:
        return True

    src_ip = (getattr(alert, "src_ip", "") or "").strip()
    if src_ip and src_ip in set(getattr(cfg, "src_ips", None) or []):
        return True

    if src_ip and getattr(cfg, "proxy_cidrs", None):
        try:
            addr = ipaddress.ip_address(src_ip)
            for net in _networks(cfg.proxy_cidrs):
                if addr in net:
                    return True
        except ValueError:
            pass

    return False
