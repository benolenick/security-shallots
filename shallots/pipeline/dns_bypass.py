"""DNS-bypass detection.

Flags an internal host doing DNS straight to a PUBLIC resolver (port 53/853)
instead of the network Pi-hole. That's either a misconfigured device or malware
deliberately evading the DNS sinkhole/logging - both worth a squawk.

Excludes the Pi-hole host itself (its upstream forwards to Cloudflare/Google are
normal) and DNS to any private/internal address (that's the Pi-hole or a local
resolver, which is fine).

Note: this catches classic UDP/TCP 53 (and DoT 853) bypass. DNS-over-HTTPS (DoH,
port 443 to a DoH provider) is a separate vector not covered here.
"""
from __future__ import annotations

_DNS_PORTS = {53, 853}


def is_dns_bypass(alert, pihole_host_ip: str, is_private) -> bool:
    """True when an internal host (not the Pi-hole box) queries an external DNS resolver."""
    try:
        dport = int(getattr(alert, "dst_port", 0) or 0)
    except (TypeError, ValueError):
        dport = 0
    if dport not in _DNS_PORTS:
        return False

    src = (getattr(alert, "src_ip", "") or "").strip()
    dst = (getattr(alert, "dst_ip", "") or "").strip()
    if not src or not dst:
        return False

    # The Pi-hole host's own upstream forwards to public resolvers are normal.
    if pihole_host_ip and src == pihole_host_ip:
        return False

    try:
        # Only our own internal hosts count; DNS to an internal address (the
        # Pi-hole / a local resolver) is exactly what we want, not a bypass.
        if not is_private(src):
            return False
        if is_private(dst):
            return False
    except Exception:
        return False

    return True
