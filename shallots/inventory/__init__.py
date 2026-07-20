"""Device census / network inventory for Security Shallots.

Phase 1 of the privileged-access (crown-jewel) architecture: a standing,
DHCP-proof map of what devices exist on the network and where each sits in the
privilege hierarchy. The credential broker (later phase) consults this registry
to know which devices it can grant access to and at what tier.
"""

from shallots.inventory.discovery import Device, scan_network
from shallots.inventory.oui import OUILookup
from shallots.inventory.registry import (
    TIERS,
    TierPolicy,
    ensure_tables,
    list_devices,
    tier_rank,
    upsert_scan,
)

__all__ = [
    "Device",
    "scan_network",
    "OUILookup",
    "TIERS",
    "TierPolicy",
    "ensure_tables",
    "list_devices",
    "tier_rank",
    "upsert_scan",
]
