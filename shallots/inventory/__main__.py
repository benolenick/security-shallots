"""Standalone CLI for the device census - `python -m shallots.inventory ...`.

Kept independent of the main `shallot` CLI/daemon for Phase 1 so it can be
proven on the LAN without touching the live control plane. Wiring into
`shallot inventory` + the daemon loop comes after review.

    python -m shallots.inventory scan          # discover + persist + show changes
    python -m shallots.inventory list          # show current registry by tier
    python -m shallots.inventory history        # recent change events
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import sqlite3
import subprocess
import sys
from pathlib import Path

from shallots.inventory.discovery import scan_network
from shallots.inventory.oui import OUILookup
from shallots.inventory.registry import (
    TIERS,
    TierPolicy,
    list_devices,
    upsert_scan,
)

_DEFAULT_DB = "inventory.db"
_DEFAULT_SEED = "data/inventory_seed.yaml"

_TIER_GLYPH = {
    "crown": "\033[95m♛\033[0m", "vault": "\033[93m⛨\033[0m",
    "core": "\033[96m◆\033[0m", "daily": "\033[92m●\033[0m",
    "iot": "\033[90m·\033[0m", "guest": "\033[90m○\033[0m",
    "unknown": "\033[91m?\033[0m",
}


def _self_ip_mac_cidr() -> tuple[str | None, str | None, str | None]:
    """Best-effort local IP, MAC, and /24 CIDR for the primary interface."""
    ip = mac = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.168.0.1", 9))  # no packets actually sent
        ip = s.getsockname()[0]
        s.close()
    except OSError:
        pass
    iface = None
    try:
        route = subprocess.run(
            ["ip", "-o", "route", "get", "192.168.0.1"],
            capture_output=True, text=True, timeout=3,
        ).stdout.split()
        if "dev" in route:
            iface = route[route.index("dev") + 1]
    except (subprocess.SubprocessError, OSError, ValueError):
        pass
    if iface:
        try:
            mac = Path(f"/sys/class/net/{iface}/address").read_text().strip()
        except OSError:
            pass
    cidr = None
    if ip:
        cidr = str(ipaddress.ip_network(f"{ip}/24", strict=False))
    return ip, mac, cidr


def _open_db(path: str) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(path)


def cmd_scan(args) -> int:
    ip, mac, auto_cidr = _self_ip_mac_cidr()
    cidr = args.cidr or auto_cidr
    if not cidr:
        print("Could not determine local network; pass --cidr 192.168.0.0/24",
              file=sys.stderr)
        return 2
    print(f"Scanning {cidr} (self={ip})…", file=sys.stderr)
    policy = TierPolicy.load(args.seed)
    oui = OUILookup()
    try:
        devices = scan_network(cidr, oui_lookup=oui, self_ip=ip, self_mac=mac,
                               port_timeout=args.timeout)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    conn = _open_db(args.db)
    events = upsert_scan(conn, devices, policy)
    conn.close()

    print(f"\nFound {len(devices)} live device(s).\n")
    _print_table(list_devices(_reopen(args.db)))

    if events:
        print(f"\n\033[1m{len(events)} change event(s) this scan:\033[0m")
        for e in events:
            tag = e["event"].upper().replace("_", " ")
            print(f"  [{tag}] {e.get('detail','')}")
    else:
        print("\nNo changes since last scan.")
    return 0


def _reopen(path: str) -> sqlite3.Connection:
    return sqlite3.connect(path)


def _print_table(rows: list[dict]) -> None:
    if not rows:
        print("(registry empty)")
        return
    print(f"{'':2} {'TIER':7} {'IP':15} {'HOSTNAME':22} {'OS':10} "
          f"{'VENDOR':22} PORTS")
    print("─" * 100)
    cur = None
    for d in rows:
        if d["tier"] != cur:
            cur = d["tier"]
        g = _TIER_GLYPH.get(d["tier"], " ")
        ports = ",".join(str(p) for p in d["open_ports"][:8])
        name = d["hostname"] or d["role"] or "-"
        print(f"{g:2} {d['tier']:7} {d['ip'] or '-':15} {name[:22]:22} "
              f"{d['os_guess'][:10]:10} {(d['vendor'] or '-')[:22]:22} {ports}")


def cmd_list(args) -> int:
    _print_table(list_devices(_open_db(args.db)))
    return 0


def cmd_history(args) -> int:
    conn = _open_db(args.db)
    try:
        rows = conn.execute(
            "SELECT ts, event, device_key, detail FROM device_history "
            "ORDER BY id DESC LIMIT ?", (args.limit,)
        ).fetchall()
    except sqlite3.OperationalError:
        rows = []
    conn.close()
    if not rows:
        print("(no history yet)")
        return 0
    for ts, event, key, detail in rows:
        print(f"{ts}  [{event}]  {key}  {detail or ''}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="shallot-inventory",
                                description="Shallots device census")
    p.add_argument("--db", default=_DEFAULT_DB, help="registry sqlite path")
    p.add_argument("--seed", default=_DEFAULT_SEED, help="tier seed yaml")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", help="discover + persist + show changes")
    sp.add_argument("--cidr", help="override network (default: local /24)")
    sp.add_argument("--timeout", type=float, default=0.6, help="per-port timeout s")
    sp.set_defaults(func=cmd_scan)

    lp = sub.add_parser("list", help="show current registry by tier")
    lp.set_defaults(func=cmd_list)

    hp = sub.add_parser("history", help="recent change events")
    hp.add_argument("--limit", type=int, default=30)
    hp.set_defaults(func=cmd_history)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
