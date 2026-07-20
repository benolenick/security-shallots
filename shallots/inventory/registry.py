"""Device registry: persistence, privilege-tier classification, and diffing.

Self-contained sqlite (mirrors the agent_watchdog table pattern) so this never
touches the async AlertDB schema or the live daemon. The registry is the
foundation the privileged-access broker will consult: every device carries a
`tier` that ranks its position in the trust hierarchy.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from shallots.inventory.discovery import Device

# Privilege hierarchy, most-privileged first. `crown` = approval authority
# (the device that says yes); `vault` = credential authority (mints secrets);
# `core` = fleet infrastructure; `daily` = personal daily-use; `iot` =
# appliances; `guest` = transient-but-known; `unknown` = needs a human look.
TIERS = ["crown", "vault", "core", "daily", "iot", "guest", "unknown"]
_TIER_RANK = {t: i for i, t in enumerate(TIERS)}


REGISTRY_DDL = """
CREATE TABLE IF NOT EXISTS devices (
    device_key   TEXT PRIMARY KEY,        -- MAC (or ip:<addr> fallback)
    ip           TEXT,
    mac          TEXT,
    vendor       TEXT,
    hostname     TEXT,
    os_guess     TEXT,
    open_ports   TEXT,                     -- json list
    services     TEXT,                     -- json list
    tier         TEXT NOT NULL DEFAULT 'unknown',
    role         TEXT,                     -- human label e.g. 'wife-mac / approval crown'
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    times_seen   INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS device_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    device_key   TEXT NOT NULL,
    event        TEXT NOT NULL,            -- new_device | departed | ip_changed | ports_changed | os_changed
    detail       TEXT
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(REGISTRY_DDL)
    conn.commit()


class TierPolicy:
    """Assigns a privilege tier + role label to a device.

    Seed file (YAML) is keyed by stable identity and is intentionally
    MAC-first so DHCP churn never reclassifies a known device. Shape:

        devices:
          "aa:bb:cc:11:22:33": {tier: crown, role: "primary workstation / approval authority"}
          "aa:bb:cc:44:55:66": {tier: vault, role: "server / credential authority"}
        rules:                      # ordered fallbacks when MAC is unseeded
          - {match: {os_guess: printer}, tier: iot}
          - {match: {vendor_contains: amazon}, tier: iot}
    """

    def __init__(self, seed: dict | None = None) -> None:
        seed = seed or {}
        self._by_mac = {
            k.lower(): v for k, v in (seed.get("devices") or {}).items()
        }
        self._rules = seed.get("rules") or []

    @classmethod
    def load(cls, path: str | Path) -> "TierPolicy":
        p = Path(path)
        if not p.exists():
            return cls({})
        import yaml

        with open(p) as fh:
            return cls(yaml.safe_load(fh) or {})

    def classify(self, dev: Device) -> tuple[str, str | None]:
        # 1) Exact MAC seed - the authoritative, DHCP-proof path.
        if dev.mac:
            hit = self._by_mac.get(dev.mac.lower())
            if hit:
                return hit.get("tier", "unknown"), hit.get("role")
        # 2) Ordered heuristic rules.
        for rule in self._rules:
            m = rule.get("match", {})
            if self._matches(dev, m):
                return rule.get("tier", "unknown"), rule.get("role")
        return "unknown", None

    @staticmethod
    def _matches(dev: Device, m: dict) -> bool:
        if "os_guess" in m and dev.os_guess != m["os_guess"]:
            return False
        if "vendor_contains" in m and m["vendor_contains"].lower() not in (
            dev.vendor or ""
        ).lower():
            return False
        if "hostname_contains" in m and m["hostname_contains"].lower() not in (
            dev.hostname or ""
        ).lower():
            return False
        return True


def tier_rank(tier: str) -> int:
    return _TIER_RANK.get(tier, len(TIERS))


def upsert_scan(
    conn: sqlite3.Connection, devices: list[Device], policy: TierPolicy
) -> list[dict]:
    """Persist a scan; return a list of change events since the prior state."""
    ensure_tables(conn)
    now = _now()
    events: list[dict] = []
    seen_now = set()

    for dev in devices:
        key = dev.key()
        seen_now.add(key)
        tier, role = policy.classify(dev)
        ports_json = json.dumps(dev.open_ports)
        svc_json = json.dumps(dev.services)

        row = conn.execute(
            "SELECT ip, open_ports, os_guess, times_seen FROM devices WHERE device_key=?",
            (key,),
        ).fetchone()

        if row is None:
            conn.execute(
                """INSERT INTO devices (device_key, ip, mac, vendor, hostname,
                       os_guess, open_ports, services, tier, role,
                       first_seen, last_seen, times_seen)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                (key, dev.ip, dev.mac, dev.vendor, dev.hostname, dev.os_guess,
                 ports_json, svc_json, tier, role, now, now),
            )
            ev = {
                "event": "new_device", "device_key": key, "ip": dev.ip,
                "tier": tier, "role": role, "hostname": dev.hostname,
                "vendor": dev.vendor, "os_guess": dev.os_guess,
                "detail": f"{dev.hostname or dev.ip} ({dev.vendor or 'unknown vendor'}, "
                          f"{dev.os_guess}) tier={tier}",
            }
            events.append(ev)
            _log(conn, now, key, "new_device", ev["detail"])
        else:
            old_ip, old_ports, old_os, _ = row
            if old_ip != dev.ip:
                d = f"{old_ip} -> {dev.ip}"
                events.append({"event": "ip_changed", "device_key": key,
                               "tier": tier, "detail": d})
                _log(conn, now, key, "ip_changed", d)
            if old_ports != ports_json:
                d = f"{json.loads(old_ports or '[]')} -> {dev.open_ports}"
                events.append({"event": "ports_changed", "device_key": key,
                               "tier": tier, "detail": d})
                _log(conn, now, key, "ports_changed", d)
            if old_os != dev.os_guess and dev.os_guess != "unknown":
                d = f"{old_os} -> {dev.os_guess}"
                events.append({"event": "os_changed", "device_key": key,
                               "tier": tier, "detail": d})
                _log(conn, now, key, "os_changed", d)
            conn.execute(
                """UPDATE devices SET ip=?, mac=COALESCE(?,mac), vendor=COALESCE(?,vendor),
                       hostname=COALESCE(?,hostname), os_guess=?, open_ports=?, services=?,
                       tier=?, role=?, last_seen=?, times_seen=times_seen+1
                   WHERE device_key=?""",
                (dev.ip, dev.mac, dev.vendor, dev.hostname, dev.os_guess, ports_json,
                 svc_json, tier, role, now, key),
            )

    conn.commit()
    return events


def _log(conn: sqlite3.Connection, ts: str, key: str, event: str, detail: str) -> None:
    conn.execute(
        "INSERT INTO device_history (ts, device_key, event, detail) VALUES (?,?,?,?)",
        (ts, key, event, detail),
    )


def list_devices(conn: sqlite3.Connection) -> list[dict]:
    ensure_tables(conn)
    cols = ["device_key", "ip", "mac", "vendor", "hostname", "os_guess",
            "open_ports", "services", "tier", "role", "first_seen",
            "last_seen", "times_seen"]
    rows = conn.execute(f"SELECT {','.join(cols)} FROM devices").fetchall()
    out = [dict(zip(cols, r)) for r in rows]
    for d in out:
        d["open_ports"] = json.loads(d["open_ports"] or "[]")
        d["services"] = json.loads(d["services"] or "[]")
    out.sort(key=lambda d: (tier_rank(d["tier"]),
                            tuple(int(x) for x in d["ip"].split(".")) if d["ip"] else ()))
    return out
