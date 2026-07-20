#!/usr/bin/env python3
"""Security Shallots - new-device watcher.

Discovery already runs (shallot-inventory-scan -> data/inventory.db, rich
per-device records keyed by MAC). What was missing: turning a NEWLY-seen MAC
into an alert. `known_devices` in shallots.db + AlertDB.check_and_register_device
existed but had no caller, so new devices joining the LAN were never flagged.

This closes that loop:
  * first run  -> seed every currently-known MAC as baseline (alert_generated=1),
                  emit NOTHING (avoids a burst on first execution),
  * later runs -> any MAC not in known_devices is inserted AND a `pending`
                  alert is written to shallots.db (source_ref=device-watch,
                  category=new-device) so it flows through the normal
                  classify -> triage -> cluster -> incident pipeline.

Idempotent: dedup_hash = "new-device:<mac>" so re-runs never duplicate.
Run by shallot-device-watch.timer (every 30 min). Read-only on inventory.db.
"""
from __future__ import annotations

import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SHALLOTS_DB = ROOT / "shallots.db"
INVENTORY_DB = ROOT / "data" / "inventory.db"

# MACs that are the fleet's own infra should never be treated as "new".
# (They are already in the inventory seed; baseline seeding covers them, but
# this is a belt-and-suspenders guard for the very first run.)
IGNORE_MACS = {"00:00:00:00:00:00"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_inventory() -> dict[str, dict]:
    """Return {mac: device_row} from the inventory census (read-only)."""
    if not INVENTORY_DB.exists():
        return {}
    con = sqlite3.connect(f"file:{INVENTORY_DB}?mode=ro", uri=True, timeout=5)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute("SELECT * FROM devices").fetchall()
    except sqlite3.Error:
        return {}
    finally:
        con.close()
    out: dict[str, dict] = {}
    for r in rows:
        d = dict(r)
        mac = (d.get("mac") or "").lower().strip()
        if mac and mac not in IGNORE_MACS:
            out[mac] = d
    return out


def emit_new_device_alert(con: sqlite3.Connection, dev: dict) -> None:
    mac = (dev.get("mac") or "").lower()
    ip = dev.get("ip") or ""
    hostname = dev.get("hostname") or ""
    vendor = (dev.get("vendor") or "unknown vendor").replace("(base 16)", "").strip() or "unknown vendor"
    ports = dev.get("open_ports") or "[]"
    services = dev.get("services") or "[]"
    title = f"New device on network: {ip} ({vendor})"
    desc = (
        f"A previously-unseen device joined the LAN. MAC={mac} IP={ip} "
        f"hostname={hostname or 'n/a'} vendor={vendor} open_ports={ports} services={services}. "
        f"If this is not a device you added, investigate immediately."
    )
    con.execute(
        """INSERT OR IGNORE INTO alerts
           (id, timestamp, source, source_ref, severity, title, description,
            src_ip, category, verdict, confidence, ai_reasoning,
            ingested_at, dedup_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            str(uuid.uuid4()), now_iso(), "device-watch", "device-watch",
            "medium", title, desc, ip, "new-device", "pending", 0.0, "",
            now_iso(), f"new-device:{mac}",
        ),
    )


def main() -> int:
    if not SHALLOTS_DB.exists():
        print("shallots.db missing", file=sys.stderr)
        return 1
    devices = read_inventory()
    if not devices:
        print("no inventory devices (census not run yet?)")
        return 0

    con = sqlite3.connect(SHALLOTS_DB, timeout=10)
    con.execute("PRAGMA busy_timeout=8000")
    con.row_factory = sqlite3.Row

    known = {r["mac"].lower() for r in con.execute("SELECT mac FROM known_devices").fetchall() if r["mac"]}
    first_run = len(known) == 0
    now = now_iso()

    new_macs: list[str] = []
    for mac, dev in devices.items():
        if mac in known:
            con.execute(
                "UPDATE known_devices SET last_seen=?, ip=?, hostname=? WHERE mac=?",
                (now, dev.get("ip") or "", dev.get("hostname") or "", mac),
            )
            continue
        # brand-new MAC
        con.execute(
            "INSERT OR IGNORE INTO known_devices (mac, ip, hostname, first_seen, last_seen, alert_generated) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (mac, dev.get("ip") or "", dev.get("hostname") or "", now, now, 1 if first_run else 0),
        )
        if not first_run:
            emit_new_device_alert(con, dev)
            con.execute("UPDATE known_devices SET alert_generated=1 WHERE mac=?", (mac,))
            new_macs.append(mac)

    con.commit()
    con.close()

    if first_run:
        print(f"baseline seeded: {len(devices)} devices recorded, no alerts (first run)")
    elif new_macs:
        print(f"NEW devices flagged ({len(new_macs)}): {', '.join(new_macs)} -> alerts queued")
    else:
        print(f"no new devices ({len(devices)} known)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
