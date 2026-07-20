"""MAC OUI -> vendor lookup.

Prefers a system IEEE/nmap database if one is installed; otherwise falls back
to a tiny built-in map covering the fleet's own hardware so a bare box still
produces useful vendor labels.
"""

from __future__ import annotations

import os

_SYSTEM_DB_PATHS = [
    "/usr/share/nmap/nmap-mac-prefixes",
    "/var/lib/ieee-data/oui.txt",
    "/usr/share/ieee-data/oui.txt",
    "/usr/share/arp-scan/ieee-oui.txt",
]

# Minimal fallback keyed by the first 3 MAC octets (uppercase, no separators).
_BUILTIN = {
    "C8787D": "Sagemcom (router)",
    "708BCD": "ASUSTek",
    "1402EC": "Hewlett Packard Enterprise",
    "60EB69": "ASRock",
    "F82819": "Dell",
    "14205E": "Apple/Intel-NIC",
    "BC1665": "Amazon Technologies",
    "7898E8": "Apple",
}


def _norm(mac: str) -> str:
    return mac.replace(":", "").replace("-", "").replace(".", "").upper()


def _load_system_db() -> dict[str, str]:
    table: dict[str, str] = {}
    for path in _SYSTEM_DB_PATHS:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # nmap format: "0000EC  Wyse Technology"
                    parts = line.split(None, 1)
                    if len(parts) == 2 and len(_norm(parts[0])) == 6:
                        table[_norm(parts[0])] = parts[1].strip()
                    # IEEE oui.txt format: "00-00-EC   (hex)   Wyse"
                    elif "(hex)" in line:
                        pfx = _norm(line.split()[0])
                        name = line.split("(hex)")[-1].strip()
                        if len(pfx) == 6 and name:
                            table[pfx] = name
        except OSError:
            continue
        if table:
            break
    return table


class OUILookup:
    def __init__(self) -> None:
        self._sys = _load_system_db()

    def __call__(self, mac: str | None) -> str | None:
        if not mac:
            return None
        pfx = _norm(mac)[:6]
        if len(pfx) < 6:
            return None
        return self._sys.get(pfx) or _BUILTIN.get(pfx)
