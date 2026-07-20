from __future__ import annotations

import asyncio
import json
import os
import subprocess
from dataclasses import dataclass

from .types import ThreatSignal

_PS_QUERY = (
    "$f=Get-WMIObject -Namespace root/subscription -Class __EventFilter "
    "-ErrorAction SilentlyContinue|Select Name,Query;"
    "$c=Get-WMIObject -Namespace root/subscription -Class __EventConsumer "
    "-ErrorAction SilentlyContinue|Select Name,__CLASS;"
    "$b=Get-WMIObject -Namespace root/subscription -Class __FilterToConsumerBinding "
    "-ErrorAction SilentlyContinue|Select Filter,Consumer;"
    "@{Filters=$f;Consumers=$c;Bindings=$b}|ConvertTo-Json -Compress -Depth 3"
)


@dataclass(slots=True)
class WmiSubsConfig:
    enabled: bool = True
    poll_seconds: int = 120


class WmiSubsMonitor:
    def __init__(self, cfg: WmiSubsConfig) -> None:
        self.cfg = cfg
        self._known_filters: set[str] = set()
        self._known_consumers: set[str] = set()
        self._known_bindings: set[str] = set()
        self._primed = False

    async def start(self, queue: asyncio.Queue[ThreatSignal]) -> None:
        while True:
            for signal in self._poll_once():
                await queue.put(signal)
            await asyncio.sleep(max(30, int(self.cfg.poll_seconds)))

    def _poll_once(self) -> list[ThreatSignal]:
        if os.name != "nt":
            return self._poll_once_linux()

        data = self._query_wmi()
        filters = data.get("filters", [])
        consumers = data.get("consumers", [])
        bindings = data.get("bindings", [])
        out: list[ThreatSignal] = []

        if not self._primed:
            self._known_filters = {f["name"] for f in filters}
            self._known_consumers = {c["name"] for c in consumers}
            self._known_bindings = {b["key"] for b in bindings}
            self._primed = True
            return out

        for f in filters:
            if f["name"] in self._known_filters:
                continue
            self._known_filters.add(f["name"])
            out.append(
                ThreatSignal(
                    event_type="wmi_persistence",
                    title="New WMI event filter detected (T1546.003)",
                    description=(
                        f"A new WMI __EventFilter was found: {f['name']!r}. "
                        "WMI subscriptions are a common APT persistence mechanism."
                    ),
                    severity="critical",
                    confidence=0.95,
                    category="persistence",
                    details={
                        "type": "filter",
                        "name": f["name"],
                        "query": f.get("query", ""),
                    },
                    raw=f,
                )
            )

        for c in consumers:
            if c["name"] in self._known_consumers:
                continue
            self._known_consumers.add(c["name"])
            out.append(
                ThreatSignal(
                    event_type="wmi_persistence",
                    title="New WMI event consumer detected (T1546.003)",
                    description=(
                        f"A new WMI __EventConsumer was found: {c['name']!r} "
                        f"(class: {c.get('cls', '')})."
                    ),
                    severity="critical",
                    confidence=0.95,
                    category="persistence",
                    details={
                        "type": "consumer",
                        "name": c["name"],
                        "cls": c.get("cls", ""),
                    },
                    raw=c,
                )
            )

        for b in bindings:
            if b["key"] in self._known_bindings:
                continue
            self._known_bindings.add(b["key"])
            out.append(
                ThreatSignal(
                    event_type="wmi_persistence",
                    title="New WMI filter-to-consumer binding detected (T1546.003)",
                    description=(
                        f"A new WMI __FilterToConsumerBinding was found: {b['key']!r}."
                    ),
                    severity="critical",
                    confidence=0.95,
                    category="persistence",
                    details={
                        "type": "binding",
                        "name": b["key"],
                    },
                    raw=b,
                )
            )

        return out

    def _poll_once_linux(self) -> list[ThreatSignal]:
        """Linux equivalent: check for suspicious systemd user services and dbus activation files."""
        import os as _os
        suspicious: list[dict] = []
        out: list[ThreatSignal] = []

        # Check ~/.local/share/systemd/user/ for user-level systemd units
        user_systemd = _os.path.expanduser("~/.local/share/systemd/user")
        try:
            for fname in _os.listdir(user_systemd):
                if fname.endswith((".service", ".timer", ".socket")):
                    suspicious.append({
                        "type": "systemd_user_unit",
                        "name": fname,
                        "path": _os.path.join(user_systemd, fname),
                    })
        except OSError:
            pass

        # Check /etc/systemd/system/ for recently added non-standard service files
        # (heuristic: services with unusual names not matching common distro patterns)
        system_systemd = "/etc/systemd/system"
        try:
            for fname in _os.listdir(system_systemd):
                if fname.endswith((".service", ".timer")):
                    suspicious.append({
                        "type": "systemd_system_unit",
                        "name": fname,
                        "path": _os.path.join(system_systemd, fname),
                    })
        except OSError:
            pass

        # Check dbus system activation files (can be used for persistence)
        dbus_services = "/usr/share/dbus-1/system-services"
        try:
            for fname in _os.listdir(dbus_services):
                if fname.endswith(".service"):
                    suspicious.append({
                        "type": "dbus_system_service",
                        "name": fname,
                        "path": _os.path.join(dbus_services, fname),
                    })
        except OSError:
            pass

        if not self._primed:
            self._known_filters = {s["name"] for s in suspicious if s["type"] == "systemd_user_unit"}
            self._known_consumers = {s["name"] for s in suspicious if s["type"] == "systemd_system_unit"}
            self._known_bindings = {s["name"] for s in suspicious if s["type"] == "dbus_system_service"}
            self._primed = True
            return out

        for s in suspicious:
            name = s["name"]
            stype = s["type"]
            if stype == "systemd_user_unit":
                if name in self._known_filters:
                    continue
                self._known_filters.add(name)
                out.append(ThreatSignal(
                    event_type="linux_persistence",
                    title=f"New systemd user unit detected: {name}",
                    description=(
                        f"A new systemd user unit appeared in ~/.local/share/systemd/user/: {name!r}. "
                        "User-level systemd units can be used for persistence without root."
                    ),
                    severity="high",
                    confidence=0.8,
                    category="persistence",
                    details={"type": stype, "name": name, "path": s["path"]},
                    raw=s,
                ))
            elif stype == "systemd_system_unit":
                if name in self._known_consumers:
                    continue
                self._known_consumers.add(name)
                out.append(ThreatSignal(
                    event_type="linux_persistence",
                    title=f"New system-level systemd unit detected: {name}",
                    description=(
                        f"A new systemd system unit appeared in /etc/systemd/system/: {name!r}."
                    ),
                    severity="medium",
                    confidence=0.7,
                    category="persistence",
                    details={"type": stype, "name": name, "path": s["path"]},
                    raw=s,
                ))
            elif stype == "dbus_system_service":
                if name in self._known_bindings:
                    continue
                self._known_bindings.add(name)
                out.append(ThreatSignal(
                    event_type="linux_persistence",
                    title=f"New D-Bus system service detected: {name}",
                    description=(
                        f"A new D-Bus system activation file appeared: {name!r}. "
                        "D-Bus services can be used for stealthy persistence."
                    ),
                    severity="medium",
                    confidence=0.7,
                    category="persistence",
                    details={"type": stype, "name": name, "path": s["path"]},
                    raw=s,
                ))

        return out

    @staticmethod
    def _query_wmi() -> dict:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", _PS_QUERY],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        raw = (proc.stdout or "").strip()
        if not raw:
            return {"filters": [], "consumers": [], "bindings": []}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {"filters": [], "consumers": [], "bindings": []}

        def _to_list(val: object) -> list:
            if val is None:
                return []
            return val if isinstance(val, list) else [val]

        filters = []
        for item in _to_list(parsed.get("Filters")):
            if isinstance(item, dict):
                filters.append(
                    {
                        "name": str(item.get("Name", "") or ""),
                        "query": str(item.get("Query", "") or ""),
                    }
                )

        consumers = []
        for item in _to_list(parsed.get("Consumers")):
            if isinstance(item, dict):
                consumers.append(
                    {
                        "name": str(item.get("Name", "") or ""),
                        "cls": str(item.get("__CLASS", "") or ""),
                    }
                )

        bindings = []
        for item in _to_list(parsed.get("Bindings")):
            if isinstance(item, dict):
                flt = str(item.get("Filter", "") or "")
                con = str(item.get("Consumer", "") or "")
                bindings.append({"key": f"{flt}->{con}", "filter": flt, "consumer": con})

        return {"filters": filters, "consumers": consumers, "bindings": bindings}
