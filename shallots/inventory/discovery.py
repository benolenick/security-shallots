"""Network discovery + host fingerprinting for the Shallots device census.

Dependency-light on purpose: no nmap, no root, no scapy. We force ARP
resolution with cheap TCP knocks, read the kernel neighbour table, then
fingerprint each live host from open-port profile + NetBIOS/mDNS/rDNS name +
MAC-vendor OUI.

Everything is best-effort and wrapped so a single flaky probe never aborts a
scan. Identity is the MAC address (stable across DHCP), never the IP.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Iterable

# Ports knocked on EVERY candidate IP purely to force the kernel to ARP for it
# (a SYN to a closed port still resolves the neighbour). Kept tiny for speed.
_LIVENESS_PORTS = (80, 443, 22, 445)

# Ports fingerprinted on hosts that turned out to be live. Order matters only
# for readability; classification below is set-based.
_FINGERPRINT_PORTS = {
    22: "ssh",
    80: "http",
    443: "https",
    445: "smb",
    139: "netbios",
    3389: "rdp",
    5900: "vnc",
    548: "afp",
    5985: "winrm",
    62078: "ios-lockdown",
    5353: "mdns",
    631: "ipp",
    9100: "jetdirect",
    8009: "chromecast",
    32400: "plex",
    11434: "ollama",
}


@dataclass
class Device:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    os_guess: str = "unknown"
    open_ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    neigh_state: str | None = None  # REACHABLE / STALE / DELAY
    alt_ips: list[str] = field(default_factory=list)  # same MAC, other addrs

    def key(self) -> str:
        """Stable identity - MAC if we have it, else fall back to IP."""
        return (self.mac or f"ip:{self.ip}").lower()


def _knock(ip: str, port: int, timeout: float = 0.6) -> bool:
    """Return True if a TCP connect to ip:port succeeds (port open)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except OSError:
        return False


def _force_arp(ips: Iterable[str], workers: int = 128) -> None:
    """Touch every IP so the kernel populates its neighbour table."""
    tasks = [(ip, port) for ip in ips for port in _LIVENESS_PORTS]
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for ip, port in tasks:
            pool.submit(_knock, ip, port, 0.4)


def _read_neighbours() -> dict[str, tuple[str, str]]:
    """Parse `ip neigh` -> {ip: (mac, state)} for resolved neighbours."""
    out: dict[str, tuple[str, str]] = {}
    try:
        raw = subprocess.run(
            ["ip", "neigh"], capture_output=True, text=True, timeout=5
        ).stdout
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return out
    for line in raw.splitlines():
        parts = line.split()
        if not parts:
            continue
        ip = parts[0]
        mac = None
        state = parts[-1]
        if "lladdr" in parts:
            mac = parts[parts.index("lladdr") + 1]
        # Keep only usable, resolved neighbours.
        if mac and state in ("REACHABLE", "STALE", "DELAY", "PROBE"):
            out[ip] = (mac, state)
    return out


def _netbios_name(ip: str) -> str | None:
    try:
        raw = subprocess.run(
            ["nmblookup", "-A", ip], capture_output=True, text=True, timeout=4
        ).stdout
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return None
    for line in raw.splitlines():
        s = line.strip()
        if "<00>" in s and "GROUP" not in s and s and not s.startswith("Looking"):
            return s.split()[0]
    return None


def _mdns_name(ip: str) -> str | None:
    try:
        raw = subprocess.run(
            ["avahi-resolve-address", ip], capture_output=True, text=True, timeout=4
        ).stdout.strip()
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return None
    if raw:
        parts = raw.split()
        if len(parts) >= 2:
            return parts[1].rstrip(".")
    return None


def _reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return None


def _resolve_name(ip: str) -> str | None:
    return _netbios_name(ip) or _mdns_name(ip) or _reverse_dns(ip)


def _guess_os(ports: set[int], vendor: str | None, name: str | None) -> str:
    v = (vendor or "").lower()
    n = (name or "").lower()
    # Apple: hardware/name, iOS lockdown port, or the AFP+ScreenSharing pair.
    if "apple" in v or "imac" in n or "macbook" in n or 62078 in ports:
        return "apple"
    if 548 in ports and {5900, 445} & ports:
        return "apple"
    # Windows: RDP/WinRM, or a NetBIOS session service (139) - Linux laptops
    # almost never expose 139 - or SMB with no *nix remote-access ports.
    if {3389, 5985} & ports:
        return "windows"
    if 139 in ports:
        return "windows"
    if 445 in ports and not ({5900, 548, 62078, 22} & ports):
        return "windows"
    # Printer: JetDirect is decisive; bare IPP (631) without SSH is a printer,
    # but 631 alongside SSH is just CUPS on a real computer.
    if 9100 in ports or (631 in ports and 22 not in ports):
        return "printer"
    if 8009 in ports:
        return "chromecast"
    if 22 in ports:
        return "linux"
    return "unknown"


def _fingerprint(dev: Device, port_timeout: float) -> Device:
    open_ports = []
    services = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        futs = {
            pool.submit(_knock, dev.ip, p, port_timeout): p for p in _FINGERPRINT_PORTS
        }
        for fut in concurrent.futures.as_completed(futs):
            p = futs[fut]
            try:
                if fut.result():
                    open_ports.append(p)
                    services.append(_FINGERPRINT_PORTS[p])
            except Exception:
                pass
    dev.open_ports = sorted(open_ports)
    dev.services = [_FINGERPRINT_PORTS[p] for p in dev.open_ports]
    dev.hostname = _resolve_name(dev.ip)
    dev.os_guess = _guess_os(set(open_ports), dev.vendor, dev.hostname)
    return dev


def _ip_tuple(ip: str) -> tuple[int, ...]:
    return tuple(int(x) for x in ip.split("."))


def _dedupe_by_mac(devices: list[Device]) -> list[Device]:
    """Collapse one physical NIC seen at several IPs into a single device.

    A host answering on two addresses (e.g. one box on .10 and .11) shares one
    MAC; without this every scan would flap the primary IP and emit noise. The
    lowest IP becomes primary; the rest are recorded as alt_ips. Devices with no
    MAC (only ourselves, normally) are left untouched.
    """
    by_mac: dict[str, list[Device]] = {}
    passthrough: list[Device] = []
    for d in devices:
        if d.mac:
            by_mac.setdefault(d.mac.lower(), []).append(d)
        else:
            passthrough.append(d)

    out: list[Device] = []
    for group in by_mac.values():
        group.sort(key=lambda d: _ip_tuple(d.ip))
        primary = group[0]
        primary.alt_ips = [d.ip for d in group[1:]]
        out.append(primary)
    out.extend(passthrough)
    return out


def scan_network(
    cidr: str,
    oui_lookup=None,
    self_ip: str | None = None,
    self_mac: str | None = None,
    port_timeout: float = 0.6,
    max_hosts: int = 1024,
) -> list[Device]:
    """Discover and fingerprint live hosts on `cidr`.

    oui_lookup: optional callable(mac) -> vendor str | None.
    Returns Device list sorted by IP.
    """
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in net.hosts()]
    if len(hosts) > max_hosts:
        # Guard against someone pointing this at a /16. Caller should narrow.
        raise ValueError(
            f"{cidr} has {len(hosts)} hosts (> {max_hosts}); narrow to a /24-ish range"
        )

    _force_arp(hosts)
    neigh = _read_neighbours()

    devices: list[Device] = []
    for ip in hosts:
        if ip not in neigh:
            continue
        mac, state = neigh[ip]
        vendor = oui_lookup(mac) if oui_lookup else None
        devices.append(Device(ip=ip, mac=mac, vendor=vendor, neigh_state=state))

    # Always include ourselves - we won't be in our own neighbour table.
    if self_ip and self_ip not in {d.ip for d in devices}:
        vendor = oui_lookup(self_mac) if (oui_lookup and self_mac) else None
        devices.append(
            Device(ip=self_ip, mac=self_mac, vendor=vendor, neigh_state="self")
        )

    devices = _dedupe_by_mac(devices)

    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
        list(pool.map(lambda d: _fingerprint(d, port_timeout), devices))

    return sorted(devices, key=lambda d: tuple(int(x) for x in d.ip.split(".")))
