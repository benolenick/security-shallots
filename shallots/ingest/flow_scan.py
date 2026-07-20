"""Flow-fan-out scan/sweep detector for Security Shallots.

Signature IDS (Suricata/Snort) reliably catches known *tools* and *exploits* but
NOT a quiet generic port scan - its scan rules are tool-specific. Yet Suricata
already emits `flow` records for every connection, and a scan is obvious there:
one source touching many ports on a host (port scan) or the same port across many
hosts (host sweep). This detector consumes those flow records and emits a Shallots
alert on that fan-out - the east-west signal (e.g. a compromised iLO/IoT knocking
on its neighbours' doors) that no signature fires on.

Pure logic: `observe(flow_event)` returns an Alert or None. No I/O, so it is unit
testable and can be replayed over a captured pcap's flow records. The EveIngestor
feeds it the `flow` events it otherwise discards.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from shallots.store.models import Alert, AlertSource, now_iso


def _epoch(ts: str) -> float:
    # Suricata timestamps: "2026-07-19T15:04:05.123456+0000". Parse cheaply without
    # a hard dependency on tz parsing correctness - we only need monotonic-ish deltas.
    from datetime import datetime
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0


@dataclass
class _SrcWindow:
    start: float = 0.0
    ports_by_dst: dict = field(default_factory=dict)   # dst_ip -> set(dst_port)
    dsts_by_port: dict = field(default_factory=dict)    # dst_port -> set(dst_ip)
    fired_port_scan: set = field(default_factory=set)   # dst_ips already alerted this window
    fired_sweep: set = field(default_factory=set)       # dst_ports already alerted this window


class FlowScanDetector:
    """Detects port scans and host sweeps from Suricata flow records."""

    def __init__(self, home_net: str = "192.168.0.0/16",
                 port_scan_threshold: int = 15,
                 sweep_threshold: int = 12,
                 window_sec: int = 60,
                 max_tracked_src: int = 4096,
                 ignore_src: set | None = None):
        self.home = ipaddress.ip_network(home_net, strict=False)
        self.port_scan_threshold = port_scan_threshold
        self.sweep_threshold = sweep_threshold
        self.window_sec = window_sec
        self.max_tracked_src = max_tracked_src
        self.ignore_src = set(ignore_src or ())
        self._win: dict[str, _SrcWindow] = {}

    def _in_home(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip) in self.home
        except ValueError:
            return False

    @staticmethod
    def _is_scan_like(flow: dict) -> bool:
        """A scan flow is short and mostly unanswered. Established data transfers
        (many bytes/packets back) are not scans - filtering them keeps precision."""
        pkts_to_client = flow.get("pkts_toclient", 0) or 0
        bytes_to_client = flow.get("bytes_toclient", 0) or 0
        # No/low response, or a tiny handshake-only flow.
        return pkts_to_client <= 3 or bytes_to_client < 1000

    def observe(self, evt: dict) -> Alert | None:
        if evt.get("event_type") != "flow":
            return None
        src = evt.get("src_ip", "")
        dst = evt.get("dest_ip", "")
        port = evt.get("dest_port")
        if not src or not dst or port in (None, 0):
            return None
        # East-west focus: source must be a local host (external recon is signatured
        # elsewhere) and not an allow-listed scanner (the hub's own probes, monitors).
        if src in self.ignore_src or not self._in_home(src):
            return None
        if dst == src:
            return None
        flow = evt.get("flow", {})
        if not self._is_scan_like(flow):
            return None
        ts = _epoch(evt.get("timestamp", "")) or 0.0

        w = self._win.get(src)
        if w is None:
            if len(self._win) >= self.max_tracked_src:
                # evict the oldest window to stay bounded
                oldest = min(self._win, key=lambda k: self._win[k].start)
                self._win.pop(oldest, None)
            w = _SrcWindow(start=ts)
            self._win[src] = w
        elif ts - w.start > self.window_sec:
            # window expired: reset
            w = _SrcWindow(start=ts)
            self._win[src] = w

        w.ports_by_dst.setdefault(dst, set()).add(int(port))
        w.dsts_by_port.setdefault(int(port), set()).add(dst)

        # Port scan: one src -> many distinct ports on one dst
        if (len(w.ports_by_dst[dst]) >= self.port_scan_threshold
                and dst not in w.fired_port_scan):
            w.fired_port_scan.add(dst)
            n = len(w.ports_by_dst[dst])
            return Alert(
                timestamp=evt.get("timestamp", now_iso()),
                source=AlertSource.SURICATA,
                source_ref="flow-portscan",
                severity="high",
                title=f"Port scan: {src} probed {n} ports on {dst}",
                description=(f"Attempted recon (flow fan-out): {src} contacted {n} distinct "
                            f"TCP/UDP ports on {dst} within {self.window_sec}s. No IDS "
                            f"signature required - detected from connection fan-out."),
                src_ip=src, dst_ip=dst, dst_port=int(port), proto=evt.get("proto", ""),
                category="attempted-recon", signature_id=990101,
            )

        # Host sweep: one src -> same port across many distinct dsts
        if (len(w.dsts_by_port[int(port)]) >= self.sweep_threshold
                and int(port) not in w.fired_sweep):
            w.fired_sweep.add(int(port))
            n = len(w.dsts_by_port[int(port)])
            return Alert(
                timestamp=evt.get("timestamp", now_iso()),
                source=AlertSource.SURICATA,
                source_ref="flow-sweep",
                severity="high",
                title=f"Host sweep: {src} hit port {port} on {n} hosts",
                description=(f"Attempted recon (flow fan-out): {src} contacted port {port} on "
                            f"{n} distinct hosts within {self.window_sec}s - lateral scan pattern."),
                src_ip=src, dst_ip=dst, dst_port=int(port), proto=evt.get("proto", ""),
                category="attempted-recon", signature_id=990102,
            )
        return None
