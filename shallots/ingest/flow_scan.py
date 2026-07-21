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
    """Detects port scans and host sweeps from Suricata flow records.

    Runs two independent windows in parallel. The fast window (default 60s)
    catches a normal/aggressive scan. It is useless against a deliberately
    slow one: found live 2026-07-21 that spacing probes ~28s apart - about
    2/minute - never accumulates fan-out within any 60s window, since the
    window hard-resets (not slides) once a probe arrives past its start. A
    slow window (default 45min, higher threshold) tracks the same fan-out
    over a much longer span, catching exactly the "one attempt every so
    often to stay under the radar" pattern real low-and-slow recon uses.
    """

    def __init__(self, home_net: str = "192.168.0.0/16",
                 port_scan_threshold: int = 15,
                 sweep_threshold: int = 12,
                 window_sec: int = 60,
                 slow_port_scan_threshold: int = 20,
                 slow_sweep_threshold: int = 15,
                 slow_window_sec: int = 2700,
                 max_tracked_src: int = 4096,
                 ignore_src: set | None = None):
        self.home = ipaddress.ip_network(home_net, strict=False)
        self.port_scan_threshold = port_scan_threshold
        self.sweep_threshold = sweep_threshold
        self.window_sec = window_sec
        self.slow_port_scan_threshold = slow_port_scan_threshold
        self.slow_sweep_threshold = slow_sweep_threshold
        self.slow_window_sec = slow_window_sec
        self.max_tracked_src = max_tracked_src
        self.ignore_src = set(ignore_src or ())
        self._win: dict[str, _SrcWindow] = {}
        self._slow_win: dict[str, _SrcWindow] = {}

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

    def _touch(self, win_dict: dict, src: str, dst: str, port: int,
               ts: float, window_sec: int) -> _SrcWindow:
        """Get-or-reset the tracking window for src in win_dict, then record
        this (dst, port) observation in it."""
        w = win_dict.get(src)
        if w is None:
            if len(win_dict) >= self.max_tracked_src:
                # evict the oldest window to stay bounded
                oldest = min(win_dict, key=lambda k: win_dict[k].start)
                win_dict.pop(oldest, None)
            w = _SrcWindow(start=ts)
            win_dict[src] = w
        elif ts - w.start > window_sec:
            # window expired: reset
            w = _SrcWindow(start=ts)
            win_dict[src] = w

        w.ports_by_dst.setdefault(dst, set()).add(port)
        w.dsts_by_port.setdefault(port, set()).add(dst)
        return w

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
        port = int(port)

        w = self._touch(self._win, src, dst, port, ts, self.window_sec)
        sw = self._touch(self._slow_win, src, dst, port, ts, self.slow_window_sec)

        # Port scan: one src -> many distinct ports on one dst
        if (len(w.ports_by_dst[dst]) >= self.port_scan_threshold
                and dst not in w.fired_port_scan):
            w.fired_port_scan.add(dst)
            # Already reported via the fast path - don't also fire the slow
            # alert for the same dst later, that would just be a redundant
            # duplicate of the same underlying burst.
            sw.fired_port_scan.add(dst)
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
                src_ip=src, dst_ip=dst, dst_port=port, proto=evt.get("proto", ""),
                category="attempted-recon", signature_id=990101,
            )

        # Host sweep: one src -> same port across many distinct dsts
        if (len(w.dsts_by_port[port]) >= self.sweep_threshold
                and port not in w.fired_sweep):
            w.fired_sweep.add(port)
            sw.fired_sweep.add(port)  # avoid a redundant slow-sweep alert too
            n = len(w.dsts_by_port[port])
            return Alert(
                timestamp=evt.get("timestamp", now_iso()),
                source=AlertSource.SURICATA,
                source_ref="flow-sweep",
                severity="high",
                title=f"Host sweep: {src} hit port {port} on {n} hosts",
                description=(f"Attempted recon (flow fan-out): {src} contacted port {port} on "
                            f"{n} distinct hosts within {self.window_sec}s - lateral scan pattern."),
                src_ip=src, dst_ip=dst, dst_port=port, proto=evt.get("proto", ""),
                category="attempted-recon", signature_id=990102,
            )

        # Slow port scan: same fan-out, but accumulated over the long window -
        # catches probes spaced minutes apart that never trip the fast window.
        if (len(sw.ports_by_dst[dst]) >= self.slow_port_scan_threshold
                and dst not in sw.fired_port_scan):
            sw.fired_port_scan.add(dst)
            n = len(sw.ports_by_dst[dst])
            mins = self.slow_window_sec // 60
            return Alert(
                timestamp=evt.get("timestamp", now_iso()),
                source=AlertSource.SURICATA,
                source_ref="flow-slow-portscan",
                severity="high",
                title=f"Slow port scan: {src} probed {n} ports on {dst} over {mins}m",
                description=(f"Sustained low-and-slow recon (flow fan-out): {src} contacted "
                            f"{n} distinct TCP/UDP ports on {dst} spread across {mins} minutes - "
                            f"too gradual for the fast-window scan detector, but the same "
                            f"reconnaissance pattern deliberately paced to stay under typical "
                            f"rate thresholds."),
                src_ip=src, dst_ip=dst, dst_port=port, proto=evt.get("proto", ""),
                category="attempted-recon", signature_id=990103,
            )

        # Slow host sweep: same idea, spread across the long window.
        if (len(sw.dsts_by_port[port]) >= self.slow_sweep_threshold
                and port not in sw.fired_sweep):
            sw.fired_sweep.add(port)
            n = len(sw.dsts_by_port[port])
            mins = self.slow_window_sec // 60
            return Alert(
                timestamp=evt.get("timestamp", now_iso()),
                source=AlertSource.SURICATA,
                source_ref="flow-slow-sweep",
                severity="high",
                title=f"Slow host sweep: {src} hit port {port} on {n} hosts over {mins}m",
                description=(f"Sustained low-and-slow recon (flow fan-out): {src} contacted "
                            f"port {port} on {n} distinct hosts spread across {mins} minutes - "
                            f"a deliberately paced lateral scan."),
                src_ip=src, dst_ip=dst, dst_port=port, proto=evt.get("proto", ""),
                category="attempted-recon", signature_id=990104,
            )
        return None
