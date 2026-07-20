"""Firewall monitor - detects disabled profiles and suspicious inbound rules.

Two independent checks per poll:
  1. Profile status  - any disabled profile triggers a critical alert.
  2. Port rules      - inbound Allow rules with ports in the suspicious list
                       trigger a high alert.

Uses `_primed` for first-poll baseline and per-item `_alerted_*` sets to avoid
re-alerting on unchanged conditions.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
from dataclasses import dataclass, field

from .types import ThreatSignal


@dataclass(slots=True)
class FirewallMonitorConfig:
    enabled: bool = True
    poll_seconds: int = 300
    suspicious_ports: list[int] = field(default_factory=lambda: [4444, 5555, 8888, 9001, 1234, 6666])


class FirewallMonitor:
    def __init__(self, cfg: FirewallMonitorConfig) -> None:
        self.cfg = cfg
        self._primed = False
        self._alerted_profiles: set[str] = set()   # profile names already alerted
        self._alerted_rules: set[str] = set()       # "rulename:port" keys already alerted

    async def start(self, queue: asyncio.Queue[ThreatSignal]) -> None:
        while True:
            for signal in self._poll_once():
                await queue.put(signal)
            await asyncio.sleep(max(60, int(self.cfg.poll_seconds)))

    def _poll_once(self) -> list[ThreatSignal]:
        out: list[ThreatSignal] = []
        out += self._check_profiles()
        out += self._check_rules()
        if not self._primed:
            self._primed = True
        return out

    # ── Profile check ────────────────────────────────────────────────────

    def _check_profiles(self) -> list[ThreatSignal]:
        if os.name != "nt":
            return self._check_profiles_linux()

        ps = "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress"
        raw = self._run_ps(ps)
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []

        items = parsed if isinstance(parsed, list) else [parsed]
        out: list[ThreatSignal] = []
        currently_disabled: set[str] = set()

        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("Name") or "")
            enabled = item.get("Enabled")
            if enabled is False or enabled == 0:
                currently_disabled.add(name)

        for name in currently_disabled:
            if name not in self._alerted_profiles:
                self._alerted_profiles.add(name)
                out.append(ThreatSignal(
                    event_type="firewall_disabled",
                    title=f"Firewall profile disabled: {name}",
                    description=(
                        f"Windows Firewall profile '{name}' is disabled - "
                        "the system has no firewall protection on this network type"
                    ),
                    severity="critical",
                    confidence=1.0,
                    category="defense_evasion",
                    details={"profile_name": name},
                ))

        # Clear alerted flag if profile has been re-enabled
        for name in list(self._alerted_profiles):
            if name not in currently_disabled:
                self._alerted_profiles.discard(name)

        return out

    def _check_profiles_linux(self) -> list[ThreatSignal]:
        """Check if ufw or iptables is active on Linux."""
        out: list[ThreatSignal] = []
        currently_disabled: set[str] = set()

        # Check ufw first
        ufw_active = False
        ufw_output = self._run_cmd(["ufw", "status"])
        if ufw_output:
            ufw_active = "Status: active" in ufw_output
            if not ufw_active:
                currently_disabled.add("ufw")

        # Check iptables (if ufw is not active, check if iptables has rules)
        if not ufw_active:
            ipt_output = self._run_cmd(["iptables", "-L", "-n"])
            if ipt_output:
                # Count non-header, non-empty lines - if only default chains with
                # no rules, the firewall is effectively off
                rule_lines = [
                    l for l in ipt_output.splitlines()
                    if l.strip() and not l.startswith("Chain ") and not l.startswith("target")
                ]
                if not rule_lines:
                    currently_disabled.add("iptables")
            else:
                # Could not run iptables at all
                currently_disabled.add("iptables")

        for name in currently_disabled:
            if name not in self._alerted_profiles:
                self._alerted_profiles.add(name)
                out.append(ThreatSignal(
                    event_type="firewall_disabled",
                    title=f"Firewall not active: {name}",
                    description=(
                        f"Linux firewall ({name}) is not active - "
                        "the system has no firewall protection"
                    ),
                    severity="critical",
                    confidence=1.0,
                    category="defense_evasion",
                    details={"profile_name": name},
                ))

        # Clear alerted flag if firewall has been re-enabled
        for name in list(self._alerted_profiles):
            if name not in currently_disabled:
                self._alerted_profiles.discard(name)

        return out

    # ── Suspicious port rule check ────────────────────────────────────────

    def _check_rules(self) -> list[ThreatSignal]:
        if os.name != "nt":
            return self._check_rules_linux()

        ps = (
            "Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | "
            "ForEach-Object { "
            "  $pf = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue; "
            "  if ($pf.LocalPort -and $pf.LocalPort -ne 'Any') { "
            "    [PSCustomObject]@{N=$_.DisplayName; P=$pf.LocalPort} "
            "  } "
            "} | ConvertTo-Json -Compress"
        )
        raw = self._run_ps(ps)
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []

        items = parsed if isinstance(parsed, list) else [parsed]
        out: list[ThreatSignal] = []
        suspicious_ports_str = {str(p) for p in self.cfg.suspicious_ports}
        current_rule_keys: set[str] = set()

        for item in items:
            if not isinstance(item, dict):
                continue
            rule_name = str(item.get("N") or "")
            port_val = item.get("P")
            # Port may be a single value or a list
            ports = port_val if isinstance(port_val, list) else [port_val]
            for port in ports:
                port_str = str(port or "").strip()
                if port_str in suspicious_ports_str:
                    key = f"{rule_name}:{port_str}"
                    current_rule_keys.add(key)
                    if key not in self._alerted_rules:
                        self._alerted_rules.add(key)
                        out.append(ThreatSignal(
                            event_type="firewall_suspicious_rule",
                            title=f"Suspicious inbound firewall rule: port {port_str}",
                            description=(
                                f"Inbound Allow rule '{rule_name}' opens port {port_str} "
                                f"- this port is commonly used by malware/C2 tools"
                            ),
                            severity="high",
                            confidence=0.85,
                            category="defense_evasion",
                            details={"rule_name": rule_name, "port": port_str},
                        ))

        # Clear alerted flag for rules that no longer exist
        for key in list(self._alerted_rules):
            if key not in current_rule_keys:
                self._alerted_rules.discard(key)

        return out

    def _check_rules_linux(self) -> list[ThreatSignal]:
        """Check iptables INPUT chain for suspicious ACCEPT rules on Linux."""
        raw = self._run_cmd(["iptables", "-L", "INPUT", "-n", "--line-numbers"])
        if not raw:
            return []

        out: list[ThreatSignal] = []
        suspicious_ports_str = {str(p) for p in self.cfg.suspicious_ports}
        current_rule_keys: set[str] = set()

        for line in raw.splitlines():
            line = line.strip()
            # Skip header lines
            if not line or line.startswith("Chain ") or line.startswith("num"):
                continue
            # Typical line: "1  ACCEPT  tcp  --  0.0.0.0/0  0.0.0.0/0  tcp dpt:4444"
            if "ACCEPT" not in line:
                continue
            # Extract port from "dpt:XXXX"
            parts = line.split()
            rule_num = parts[0] if parts else ""
            for part in parts:
                if part.startswith("dpt:"):
                    port_str = part.split(":")[1]
                    if port_str in suspicious_ports_str:
                        rule_name = f"iptables-INPUT-{rule_num}"
                        key = f"{rule_name}:{port_str}"
                        current_rule_keys.add(key)
                        if key not in self._alerted_rules:
                            self._alerted_rules.add(key)
                            out.append(ThreatSignal(
                                event_type="firewall_suspicious_rule",
                                title=f"Suspicious inbound iptables rule: port {port_str}",
                                description=(
                                    f"iptables INPUT ACCEPT rule #{rule_num} opens port {port_str} "
                                    f"- this port is commonly used by malware/C2 tools"
                                ),
                                severity="high",
                                confidence=0.85,
                                category="defense_evasion",
                                details={"rule_name": rule_name, "port": port_str},
                            ))

        # Clear alerted flag for rules that no longer exist
        for key in list(self._alerted_rules):
            if key not in current_rule_keys:
                self._alerted_rules.discard(key)

        return out

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _run_ps(command: str) -> str:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return (proc.stdout or "").strip()

    @staticmethod
    def _run_cmd(args: list[str]) -> str:
        """Run a command on Linux/Unix and return stdout."""
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            return ""
        return (proc.stdout or "").strip()
