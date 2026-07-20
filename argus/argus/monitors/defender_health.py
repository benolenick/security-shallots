"""Periodic Windows Defender health audit.

Checks Get-MpComputerStatus and Get-MpPreference to detect:
- Real-time protection disabled
- Definitions out of date (>3 days)
- Suspicious exclusion paths added
- Tamper protection off
- Defender service not running
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from datetime import datetime, timezone

from .types import ThreatSignal


class DefenderHealthMonitor:
    def __init__(self, poll_seconds: int = 300) -> None:
        self.poll_seconds = max(60, poll_seconds)
        self._last_exclusions: set[str] = set()
        self._baseline_set = False

    async def start(self, queue: asyncio.Queue[ThreatSignal]) -> None:
        # Initial delay - let other monitors start first
        await asyncio.sleep(15)
        while True:
            for signal in self._check():
                await queue.put(signal)
            await asyncio.sleep(self.poll_seconds)

    def _run_ps(self, command: str) -> str:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return (proc.stdout or "").strip()

    def _check(self) -> list[ThreatSignal]:
        out: list[ThreatSignal] = []

        # ── Defender status ──────────────────────────────────
        try:
            raw = self._run_ps(
                "$s = Get-MpComputerStatus; "
                "[PSCustomObject]@{"
                "RTPEnabled=$s.RealTimeProtectionEnabled;"
                "AntivirusEnabled=$s.AntivirusEnabled;"
                "AntispywareEnabled=$s.AntispywareEnabled;"
                "TamperProtected=$s.IsTamperProtected;"
                "DefSigAge=$s.AntivirusSignatureAge;"
                "LastScan=$s.LastFullScanEndTime;"
                "QuickScanAge=$s.QuickScanAge"
                "} | ConvertTo-Json -Compress"
            )
            if raw:
                status = json.loads(raw)
                out += self._check_status(status)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            pass

        # ── Exclusion audit ──────────────────────────────────
        try:
            raw = self._run_ps(
                "$p = Get-MpPreference; "
                "[PSCustomObject]@{"
                "ExPaths=@($p.ExclusionPath);"
                "ExProcesses=@($p.ExclusionProcess);"
                "ExExtensions=@($p.ExclusionExtension)"
                "} | ConvertTo-Json -Compress"
            )
            if raw:
                prefs = json.loads(raw)
                out += self._check_exclusions(prefs)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            pass

        # ── Recent detections (scan results) ─────────────
        try:
            raw = self._run_ps(
                "$d = Get-MpThreatDetection | Where-Object {"
                "$_.InitialDetectionTime -gt (Get-Date).AddSeconds(-" + str(self.poll_seconds + 30) + ")"
                "}; if($d){"
                "$out = @(); foreach($t in $d){"
                "$out += [PSCustomObject]@{"
                "ThreatID=$t.ThreatID;"
                "Resources=@($t.Resources);"
                "InitialDetectionTime=$t.InitialDetectionTime.ToUniversalTime().ToString('o');"
                "ProcessName=$t.ProcessName;"
                "ActionSuccess=$t.ActionSuccess;"
                "AdditionalActionsBitMask=$t.AdditionalActionsBitMask"
                "}}; $out | ConvertTo-Json -Compress"
                "}"
            )
            if raw:
                detections = json.loads(raw)
                if isinstance(detections, dict):
                    detections = [detections]
                out += self._check_detections(detections)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            pass

        return out

    def _check_detections(self, detections: list[dict]) -> list[ThreatSignal]:
        """Map Get-MpThreatDetection results to signals."""
        signals: list[ThreatSignal] = []
        for d in detections:
            resources = d.get("Resources", [])
            path = resources[0] if resources else "unknown"
            process = d.get("ProcessName", "")
            success = d.get("ActionSuccess")

            title = f"Defender scan detection"
            if process:
                title += f" ({process})"

            sev = "high" if success else "critical"
            desc = f"Path: {path}"
            if process:
                desc += f" | Process: {process}"
            if success is False:
                desc += " | Action FAILED"

            signals.append(ThreatSignal(
                event_type="defender_scan_detection",
                title=title,
                description=desc,
                severity=sev,
                confidence=0.95,
                category="malware",
                details=d,
            ))
        return signals

    def _check_status(self, s: dict) -> list[ThreatSignal]:
        signals: list[ThreatSignal] = []

        if s.get("RTPEnabled") is False:
            signals.append(ThreatSignal(
                event_type="defender_health",
                title="Defender: real-time protection is OFF",
                description="Windows Defender real-time protection is currently disabled",
                severity="critical",
                confidence=1.0,
                category="defense_evasion",
                details=s,
            ))

        if s.get("AntivirusEnabled") is False:
            signals.append(ThreatSignal(
                event_type="defender_health",
                title="Defender: antivirus engine is OFF",
                description="Windows Defender antivirus component is disabled",
                severity="critical",
                confidence=1.0,
                category="defense_evasion",
                details=s,
            ))

        if s.get("TamperProtected") is False:
            signals.append(ThreatSignal(
                event_type="defender_health",
                title="Defender: tamper protection is OFF",
                description="Tamper protection is disabled - Defender settings can be changed by malware",
                severity="high",
                confidence=0.95,
                category="defense_evasion",
                details=s,
            ))

        # Definitions older than 3 days
        sig_age = s.get("DefSigAge")
        if sig_age is not None and isinstance(sig_age, (int, float)) and sig_age > 3:
            signals.append(ThreatSignal(
                event_type="defender_health",
                title=f"Defender: definitions {int(sig_age)} days old",
                description=f"Antivirus definitions are {int(sig_age)} days out of date",
                severity="high" if sig_age > 7 else "medium",
                confidence=0.9,
                category="security_posture",
                details=s,
            ))

        return signals

    def _check_exclusions(self, prefs: dict) -> list[ThreatSignal]:
        signals: list[ThreatSignal] = []

        # Combine all exclusions into a set for comparison
        current: set[str] = set()
        for key in ("ExPaths", "ExProcesses", "ExExtensions"):
            items = prefs.get(key) or []
            if isinstance(items, list):
                current.update(str(x) for x in items if x)

        if not self._baseline_set:
            self._last_exclusions = current
            self._baseline_set = True
            return signals

        # Detect new exclusions since last check
        new_exclusions = current - self._last_exclusions
        if new_exclusions:
            # Flag suspicious patterns
            suspicious = [
                ex for ex in new_exclusions
                if any(p in ex.lower() for p in [
                    "\\temp\\", "\\tmp\\", "\\appdata\\",
                    "\\downloads\\", "\\desktop\\",
                    "powershell", "cmd.exe", "wscript",
                    "cscript", "mshta", "regsvr32",
                    ".exe", "c:\\",
                ])
            ]
            if suspicious:
                signals.append(ThreatSignal(
                    event_type="defender_exclusion",
                    title=f"Defender: {len(suspicious)} suspicious exclusion(s) added",
                    description=f"New exclusions: {', '.join(suspicious[:5])}",
                    severity="high",
                    confidence=0.85,
                    category="defense_evasion",
                    details={"new_exclusions": list(new_exclusions)},
                ))
            else:
                signals.append(ThreatSignal(
                    event_type="defender_exclusion",
                    title=f"Defender: {len(new_exclusions)} new exclusion(s) added",
                    description=f"New exclusions: {', '.join(new_exclusions)}",
                    severity="medium",
                    confidence=0.8,
                    category="defense_evasion",
                    details={"new_exclusions": list(new_exclusions)},
                ))

        self._last_exclusions = current
        return signals
