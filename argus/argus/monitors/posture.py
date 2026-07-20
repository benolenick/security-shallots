"""Security posture monitor - hourly audit of BitLocker, Secure Boot, and UAC.

Unlike change-detection monitors, this audits absolute posture:
  - On first poll: checks all items and alerts on anything currently weak.
  - On subsequent polls: only alerts when posture DEGRADES (gets worse than
    the previous check).  Recovery (improvement) silently clears the state.

Checks:
  1. BitLocker    - C: drive protection status (ProtectionStatus 0 = Off)
  2. Secure Boot  - Confirm-SecureBootUEFI (True/False/unavailable)
  3. UAC          - EnableLUA and ConsentPromptBehaviorAdmin registry values
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
from dataclasses import dataclass, field

from .types import ThreatSignal


@dataclass(slots=True)
class PostureMonitorConfig:
    enabled: bool = True
    poll_seconds: int = 3600


class PostureMonitor:
    def __init__(self, cfg: PostureMonitorConfig) -> None:
        self.cfg = cfg
        self._primed = False
        # Tracks last known value for each check; None = not yet measured.
        self._last_posture: dict[str, object] = {
            "bitlocker": None,
            "secureboot": None,
            "uac_enabled": None,
            "uac_consent": None,
        }

    async def start(self, queue: asyncio.Queue[ThreatSignal]) -> None:
        while True:
            for signal in self._poll_once():
                await queue.put(signal)
            await asyncio.sleep(max(300, int(self.cfg.poll_seconds)))

    def _poll_once(self) -> list[ThreatSignal]:
        current = self._read_posture()
        out: list[ThreatSignal] = []

        if not self._primed:
            # First poll: alert on anything weak right now.
            out += self._evaluate_all(current, first_poll=True)
            self._last_posture = current
            self._primed = True
            return out

        # Subsequent polls: only alert when something gets WORSE.
        out += self._evaluate_degradation(current)
        self._last_posture = current
        return out

    # ── Evaluation helpers ───────────────────────────────────────────────

    def _evaluate_all(self, posture: dict[str, object], *, first_poll: bool) -> list[ThreatSignal]:
        """Evaluate all posture checks and return signals for any weak state."""
        out: list[ThreatSignal] = []
        is_linux = os.name != "nt"

        bitlocker_on = posture.get("bitlocker")
        if bitlocker_on is False:
            if is_linux:
                out.append(ThreatSignal(
                    event_type="posture_risk",
                    title="Disk encryption (LUKS) not active",
                    description="No LUKS/dm-crypt volume detected - data may be readable without authentication",
                    severity="high",
                    confidence=0.9,
                    category="defense_evasion",
                    details={
                        "check": "disk_encryption",
                        "current_value": False,
                        "description": "No active LUKS/dm-crypt encryption found",
                    },
                ))
            else:
                out.append(ThreatSignal(
                    event_type="posture_risk",
                    title="BitLocker: OS drive is NOT encrypted",
                    description="Drive C: is not BitLocker-protected - data is readable without authentication",
                    severity="high",
                    confidence=0.9,
                    category="defense_evasion",
                    details={
                        "check": "bitlocker",
                        "current_value": False,
                        "description": "BitLocker protection is OFF for C:",
                    },
                ))

        secureboot = posture.get("secureboot")
        if secureboot is False:
            out.append(ThreatSignal(
                event_type="posture_risk",
                title="Secure Boot is disabled",
                description="Secure Boot is OFF - unsigned bootloaders and bootkits can execute at startup",
                severity="medium",
                confidence=0.9,
                category="defense_evasion",
                details={
                    "check": "secureboot",
                    "current_value": False,
                    "description": "Secure Boot EFI variable reports disabled" if is_linux else "Confirm-SecureBootUEFI returned False",
                },
            ))

        uac_enabled = posture.get("uac_enabled")
        if uac_enabled is False:
            if is_linux:
                out.append(ThreatSignal(
                    event_type="posture_risk",
                    title="Root account direct login is enabled",
                    description="Root account has an unlocked password - direct root login is possible",
                    severity="medium",
                    confidence=0.9,
                    category="defense_evasion",
                    details={
                        "check": "root_login",
                        "current_value": "root_unlocked",
                        "description": "Root password is not locked in /etc/shadow",
                    },
                ))
            else:
                out.append(ThreatSignal(
                    event_type="posture_risk",
                    title="UAC is fully disabled (EnableLUA=0)",
                    description="User Account Control is disabled - all processes run with full admin rights",
                    severity="medium",
                    confidence=0.9,
                    category="defense_evasion",
                    details={
                        "check": "uac",
                        "current_value": "EnableLUA=0",
                        "description": "UAC enforcement is completely disabled",
                    },
                ))
        else:
            uac_consent = posture.get("uac_consent")
            if uac_consent == 0 and not is_linux:
                out.append(ThreatSignal(
                    event_type="posture_risk",
                    title="UAC consent prompt is disabled for admins",
                    description=(
                        "ConsentPromptBehaviorAdmin=0 - admin operations silently elevate "
                        "without any prompt, removing a key malware barrier"
                    ),
                    severity="medium",
                    confidence=0.9,
                    category="defense_evasion",
                    details={
                        "check": "uac",
                        "current_value": "ConsentPromptBehaviorAdmin=0",
                        "description": "UAC elevation prompt suppressed for administrators",
                    },
                ))

        return out

    def _evaluate_degradation(self, current: dict[str, object]) -> list[ThreatSignal]:
        """Return signals only for checks that degraded since the last poll."""
        out: list[ThreatSignal] = []
        prev = self._last_posture
        is_linux = os.name != "nt"

        # BitLocker/LUKS: degraded if it was on (True) and is now off (False)
        if prev.get("bitlocker") is True and current.get("bitlocker") is False:
            if is_linux:
                out.append(ThreatSignal(
                    event_type="posture_risk",
                    title="Disk encryption (LUKS) was REMOVED",
                    description="LUKS/dm-crypt volume was removed since the last check",
                    severity="high",
                    confidence=0.9,
                    category="defense_evasion",
                    details={
                        "check": "disk_encryption",
                        "current_value": False,
                        "description": "LUKS encryption changed from active to inactive",
                    },
                ))
            else:
                out.append(ThreatSignal(
                    event_type="posture_risk",
                    title="BitLocker: OS drive protection was TURNED OFF",
                    description="Drive C: BitLocker protection has been disabled since the last check",
                    severity="high",
                    confidence=0.9,
                    category="defense_evasion",
                    details={
                        "check": "bitlocker",
                        "current_value": False,
                        "description": "BitLocker protection changed from On to Off",
                    },
                ))

        # Secure Boot: degraded if it was True and is now False
        if prev.get("secureboot") is True and current.get("secureboot") is False:
            out.append(ThreatSignal(
                event_type="posture_risk",
                title="Secure Boot was DISABLED",
                description="Secure Boot has been turned off since the last posture check",
                severity="medium",
                confidence=0.9,
                category="defense_evasion",
                details={
                    "check": "secureboot",
                    "current_value": False,
                    "description": "Secure Boot changed from enabled to disabled",
                },
            ))

        # UAC/root-login: degraded if it was True (safe) and is now False (unsafe)
        if prev.get("uac_enabled") is not False and current.get("uac_enabled") is False:
            if is_linux:
                out.append(ThreatSignal(
                    event_type="posture_risk",
                    title="Root account direct login was ENABLED",
                    description="Root account password was unlocked since the last posture check",
                    severity="medium",
                    confidence=0.9,
                    category="defense_evasion",
                    details={
                        "check": "root_login",
                        "current_value": "root_unlocked",
                        "description": "Root password changed from locked to unlocked",
                    },
                ))
            else:
                out.append(ThreatSignal(
                    event_type="posture_risk",
                    title="UAC was DISABLED (EnableLUA set to 0)",
                    description="User Account Control has been turned off since the last posture check",
                    severity="medium",
                    confidence=0.9,
                    category="defense_evasion",
                    details={
                        "check": "uac",
                        "current_value": "EnableLUA=0",
                        "description": "UAC enforcement was disabled",
                    },
                ))

        # UAC consent: only applies on Windows
        if not is_linux:
            prev_consent = prev.get("uac_consent")
            curr_consent = current.get("uac_consent")
            if prev_consent != 0 and curr_consent == 0 and current.get("uac_enabled") is not False:
                out.append(ThreatSignal(
                    event_type="posture_risk",
                    title="UAC consent prompt silenced for admins",
                    description=(
                        "ConsentPromptBehaviorAdmin changed to 0 - "
                        "admin elevation now happens silently without any user prompt"
                    ),
                    severity="medium",
                    confidence=0.9,
                    category="defense_evasion",
                    details={
                        "check": "uac",
                        "current_value": "ConsentPromptBehaviorAdmin=0",
                        "description": "UAC prompt was suppressed for administrators",
                    },
                ))

        return out

    # ── Data collection ──────────────────────────────────────────────────

    def _read_posture(self) -> dict[str, object]:
        if os.name != "nt":
            return self._read_posture_linux()
        return {
            "bitlocker": self._check_bitlocker(),
            "secureboot": self._check_secureboot(),
            **self._check_uac(),
        }

    def _read_posture_linux(self) -> dict[str, object]:
        return {
            "bitlocker": self._check_luks_linux(),
            "secureboot": self._check_secureboot_linux(),
            **self._check_root_login_linux(),
        }

    @staticmethod
    def _check_luks_linux() -> bool | None:
        """Return True if at least one LUKS (dm-crypt) volume is active, False if none, None if unavailable."""
        # Try dmsetup first
        try:
            proc = subprocess.run(
                ["dmsetup", "status"],
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0:
                output = (proc.stdout or "").strip()
                if output and output != "No devices found":
                    return True
                return False
        except FileNotFoundError:
            pass

        # Fallback: check lsblk for crypt type
        try:
            proc = subprocess.run(
                ["lsblk", "-o", "NAME,FSTYPE,TYPE", "--noheadings"],
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0:
                output = (proc.stdout or "").strip()
                for line in output.splitlines():
                    if "crypt" in line.lower():
                        return True
                return False
        except FileNotFoundError:
            pass

        return None

    @staticmethod
    def _check_secureboot_linux() -> bool | None:
        """Return True/False for Secure Boot state, None if not applicable."""
        import glob as _glob
        # Check EFI variable for Secure Boot state
        efi_path = "/sys/firmware/efi"
        if not os.path.isdir(efi_path):
            return None  # Legacy BIOS or not exposed

        # Look for SecureBoot EFI variable (byte 4 of value = 1 means enabled)
        sb_files = _glob.glob("/sys/firmware/efi/efivars/SecureBoot-*")
        for sb_file in sb_files:
            try:
                with open(sb_file, "rb") as f:
                    data = f.read()
                # EFI variable: 4 bytes attributes + value bytes
                if len(data) >= 5:
                    return data[4] == 1
            except OSError:
                pass

        # Fallback: check /sys/firmware/efi/efivars/SecureBoot (some distros)
        alt = "/sys/firmware/efi/vars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c/data"
        try:
            with open(alt, "rb") as f:
                data = f.read()
            if len(data) >= 1:
                return data[0] == 1
        except OSError:
            pass

        return None

    @staticmethod
    def _check_root_login_linux() -> dict[str, object]:
        """Check if root direct login is locked (Linux equivalent of UAC).

        Returns uac_enabled (True = root login locked = good, False = root login enabled = bad)
        and uac_consent (None on Linux - not applicable).
        """
        result: dict[str, object] = {"uac_enabled": None, "uac_consent": None}

        # Check /etc/shadow for root account lock status
        # A locked password starts with '!' or '*'
        try:
            with open("/etc/shadow", "r", errors="replace") as f:
                for line in f:
                    if line.startswith("root:"):
                        parts = line.split(":")
                        if len(parts) >= 2:
                            pw_hash = parts[1]
                            # Locked if hash starts with '!' or is '*' or '!!'
                            root_locked = pw_hash.startswith("!") or pw_hash == "*"
                            result["uac_enabled"] = root_locked
                        break
        except OSError:
            pass

        return result

    def _run_ps(self, command: str) -> str:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return (proc.stdout or "").strip()

    def _check_bitlocker(self) -> bool | None:
        """Return True if C: is BitLocker-protected, False if off, None if unavailable."""
        ps = (
            "Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue "
            "| Select-Object MountPoint,ProtectionStatus | ConvertTo-Json -Compress"
        )
        raw = self._run_ps(ps)
        if not raw:
            return None
        try:
            data = json.loads(raw)
        except ValueError:
            return None
        # ProtectionStatus: 0 = Off, 1 = On, 2 = Unknown
        status = data.get("ProtectionStatus")
        if status is None:
            return None
        return int(status) == 1

    def _check_secureboot(self) -> bool | None:
        """Return True/False for Secure Boot state, None if not applicable (legacy BIOS)."""
        ps = "try { Confirm-SecureBootUEFI } catch { $false }"
        raw = self._run_ps(ps).strip().lower()
        if raw == "true":
            return True
        if raw == "false":
            return False
        return None  # cmdlet not available (non-UEFI system)

    def _check_uac(self) -> dict[str, object]:
        """Return dict with uac_enabled (bool|None) and uac_consent (int|None)."""
        result: dict[str, object] = {"uac_enabled": None, "uac_consent": None}

        lua_out = self._run_reg(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableLUA",
        )
        if lua_out is not None:
            result["uac_enabled"] = lua_out != 0

        consent_out = self._run_reg(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "ConsentPromptBehaviorAdmin",
        )
        if consent_out is not None:
            result["uac_consent"] = consent_out

        return result

    @staticmethod
    def _run_reg(key: str, value: str) -> int | None:
        """Query a registry DWORD value; returns the integer or None on failure."""
        proc = subprocess.run(
            ["reg", "query", key, "/v", value],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        output = (proc.stdout or "").strip()
        for line in output.splitlines():
            parts = line.split()
            # Format: ValueName  REG_DWORD  0x...
            if value in line and "REG_DWORD" in line and len(parts) >= 3:
                try:
                    return int(parts[-1], 16)
                except ValueError:
                    return None
        return None
