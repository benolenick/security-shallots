"""Audit policy monitor - detects weak or disabled Windows audit categories.

Checks `auditpol /get /category:*` output for critical categories that should
be set to "Success and Failure".  On first poll, establishes a baseline; on
subsequent polls it only fires when the setting CHANGES (or has never been
alerted before).
"""

from __future__ import annotations

import asyncio
import os
import subprocess
from dataclasses import dataclass

from .types import ThreatSignal

# Categories that must log both Success and Failure for meaningful coverage.
_CRITICAL_CATEGORIES = {
    "Account Logon",
    "Logon/Logoff",
    "Account Management",
    "Policy Change",
    "System",
}


@dataclass(slots=True)
class AuditPolicyConfig:
    enabled: bool = True
    poll_seconds: int = 300


class AuditPolicyMonitor:
    def __init__(self, cfg: AuditPolicyConfig) -> None:
        self.cfg = cfg
        self._primed = False
        self._last_state: dict[str, str] = {}   # category → setting
        self._alerted: set[str] = set()          # categories already alerted

    async def start(self, queue: asyncio.Queue[ThreatSignal]) -> None:
        while True:
            for signal in self._poll_once():
                await queue.put(signal)
            await asyncio.sleep(max(60, int(self.cfg.poll_seconds)))

    def _poll_once(self) -> list[ThreatSignal]:
        current = self._read_audit_policy()
        out: list[ThreatSignal] = []

        if not self._primed:
            self._last_state = current
            self._primed = True
            # On first poll, alert for any weak setting not yet alerted
            for category, setting in current.items():
                signal = self._evaluate(category, setting)
                if signal is not None:
                    self._alerted.add(category)
                    out.append(signal)
            return out

        for category, setting in current.items():
            prev = self._last_state.get(category)
            changed = prev != setting
            already_alerted = category in self._alerted

            if changed or not already_alerted:
                signal = self._evaluate(category, setting)
                if signal is not None:
                    self._alerted.add(category)
                    out.append(signal)
                elif already_alerted and changed:
                    # Setting improved - remove from alerted set
                    self._alerted.discard(category)

        self._last_state = current
        return out

    def _evaluate(self, category: str, setting: str) -> ThreatSignal | None:
        """Return a ThreatSignal if the audit setting is weak, else None."""
        if category not in _CRITICAL_CATEGORIES:
            return None

        setting_lower = setting.lower()
        if "no auditing" in setting_lower:
            return ThreatSignal(
                event_type="audit_policy",
                title=f"Audit policy: '{category}' is NOT audited",
                description=(
                    f"Critical audit category '{category}' has 'No Auditing' - "
                    "successful and failed events will not be logged"
                ),
                severity="critical",
                confidence=1.0,
                category="defense_evasion",
                details={
                    "category": category,
                    "setting": setting,
                    "expected": "Success and Failure",
                },
            )

        # Has Success but not Failure (or vice-versa)
        has_success = "success" in setting_lower
        has_failure = "failure" in setting_lower
        if not (has_success and has_failure):
            missing = "Failure" if has_success else "Success"
            return ThreatSignal(
                event_type="audit_policy",
                title=f"Audit policy: '{category}' missing {missing} logging",
                description=(
                    f"Critical audit category '{category}' only logs "
                    f"'{setting}' - {missing} events are not captured"
                ),
                severity="high",
                confidence=0.9,
                category="defense_evasion",
                details={
                    "category": category,
                    "setting": setting,
                    "expected": "Success and Failure",
                },
            )

        return None  # "Success and Failure" - healthy

    @staticmethod
    def _read_audit_policy() -> dict[str, str]:
        """Run auditpol (Windows) or auditctl (Linux) and parse results."""
        if os.name != "nt":
            return AuditPolicyMonitor._read_audit_policy_linux()

        proc = subprocess.run(
            ["auditpol", "/get", "/category:*"],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        output = (proc.stdout or "").strip()
        result: dict[str, str] = {}
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            # Lines look like: "  Account Logon                    Success and Failure"
            # We detect a setting keyword to find the split point.
            for keyword in ("Success and Failure", "No Auditing", "Success", "Failure"):
                idx = line.find(keyword)
                if idx > 0:
                    category = line[:idx].strip()
                    setting = line[idx:].strip()
                    if category:
                        result[category] = setting
                    break
        return result

    @staticmethod
    def _read_audit_policy_linux() -> dict[str, str]:
        """Read Linux audit rules via auditctl -l and map to categories."""
        try:
            proc = subprocess.run(
                ["auditctl", "-l"],
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            # auditctl not installed - report everything as No Auditing
            return {cat: "No Auditing" for cat in _CRITICAL_CATEGORIES}

        output = (proc.stdout or "").strip()

        # If no rules at all, everything is "No Auditing"
        if not output or "No rules" in output:
            return {cat: "No Auditing" for cat in _CRITICAL_CATEGORIES}

        rules_lower = output.lower()

        # Map Linux audit rule patterns to our critical categories.
        # We look for keywords/syscalls that indicate each area is covered.
        category_checks = {
            "Account Logon": [
                # PAM / login / SSH auth files
                "/etc/pam.d", "/etc/ssh/sshd_config", "pam_", "/var/log/auth",
                "/var/log/secure",
            ],
            "Logon/Logoff": [
                "/var/log/wtmp", "/var/log/btmp", "/var/run/utmp",
                "login", "session",
            ],
            "Account Management": [
                "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
                "useradd", "usermod", "userdel", "groupadd",
            ],
            "Policy Change": [
                "/etc/sudoers", "/etc/audit", "auditctl", "auditd",
                "/etc/selinux", "apparmor",
            ],
            "System": [
                "execve", "-S all", "init_module", "delete_module",
                "reboot", "shutdown", "insmod", "modprobe",
            ],
        }

        result: dict[str, str] = {}
        for category, indicators in category_checks.items():
            covered = any(ind.lower() in rules_lower for ind in indicators)
            result[category] = "Success and Failure" if covered else "No Auditing"

        return result
