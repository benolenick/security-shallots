"""Windows Event Log monitor - Security, System, Defender, Firewall.

Polls multiple event logs for high-value security events and maps them
to ThreatSignals for the Argus pipeline.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone

from .types import ThreatSignal

# ── Event ID registries per log ──────────────────────────────────────────

# Security log - IDs passed via config (user-customizable) plus these extras
SECURITY_EXTRA_IDS = [
    4648,  # Explicit credential use (runas / pass-the-hash)
    4672,  # Special privileges assigned to new logon (admin used)
    4688,  # Process creation (needs GPO to include command line)
    4698,  # Scheduled task created
    4702,  # Scheduled task updated
    4719,  # System audit policy changed
    4624,  # Successful logon (filtered by type in mapper)
    4756,  # Member added to universal security group
    4757,  # Member removed from universal security group
    4769,  # Kerberos service ticket requested (kerberoasting)
]

# System log event IDs
SYSTEM_EVENT_IDS = [
    7045,  # New service installed
    104,   # System log cleared
]

# Windows Defender Operational log
DEFENDER_EVENT_IDS = [
    1116,  # Threat detected
    1117,  # Action taken on threat
    1118,  # Action failed on threat
    1119,  # Critical action failed
    5001,  # Real-time protection disabled
    5004,  # Real-time protection config changed
    5007,  # Platform config changed (exclusions, etc.)
    5010,  # Scanning disabled
    5012,  # Tamper protection disabled
]
DEFENDER_LOG = "Microsoft-Windows-Windows Defender/Operational"

# Windows Firewall log
FIREWALL_EVENT_IDS = [
    2004,  # Firewall rule added
    2005,  # Firewall rule modified
    2006,  # Firewall rule deleted
]
FIREWALL_LOG = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"

# ── Ransomware command patterns (matched against 4688 command lines) ─────

_RANSOMWARE_PATTERNS = [
    re.compile(r"vssadmin\b.*\bdelete\s+shadows", re.IGNORECASE),
    re.compile(r"wmic\b.*\bshadowcopy\s+delete", re.IGNORECASE),
    re.compile(r"bcdedit\b.*[/\-]set\b.*\brecoveryenabled\b.*\bno\b", re.IGNORECASE),
    re.compile(r"bcdedit\b.*[/\-]set\b.*\bbootstatuspolicy\b.*\bignoreallfailures\b", re.IGNORECASE),
    re.compile(r"wbadmin\b.*\bdelete\b.*\bcatalog", re.IGNORECASE),
    re.compile(r"cipher\b.*[/\-]w:", re.IGNORECASE),  # wiping free space
]

# Suspicious process patterns for 4688 (LOLBins, encoded PS, etc.)
_SUSPICIOUS_CMD_PATTERNS = [
    (re.compile(r"powershell.*-[Ee]nc", re.IGNORECASE), "Encoded PowerShell command"),
    (re.compile(r"certutil.*-(?:decode|urlcache)", re.IGNORECASE), "certutil abuse (download/decode)"),
    (re.compile(r"mshta\b.*(?:http|javascript|vbscript)", re.IGNORECASE), "mshta LOLBin execution"),
    (re.compile(r"regsvr32\b.*/s.*/(?:n|i:)", re.IGNORECASE), "regsvr32 squiblydoo"),
    (re.compile(r"wmic\b.*process\s+call\s+create", re.IGNORECASE), "WMI remote process creation"),
    (re.compile(r"bitsadmin\b.*/(?:transfer|create)", re.IGNORECASE), "BITS download/persistence"),
    (re.compile(r"rundll32\b.*comsvcs.*MiniDump", re.IGNORECASE), "LSASS dump via comsvcs"),
]


class WindowsEventsMonitor:
    def __init__(self, poll_seconds: int, watch_event_ids: list[int]) -> None:
        self.poll_seconds = max(5, int(poll_seconds))
        self.watch_event_ids = watch_event_ids
        self._last_seen = datetime.now(timezone.utc) - timedelta(seconds=self.poll_seconds + 10)

    async def start(self, queue: asyncio.Queue[ThreatSignal]) -> None:
        while True:
            for signal in self._poll_once():
                await queue.put(signal)
            self._last_seen = datetime.now(timezone.utc)
            await asyncio.sleep(self.poll_seconds)

    def _query_log(self, log_name: str, event_ids: list[int]) -> list[dict]:
        """Query a Windows event log for specific event IDs since last poll."""
        if not event_ids:
            return []
        ids = ",".join(str(i) for i in event_ids)
        ps = (
            "$ErrorActionPreference='SilentlyContinue'; "
            f"$start=(Get-Date '{self._last_seen.isoformat()}').ToUniversalTime(); "
            f"$events=Get-WinEvent -FilterHashtable @{{LogName='{log_name}'; StartTime=$start; Id={ids}}}; "
            "$out=@(); "
            "foreach($e in $events){$out += [PSCustomObject]@{"
            "TimeCreated=$e.TimeCreated.ToUniversalTime().ToString('o');"
            "Id=$e.Id;"
            "RecordId=$e.RecordId;"
            "LogName=$e.LogName;"
            "Message=($e.Message -replace '\\r?\\n',' ')}"
            "}; $out | ConvertTo-Json -Compress"
        )
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        raw = (proc.stdout or "").strip()
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []
        items = parsed if isinstance(parsed, list) else [parsed]
        return [i for i in items if isinstance(i, dict)]

    def _poll_once(self) -> list[ThreatSignal]:
        if os.name != "nt":
            return self._poll_once_linux()

        # Merge user-configured IDs with our extras (dedup)
        sec_ids = list(set(self.watch_event_ids) | set(SECURITY_EXTRA_IDS))

        items = self._query_log("Security", sec_ids)
        items += self._query_log("System", SYSTEM_EVENT_IDS)
        items += self._query_log(DEFENDER_LOG, DEFENDER_EVENT_IDS)
        items += self._query_log(FIREWALL_LOG, FIREWALL_EVENT_IDS)

        out: list[ThreatSignal] = []
        for item in items:
            signal = self._map_event(item)
            if signal is not None:
                out.append(signal)
        return out

    def _poll_once_linux(self) -> list[ThreatSignal]:
        """Poll Linux auth logs and journal for security-relevant events."""
        out: list[ThreatSignal] = []
        out += self._read_auth_log_linux()
        out += self._read_journal_errors_linux()
        self._last_seen = datetime.now(timezone.utc)
        return out

    # Patterns checked against each newly-tailed auth.log line.
    # NOTE: do NOT add `pam_unix.*session opened for user root` here. Routine
    # cron jobs trip it dozens of times per day and historically caused 4.6 GB
    # of duplicated alerts on host03 + repeated LOCKDOWN trips on April 2026.
    # If you want to monitor escalations, watch sudo/su/SSH paths instead.
    _AUTH_PATTERNS_LINUX = [
        (re.compile(r"Failed password for", re.IGNORECASE), "failed_logon",
         "SSH failed password attempt", "high", "authentication"),
        (re.compile(r"Invalid user .+ from", re.IGNORECASE), "failed_logon",
         "SSH login attempt with invalid user", "high", "authentication"),
        (re.compile(r"sudo:.+authentication failure", re.IGNORECASE), "failed_logon",
         "sudo authentication failure", "high", "authentication"),
        (re.compile(r"sudo:.+command not allowed", re.IGNORECASE), "suspicious_process",
         "sudo command not permitted", "medium", "privilege_use"),
        (re.compile(r"useradd|usermod|userdel", re.IGNORECASE), "account_modified",
         "User account modified", "critical", "account_management"),
        (re.compile(r"Accepted publickey for root", re.IGNORECASE), "admin_logon",
         "SSH root login via public key", "medium", "privilege_use"),
        (re.compile(r"Accepted password for root", re.IGNORECASE), "admin_logon",
         "SSH root password login", "high", "privilege_use"),
    ]

    def _read_auth_log_linux(self) -> list[ThreatSignal]:
        """Tail /var/log/auth.log (or /secure) emitting only newly-appended lines.

        Uses persistent (inode, position) state so the monitor never re-reads
        and re-emits the same line. On rotation (inode change OR file shrunk),
        the cursor resets to 0 and we resume from the start of the new file.

        Was a notorious replay-bug source: the previous implementation called
        ``f.readlines()`` and iterated ``lines[-2000:]`` every poll, re-emitting
        the same auth events forever (4.6 GB of duplicates over ~3 weeks on
        host03, April 2026). Do not regress this without a test.
        """
        import os as _os
        auth_log = "/var/log/auth.log"
        if not _os.path.exists(auth_log):
            auth_log = "/var/log/secure"
        try:
            st = _os.stat(auth_log)
        except OSError:
            return []

        # Per-instance tail cursor. Stored as (inode, byte_offset).
        cursor = getattr(self, "_auth_log_cursor", None)
        if (cursor is None
                or cursor[0] != st.st_ino
                or cursor[1] > st.st_size):
            # First read OR rotation OR truncation - start from current end so
            # we don't replay history on first boot.
            cursor = (st.st_ino, 0 if cursor is None else 0)
            # On first ever read, jump to EOF so we only see new events going
            # forward. After the very first poll, cursor advances normally.
            if not getattr(self, "_auth_log_initialized", False):
                cursor = (st.st_ino, st.st_size)
                self._auth_log_initialized = True

        new_lines: list[str] = []
        try:
            with open(auth_log, "r", errors="replace") as f:
                f.seek(cursor[1])
                new_lines = f.readlines()
                self._auth_log_cursor = (st.st_ino, f.tell())
        except OSError:
            return []

        out: list[ThreatSignal] = []
        ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")

        # Hard ceiling per cycle to bound work if something dumps the log
        for line in new_lines[-5000:]:
            for pattern, event_type, title, severity, category in self._AUTH_PATTERNS_LINUX:
                if pattern.search(line):
                    out.append(ThreatSignal(
                        event_type=event_type,
                        title=title,
                        description=line.strip()[:300],
                        severity=severity,
                        confidence=0.85,
                        category=category,
                        raw={"line": line.strip()},
                        timestamp=ts,
                    ))
                    break

        return out

    def _read_journal_errors_linux(self) -> list[ThreatSignal]:
        """Read recent error/critical entries from systemd journal."""
        try:
            proc = subprocess.run(
                ["journalctl", "-p", "err", "-n", "100", "--no-pager", "-o", "json",
                 "--since", self._last_seen.strftime("%Y-%m-%d %H:%M:%S")],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

        out: list[ThreatSignal] = []
        ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")

        _SERVICE_CRASH_PATTERN = re.compile(r"process .+ exited|segfault|killed by signal|core dumped", re.IGNORECASE)

        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            msg = str(entry.get("MESSAGE", "") or "")
            unit = str(entry.get("_SYSTEMD_UNIT", "") or entry.get("UNIT", "") or "")
            priority = int(entry.get("PRIORITY", 6))

            if not msg:
                continue

            # Service crash / OOM killer
            if _SERVICE_CRASH_PATTERN.search(msg):
                out.append(ThreatSignal(
                    event_type="service_crash",
                    title=f"Service crash or process killed: {unit or 'unknown'}",
                    description=msg[:300],
                    severity="medium",
                    confidence=0.75,
                    category="availability",
                    raw=entry,
                    timestamp=ts,
                ))
            elif priority <= 2:  # emergency or alert
                out.append(ThreatSignal(
                    event_type="system_error",
                    title=f"Critical system error: {unit or 'kernel'}",
                    description=msg[:300],
                    severity="high",
                    confidence=0.8,
                    category="availability",
                    raw=entry,
                    timestamp=ts,
                ))

        return out

    def _map_event(self, item: dict) -> ThreatSignal | None:
        event_id = int(item.get("Id", 0))
        msg = str(item.get("Message", ""))
        ts = str(item.get("TimeCreated", datetime.now(timezone.utc).isoformat(timespec="milliseconds")))

        # ── Security log events ──────────────────────────────

        if event_id == 4625:
            return ThreatSignal(
                event_type="failed_logon",
                title="Failed logon",
                description="Failed authentication attempt",
                severity="high",
                confidence=0.9,
                category="authentication",
                raw=item,
                timestamp=ts,
            )

        if event_id in {4720, 4728, 4732, 4740}:
            titles = {
                4720: "User account created",
                4728: "Member added to global security group",
                4732: "Member added to local security group",
                4740: "Account locked out",
            }
            return ThreatSignal(
                event_type="account_modified",
                title=titles.get(event_id, f"Account event {event_id}"),
                description=msg[:300] if msg else f"Account/group change event {event_id}",
                severity="critical",
                confidence=0.95,
                category="account_management",
                raw=item,
                timestamp=ts,
            )

        if event_id in {4756, 4757}:
            action = "added to" if event_id == 4756 else "removed from"
            return ThreatSignal(
                event_type="account_modified",
                title=f"Member {action} universal security group",
                description=msg[:300] if msg else f"Universal group membership change",
                severity="critical",
                confidence=0.95,
                category="account_management",
                raw=item,
                timestamp=ts,
            )

        if event_id == 1102:
            return ThreatSignal(
                event_type="audit_tamper",
                title="Security audit log cleared",
                description="Security audit log was cleared - possible evidence destruction",
                severity="critical",
                confidence=1.0,
                category="defense_evasion",
                raw=item,
                timestamp=ts,
            )

        if event_id == 4648:
            return ThreatSignal(
                event_type="explicit_credential",
                title="Explicit credential use (runas / PtH indicator)",
                description=msg[:300] if msg else "A process used explicit credentials different from the logged-on user",
                severity="high",
                confidence=0.85,
                category="lateral_movement",
                raw=item,
                timestamp=ts,
            )

        if event_id == 4672:
            return ThreatSignal(
                event_type="admin_logon",
                title="Admin privileges assigned to logon",
                description=msg[:300] if msg else "An account with elevated privileges logged on",
                severity="medium",
                confidence=0.8,
                category="privilege_use",
                raw=item,
                timestamp=ts,
            )

        if event_id == 4688:
            return self._map_process_creation(item, msg, ts)

        if event_id in {4698, 4702}:
            action = "created" if event_id == 4698 else "modified"
            return ThreatSignal(
                event_type="scheduled_task",
                title=f"Scheduled task {action}",
                description=msg[:300] if msg else f"A scheduled task was {action}",
                severity="high",
                confidence=0.85,
                category="persistence",
                raw=item,
                timestamp=ts,
            )

        if event_id == 4719:
            return ThreatSignal(
                event_type="audit_tamper",
                title="System audit policy changed",
                description=msg[:300] if msg else "Audit policy was modified - attacker may be disabling logging",
                severity="critical",
                confidence=0.9,
                category="defense_evasion",
                raw=item,
                timestamp=ts,
            )

        if event_id == 4624:
            return self._map_logon(item, msg, ts)

        if event_id == 4769:
            # Kerberoasting: look for RC4 encryption (0x17)
            if "0x17" in msg or "RC4" in msg.upper():
                return ThreatSignal(
                    event_type="kerberoast",
                    title="Kerberos TGS request with RC4 (possible kerberoasting)",
                    description=msg[:300] if msg else "TGS request using weak RC4 encryption - may indicate kerberoasting",
                    severity="high",
                    confidence=0.8,
                    category="credential_access",
                    raw=item,
                    timestamp=ts,
                )
            return None  # Normal Kerberos traffic, skip

        # ── System log events ────────────────────────────────

        if event_id == 7045:
            sev = "high"
            # Flag services in suspicious paths
            suspicious_paths = ["%temp%", "\\appdata\\", "\\users\\", "\\downloads\\", "\\desktop\\"]
            if any(p in msg.lower() for p in suspicious_paths):
                sev = "critical"
            return ThreatSignal(
                event_type="new_service",
                title="New service installed",
                description=msg[:300] if msg else "A new Windows service was installed",
                severity=sev,
                confidence=0.85,
                category="persistence",
                raw=item,
                timestamp=ts,
            )

        if event_id == 104:
            return ThreatSignal(
                event_type="audit_tamper",
                title="System event log cleared",
                description="System event log was cleared - possible evidence destruction",
                severity="critical",
                confidence=1.0,
                category="defense_evasion",
                raw=item,
                timestamp=ts,
            )

        # ── Firewall events ──────────────────────────────────

        if event_id in {2004, 2005, 2006}:
            actions = {2004: "added", 2005: "modified", 2006: "deleted"}
            return ThreatSignal(
                event_type="firewall_change",
                title=f"Firewall rule {actions[event_id]}",
                description=msg[:300] if msg else f"Windows Firewall rule was {actions[event_id]}",
                severity="medium",
                confidence=0.8,
                category="defense_evasion",
                raw=item,
                timestamp=ts,
            )

        # ── Windows Defender events ──────────────────────────

        if event_id in {1116, 1117, 1118, 1119}:
            return self._map_defender_threat(event_id, item, msg, ts)

        if event_id == 5001:
            return ThreatSignal(
                event_type="defender_disabled",
                title="Defender: real-time protection DISABLED",
                description="Windows Defender real-time protection was turned off",
                severity="critical",
                confidence=1.0,
                category="defense_evasion",
                raw=item,
                timestamp=ts,
            )

        if event_id == 5010:
            return ThreatSignal(
                event_type="defender_disabled",
                title="Defender: scanning DISABLED",
                description="Windows Defender scanning was disabled",
                severity="critical",
                confidence=1.0,
                category="defense_evasion",
                raw=item,
                timestamp=ts,
            )

        if event_id == 5012:
            return ThreatSignal(
                event_type="defender_tamper",
                title="Defender: tamper protection DISABLED",
                description="Windows Defender tamper protection was turned off - possible attacker activity",
                severity="critical",
                confidence=1.0,
                category="defense_evasion",
                raw=item,
                timestamp=ts,
            )

        if event_id in {5004, 5007}:
            return ThreatSignal(
                event_type="defender_config_change",
                title="Defender: configuration changed",
                description=msg[:500] if msg else f"Defender config event {event_id} - check for new exclusions",
                severity="medium",
                confidence=0.8,
                category="defense_evasion",
                raw=item,
                timestamp=ts,
            )

        # ── Fallback for any other watched event ─────────────

        if msg:
            return ThreatSignal(
                event_type="security_event",
                title=f"Security event {event_id}",
                description=f"Security event observed: {event_id}",
                severity="medium",
                confidence=0.7,
                category="security_event",
                raw=item,
                timestamp=ts,
            )
        return None

    # ── Specialized mappers ──────────────────────────────────────────

    def _map_process_creation(self, item: dict, msg: str, ts: str) -> ThreatSignal | None:
        """Map Event ID 4688 - process creation with command line analysis."""
        msg_lower = msg.lower()

        # Check for ransomware indicators (CRITICAL - act immediately)
        for pattern in _RANSOMWARE_PATTERNS:
            if pattern.search(msg):
                return ThreatSignal(
                    event_type="ransomware_indicator",
                    title="RANSOMWARE: recovery destruction detected",
                    description=msg[:500],
                    severity="critical",
                    confidence=0.98,
                    category="impact",
                    raw=item,
                    timestamp=ts,
                )

        # Check for suspicious LOLBin / attack tool usage
        for pattern, label in _SUSPICIOUS_CMD_PATTERNS:
            if pattern.search(msg):
                return ThreatSignal(
                    event_type="suspicious_process",
                    title=f"Suspicious process: {label}",
                    description=msg[:500],
                    severity="high",
                    confidence=0.85,
                    category="execution",
                    raw=item,
                    timestamp=ts,
                )

        # Office app spawning cmd/powershell (macro execution indicator)
        office_apps = ("winword", "excel", "powerpnt", "outlook", "msaccess")
        shell_procs = ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe")
        if any(app in msg_lower for app in office_apps) and any(sh in msg_lower for sh in shell_procs):
            return ThreatSignal(
                event_type="suspicious_process",
                title="Office application spawned shell process",
                description=msg[:500],
                severity="critical",
                confidence=0.9,
                category="execution",
                raw=item,
                timestamp=ts,
            )

        # Generic 4688 - log but at low severity (high volume when enabled)
        return None  # Skip generic process creation to avoid noise

    def _map_logon(self, item: dict, msg: str, ts: str) -> ThreatSignal | None:
        """Map Event ID 4624 - only report interesting logon types."""
        # Type 10 = RDP, Type 3 = Network (SMB/WMI/PsExec)
        # We only care about Type 10 (RDP) since Type 3 is very noisy
        if "Logon Type:\t\t10" in msg or "Logon Type:  10" in msg or "LogonType.*10" in msg:
            return ThreatSignal(
                event_type="rdp_logon",
                title="RDP logon detected",
                description=msg[:300] if msg else "Remote Desktop logon",
                severity="medium",
                confidence=0.8,
                category="lateral_movement",
                raw=item,
                timestamp=ts,
            )
        return None  # Skip other logon types

    def _map_defender_threat(self, event_id: int, item: dict, msg: str, ts: str) -> ThreatSignal:
        """Parse Defender threat events (1116-1119) to extract threat name, path, and action."""
        base_titles = {
            1116: "Defender: threat detected",
            1117: "Defender: action taken on threat",
            1118: "Defender: action FAILED on threat",
            1119: "Defender: critical action FAILED",
        }

        # Extract structured fields from Defender message text
        threat_name = ""
        threat_path = ""
        action_name = ""
        for line in msg.split("  "):
            line = line.strip()
            if line.startswith("Name:"):
                threat_name = line[5:].strip()
            elif line.startswith("Path:"):
                threat_path = line[5:].strip()
            elif line.startswith("Action:"):
                action_name = line[7:].strip()

        title = base_titles[event_id]
        if threat_name:
            title = f"Defender: {threat_name}"
            if event_id == 1117 and action_name:
                title += f" ({action_name})"
            elif event_id in {1118, 1119}:
                title += " - remediation FAILED"

        desc_parts = []
        if threat_name:
            desc_parts.append(f"Threat: {threat_name}")
        if threat_path:
            desc_parts.append(f"Path: {threat_path}")
        if action_name:
            desc_parts.append(f"Action: {action_name}")
        description = " | ".join(desc_parts) if desc_parts else msg[:500]

        sev = "critical" if event_id in {1118, 1119} else "high"
        details = dict(item)
        if threat_name:
            details["threat_name"] = threat_name
        if threat_path:
            details["threat_path"] = threat_path
        if action_name:
            details["action"] = action_name

        return ThreatSignal(
            event_type="defender_threat",
            title=title,
            description=description,
            severity=sev,
            confidence=0.95,
            category="malware",
            raw=details,
            timestamp=ts,
        )
