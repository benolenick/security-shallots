from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import subprocess
from datetime import datetime, timedelta, timezone

from .types import ThreatSignal


class SessionMonitor:
    def __init__(self, poll_seconds: int = 10, logon_types: list[int] | None = None) -> None:
        self.poll_seconds = max(5, int(poll_seconds))
        self.logon_types = set(int(x) for x in (logon_types or [3, 10]))
        self._last_seen = datetime.now(timezone.utc) - timedelta(seconds=self.poll_seconds + 5)
        # Linux: track known sessions so we only alert on new ones
        self._known_linux_sessions: set[str] = set()
        self._linux_primed = False

    async def start(self, queue: asyncio.Queue[ThreatSignal]) -> None:
        while True:
            for signal in self._poll_once():
                await queue.put(signal)
            self._last_seen = datetime.now(timezone.utc)
            await asyncio.sleep(self.poll_seconds)

    def _poll_once(self) -> list[ThreatSignal]:
        rows = self._query_4624_events(self._last_seen)
        if os.name != "nt":
            if rows:
                return self._signals_from_windows_rows(rows)
            return self._poll_linux()
        return self._signals_from_windows_rows(rows)

    def _signals_from_windows_rows(self, rows: list[dict]) -> list[ThreatSignal]:
        out: list[ThreatSignal] = []
        for row in rows:
            logon_type = int(row.get("LogonType", 0) or 0)
            if logon_type not in self.logon_types:
                continue
            target_user = str(row.get("TargetUserName", "") or "").strip()
            if target_user.upper() in {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "UMFD-0", "DWM-1"}:
                continue
            process = str(row.get("ProcessName", "") or "")
            ip = str(row.get("IpAddress", "") or "")
            ts = str(row.get("TimeCreated", datetime.now(timezone.utc).isoformat(timespec="milliseconds")))

            severity = "high" if logon_type == 10 else "medium"
            desc = f"Interactive/remote session logon detected (type {logon_type}) for user {target_user}"
            out.append(
                ThreatSignal(
                    event_type="session_alert",
                    title="Session activity detected",
                    description=desc,
                    severity=severity,
                    confidence=0.85,
                    category="lateral_movement",
                    details={
                        "target_user": target_user,
                        "logon_type": logon_type,
                        "ip_address": ip,
                        "process_name": process,
                    },
                    raw=row,
                    timestamp=ts,
                )
            )
        return out

    def _poll_linux(self) -> list[ThreatSignal]:
        """Poll active sessions on Linux using `who`."""
        sessions = self._query_who()
        out: list[ThreatSignal] = []

        current_keys: set[str] = set()
        for sess in sessions:
            # Unique key: user + tty + source IP/host
            key = f"{sess['user']}:{sess['tty']}:{sess['source']}"
            current_keys.add(key)

        if not self._linux_primed:
            self._known_linux_sessions = current_keys
            self._linux_primed = True
            return out

        for sess in sessions:
            key = f"{sess['user']}:{sess['tty']}:{sess['source']}"
            if key in self._known_linux_sessions:
                continue
            self._known_linux_sessions.add(key)

            source = sess["source"]
            # _query_who strips the parens, so an X session arrives as ":0"/":1",
            # never "(:0)". Treat X displays and localhost as LOCAL, and down-rank
            # private-IP sources to medium (routine LAN admin SSH) so only
            # public/unknown remote sources rate "high".
            is_local = _source_is_local(source)
            is_remote = bool(source) and not is_local
            if not is_remote:
                severity = "low"
            elif _source_is_private_ip(source):
                severity = "medium"
            else:
                severity = "high"
            session_type = "SSH/remote" if is_remote else "local"
            desc = (
                f"{session_type} session detected for user {sess['user']} "
                f"on {sess['tty']}"
            )
            if source:
                desc += f" from {source}"

            out.append(
                ThreatSignal(
                    event_type="session_alert",
                    title="Session activity detected",
                    description=desc,
                    severity=severity,
                    confidence=0.85,
                    category="lateral_movement" if is_remote else "session",
                    details={
                        "target_user": sess["user"],
                        "logon_type": 10 if is_remote else 3,
                        "ip_address": source if is_remote else "",
                        "display": source if is_local and source else "",
                        "process_name": sess["tty"],
                    },
                    raw=sess,
                    timestamp=sess.get("login_time", datetime.now(timezone.utc).isoformat(timespec="milliseconds")),
                )
            )

        # Remove sessions that are no longer active
        self._known_linux_sessions &= current_keys
        return out

    @staticmethod
    def _query_who() -> list[dict]:
        """Run `who` and parse output into session dicts."""
        try:
            proc = subprocess.run(
                ["who"],
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            return []
        output = (proc.stdout or "").strip()
        if not output:
            return []
        sessions: list[dict] = []
        for line in output.splitlines():
            # Format: USERNAME  TTY  DATE TIME (SOURCE)
            parts = line.split()
            if len(parts) < 3:
                continue
            user = parts[0]
            tty = parts[1]
            # Date/time is typically parts[2] and parts[3]
            login_time = " ".join(parts[2:4]) if len(parts) >= 4 else parts[2]
            # Source (hostname/IP) is in parentheses at the end
            source = ""
            if line.rstrip().endswith(")"):
                idx = line.rfind("(")
                if idx != -1:
                    source = line[idx + 1 : -1].strip()
            sessions.append({
                "user": user,
                "tty": tty,
                "login_time": login_time,
                "source": source,
            })
        return sessions

    @staticmethod
    def _query_4624_events(start_time: datetime) -> list[dict]:
        if os.name != "nt":
            return []

        ps = (
            "$ErrorActionPreference='SilentlyContinue'; "
            f"$start=(Get-Date '{start_time.isoformat()}').ToUniversalTime(); "
            "$events=Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$start; Id=4624}; "
            "$out=@(); "
            "foreach($e in $events){ "
            "$x=[xml]$e.ToXml(); $d=@{}; foreach($n in $x.Event.EventData.Data){$d[$n.Name]=$n.'#text'}; "
            "$out += [PSCustomObject]@{"
            "TimeCreated=$e.TimeCreated.ToUniversalTime().ToString('o');"
            "TargetUserName=$d['TargetUserName'];"
            "TargetDomainName=$d['TargetDomainName'];"
            "LogonType=$d['LogonType'];"
            "ProcessName=$d['ProcessName'];"
            "IpAddress=$d['IpAddress'];"
            "AuthenticationPackageName=$d['AuthenticationPackageName']"
            "}"
            "}; $out | ConvertTo-Json -Compress"
        )

        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        raw = (proc.stdout or "").strip()
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []
        return parsed if isinstance(parsed, list) else [parsed]


def _source_is_local(source: str) -> bool:
    """True for X displays (":0", "host02:1"), empty, localhost, or loopback."""
    if not source:
        return True
    if source.startswith(":"):  # X display, e.g. ":0", ":1"
        return True
    host = source.split(":", 1)[0].lower()
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _source_is_private_ip(source: str) -> bool:
    host = source.split(":", 1)[0]
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        return False
    return parsed.is_private or parsed.is_link_local
