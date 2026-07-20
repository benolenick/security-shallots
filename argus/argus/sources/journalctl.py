from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone

from argus.models import ArgusEvent

_FAILED_RE = re.compile(r"Failed password for (?:invalid user )?\S+ from (?P<ip>\d+\.\d+\.\d+\.\d+)")
_ACCEPTED_RE = re.compile(r"Accepted (?:password|publickey) for \S+ from (?P<ip>\d+\.\d+\.\d+\.\d+)")
_INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")


class JournalctlSource:
    def __init__(self, units: list[str] | None = None, min_severity: int = 1) -> None:
        self.units = set(units or ["ssh", "sshd"])
        self.min_severity = max(1, min(15, int(min_severity)))

    async def start(self, queue: asyncio.Queue[ArgusEvent]) -> None:
        cmd = ["journalctl", "-f", "-n", "0", "-o", "json"]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert proc.stdout is not None

        while True:
            line = await proc.stdout.readline()
            if not line:
                if proc.returncode is not None:
                    break
                await asyncio.sleep(0.2)
                continue

            raw_line = line.decode("utf-8", "replace").strip()
            if not raw_line:
                continue

            try:
                entry = json.loads(raw_line)
            except json.JSONDecodeError:
                continue

            event = self._to_event(entry)
            if event and event.severity >= self.min_severity:
                await queue.put(event)

    def _to_event(self, entry: dict) -> ArgusEvent | None:
        msg = str(entry.get("MESSAGE", ""))
        if not msg:
            return None

        unit = str(entry.get("_SYSTEMD_UNIT", "")).strip().lower()
        ident = str(entry.get("SYSLOG_IDENTIFIER", "")).strip().lower()

        # Keep SSH-heavy signal path by default, but allow key host events outside SSH too.
        unit_or_ident = {unit, ident}
        is_sshish = any(x in unit_or_ident for x in self.units)

        ts = self._ts(entry)

        m = _FAILED_RE.search(msg)
        if m and is_sshish:
            ip = m.group("ip")
            return ArgusEvent(
                timestamp=ts,
                severity=11,
                category="auth_failed",
                src_ip=ip,
                description="SSH authentication failure",
                detector="journalctl.ssh_failed",
                raw={"message": msg, "unit": unit, "identifier": ident},
            )

        m = _INVALID_USER_RE.search(msg)
        if m and is_sshish:
            return ArgusEvent(
                timestamp=ts,
                severity=10,
                category="invalid_user",
                src_ip=m.group("ip"),
                description=f"SSH invalid user attempted: {m.group('user')}",
                detector="journalctl.ssh_invalid_user",
                raw={"message": msg, "unit": unit, "identifier": ident},
            )

        m = _ACCEPTED_RE.search(msg)
        if m and is_sshish:
            return ArgusEvent(
                timestamp=ts,
                severity=7,
                category="auth_success",
                src_ip=m.group("ip"),
                description="SSH authentication success",
                detector="journalctl.ssh_accepted",
                raw={"message": msg, "unit": unit, "identifier": ident},
            )

        lower = msg.lower()
        if "sudo" in ident and "command=" in lower:
            return ArgusEvent(
                timestamp=ts,
                severity=10,
                category="privilege_escalation",
                description="sudo command execution",
                detector="journalctl.sudo_command",
                raw={"message": msg, "unit": unit, "identifier": ident},
            )

        if any(token in lower for token in ("useradd", "usermod", "userdel", "groupadd", "groupdel")):
            return ArgusEvent(
                timestamp=ts,
                severity=10,
                category="account_change",
                description="Local account/group management command observed",
                detector="journalctl.account_change",
                raw={"message": msg, "unit": unit, "identifier": ident},
            )

        if "journal has been rotated" in lower or "audit" in lower and "cleared" in lower:
            return ArgusEvent(
                timestamp=ts,
                severity=13,
                category="tamper_signal",
                description="Possible logging/audit tamper signal",
                detector="journalctl.tamper_signal",
                raw={"message": msg, "unit": unit, "identifier": ident},
            )

        return None

    @staticmethod
    def _ts(entry: dict) -> str:
        # journald often includes __REALTIME_TIMESTAMP in microseconds since epoch.
        raw = str(entry.get("__REALTIME_TIMESTAMP", "")).strip()
        if raw.isdigit():
            dt = datetime.fromtimestamp(int(raw) / 1_000_000, tz=timezone.utc)
            return dt.isoformat()
        return datetime.now(timezone.utc).isoformat()
