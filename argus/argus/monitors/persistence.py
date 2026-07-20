from __future__ import annotations

import asyncio
import hashlib
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .types import ThreatSignal, expand_config_path


@dataclass(slots=True)
class PersistenceMonitorConfig:
    enabled: bool = False
    poll_seconds: int = 30
    watch_paths: list[str] = field(default_factory=list)


class PersistenceMonitor:
    def __init__(self, cfg: PersistenceMonitorConfig) -> None:
        self.cfg = cfg
        self._last_digest: str | None = None
        self._last_payload: str | None = None

    async def start(self, queue: asyncio.Queue[ThreatSignal]) -> None:
        while True:
            signal = self._poll_once()
            if signal is not None:
                await queue.put(signal)
            await asyncio.sleep(max(10, int(self.cfg.poll_seconds)))

    def _poll_once(self) -> ThreatSignal | None:
        payload = self._collect_payload()
        digest = hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()
        if self._last_digest is None:
            self._last_digest = digest
            self._last_payload = payload
            return None
        if digest == self._last_digest:
            return None
        added, removed = _payload_diff(self._last_payload or "", payload)
        self._last_digest = digest
        self._last_payload = payload
        changed_preview = "; ".join((added + removed)[:3])[:200]
        description = "Scheduled tasks/startup persistence surface changed"
        if changed_preview:
            description += f": {changed_preview}"
        return ThreatSignal(
            event_type="persistence_detected",
            title="Persistence surface changed",
            description=description,
            severity="high",
            confidence=0.85,
            category="persistence",
            details={
                "added_lines": added[:20],
                "removed_lines": removed[:20],
                "added_count": len(added),
                "removed_count": len(removed),
            },
            raw={"snapshot_hash": digest},
        )

    def _collect_payload(self) -> str:
        chunks: list[str] = []
        if os.name == "nt":
            for cmd in (
                # Avoid volatile timing columns from `/V` output that cause false positives.
                ["schtasks", "/Query", "/FO", "CSV"],
                ["reg", "query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"],
                ["reg", "query", r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"],
            ):
                p = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                chunks.append(p.stdout or "")
        else:
            # Cron persistence. `crontab -l` is unreliable under systemd
            # sandboxing (NoNewPrivileges neuters crontab's setgid, so it
            # returns "Permission denied"/empty). Read the spool + system cron
            # files directly - the running user owns its own crontab file and
            # system cron is world-readable, so this works inside the sandbox.
            import pwd
            try:
                user = pwd.getpwuid(os.getuid()).pw_name
            except Exception:
                user = os.environ.get("USER", "root")
            cron_chunks: list[str] = []
            for cp in (
                f"/var/spool/cron/crontabs/{user}",  # Debian/Ubuntu
                f"/var/spool/cron/{user}",           # RHEL/others
                "/etc/crontab",
            ):
                try:
                    cron_chunks.append(f"# {cp}\n" + Path(cp).read_text(errors="replace"))
                except Exception:
                    pass
            try:
                for f in sorted(Path("/etc/cron.d").glob("*")):
                    if f.is_file():
                        cron_chunks.append(f"# {f}\n" + f.read_text(errors="replace"))
            except Exception:
                pass
            # Fallback: crontab -l still works when not sandboxed.
            try:
                p = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
                if p.stdout:
                    cron_chunks.append("# crontab -l\n" + p.stdout)
            except Exception:
                pass
            chunks.append("\n".join(cron_chunks))
            # systemd unit persistence (unaffected by the sandbox).
            p = subprocess.run(
                ["systemctl", "list-unit-files", "--type=service"],
                capture_output=True, text=True,
            )
            chunks.append(p.stdout or "")

        for raw in self.cfg.watch_paths:
            path = Path(expand_config_path(str(raw)))
            if path.exists():
                try:
                    st = path.stat()
                    chunks.append(f"{path}|{st.st_mtime_ns}|{st.st_size}")
                except OSError:
                    chunks.append(f"{path}|ERR")
            else:
                chunks.append(f"{path}|MISSING")
        return "\n".join(chunks)


def _payload_diff(old: str, new: str, max_line_len: int = 160) -> tuple[list[str], list[str]]:
    """Line-set diff between two persistence snapshots (order-insensitive).

    Returns (added, removed) with each line truncated for alert-sized payloads.
    """
    old_lines = set(old.splitlines())
    new_lines = set(new.splitlines())
    added = sorted(l.strip()[:max_line_len] for l in new_lines - old_lines if l.strip())
    removed = sorted(l.strip()[:max_line_len] for l in old_lines - new_lines if l.strip())
    return added, removed
