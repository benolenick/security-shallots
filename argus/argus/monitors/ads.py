from __future__ import annotations

import asyncio
import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .types import ThreatSignal


@dataclass(slots=True)
class AdsMonitorConfig:
    enabled: bool = True
    poll_seconds: int = 300
    scan_dirs: list[str] = field(
        default_factory=lambda: [
            r"%USERPROFILE%\Desktop",
            r"%USERPROFILE%\Downloads",
            r"%USERPROFILE%\Documents",
            r"%TEMP%",
        ]
    )
    linux_scan_dirs: list[str] = field(
        default_factory=lambda: [
            "~/Desktop",
            "~/Downloads",
            "/tmp",
        ]
    )


class AdsMonitor:
    def __init__(self, cfg: AdsMonitorConfig) -> None:
        self.cfg = cfg
        self._known_streams: set[tuple[str, str]] = set()
        self._primed = False

    async def start(self, queue: asyncio.Queue[ThreatSignal]) -> None:
        while True:
            for signal in self._poll_once():
                await queue.put(signal)
            await asyncio.sleep(max(60, int(self.cfg.poll_seconds)))

    def _poll_once(self) -> list[ThreatSignal]:
        if os.name != "nt":
            return self._poll_once_linux()

        current = self._scan_all_dirs()
        out: list[ThreatSignal] = []

        if not self._primed:
            self._known_streams = {(s["file_path"], s["stream_name"]) for s in current}
            self._primed = True
            return out

        for stream in current:
            key = (stream["file_path"], stream["stream_name"])
            if key in self._known_streams:
                continue
            self._known_streams.add(key)
            out.append(
                ThreatSignal(
                    event_type="ntfs_ads",
                    title="New NTFS alternate data stream detected",
                    description=(
                        f"Non-standard ADS found on {stream['file_path']!r}: "
                        f"stream {stream['stream_name']!r} ({stream['length']} bytes)"
                    ),
                    severity="high",
                    confidence=0.8,
                    category="defense_evasion",
                    details={
                        "file_path": stream["file_path"],
                        "stream_name": stream["stream_name"],
                        "length": stream["length"],
                    },
                    raw=stream,
                )
            )

        return out

    def _poll_once_linux(self) -> list[ThreatSignal]:
        """On Linux: detect new hidden files in sensitive directories."""
        current = self._scan_hidden_files_linux()
        out: list[ThreatSignal] = []

        if not self._primed:
            # Use (file_path, "") as key to reuse self._known_streams
            self._known_streams = {(f["file_path"], "") for f in current}
            self._primed = True
            return out

        for item in current:
            key = (item["file_path"], "")
            if key in self._known_streams:
                continue
            self._known_streams.add(key)
            out.append(
                ThreatSignal(
                    event_type="hidden_file",
                    title="New hidden file detected",
                    description=(
                        f"New hidden file appeared in monitored directory: {item['file_path']!r}"
                    ),
                    severity="medium",
                    confidence=0.7,
                    category="defense_evasion",
                    details={
                        "file_path": item["file_path"],
                        "directory": item["directory"],
                    },
                    raw=item,
                )
            )

        return out

    def _scan_hidden_files_linux(self) -> list[dict]:
        """Find hidden files (dot-files) in configured Linux scan dirs."""
        results: list[dict] = []
        for raw_dir in self.cfg.linux_scan_dirs:
            expanded = str(Path(raw_dir).expanduser())
            results.extend(_scan_dir_for_hidden_files(expanded))
        return results

    def _scan_all_dirs(self) -> list[dict]:
        results: list[dict] = []
        for raw_dir in self.cfg.scan_dirs:
            expanded = os.path.expandvars(raw_dir)
            results.extend(_scan_dir_for_ads(expanded))
        return results


def _scan_dir_for_hidden_files(directory: str) -> list[dict]:
    """Find hidden (dot-file) regular files directly inside directory on Linux."""
    results: list[dict] = []
    try:
        d = Path(directory)
        if not d.is_dir():
            return []
        for entry in d.iterdir():
            if entry.name.startswith(".") and entry.is_file():
                results.append({
                    "file_path": str(entry),
                    "directory": directory,
                })
    except OSError:
        pass
    return results


def _scan_dir_for_ads(directory: str) -> list[dict]:
    ps = (
        f'Get-Item -Path "{directory}\\*" -Stream * -ErrorAction SilentlyContinue '
        "| Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' } "
        "| Select-Object FileName,Stream,Length "
        "| ConvertTo-Json -Compress"
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
    items = parsed if isinstance(parsed, list) else [parsed]
    results: list[dict] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        file_name = str(it.get("FileName", "") or "")
        stream = str(it.get("Stream", "") or "")
        length = it.get("Length", 0)
        try:
            length = int(length)
        except (TypeError, ValueError):
            length = 0
        if not file_name or not stream:
            continue
        file_path = os.path.join(directory, file_name) if not os.path.isabs(file_name) else file_name
        results.append(
            {
                "file_path": file_path,
                "stream_name": stream,
                "length": length,
            }
        )
    return results
