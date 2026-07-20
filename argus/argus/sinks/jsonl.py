from __future__ import annotations

import logging
from datetime import datetime, timedelta
from pathlib import Path
import json

from argus.core.events import ArgusEvent

log = logging.getLogger("argus.sinks.jsonl")


class JsonlSink:
    def __init__(self, directory: str, prefix: str = "argus_events", retention_days: int = 30) -> None:
        self.directory = Path(directory)
        self.prefix = prefix
        self.retention_days = retention_days
        self.directory.mkdir(parents=True, exist_ok=True)
        self._last_cleanup: str = ""  # date string of last cleanup run

    def _path_for_today(self) -> Path:
        day = datetime.now().strftime("%Y-%m-%d")
        return self.directory / f"{self.prefix}_{day}.jsonl"

    async def emit(self, event: ArgusEvent) -> None:
        path = self._path_for_today()
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event.to_dict(), separators=(",", ":"), ensure_ascii=True))
            f.write("\n")

        # Run cleanup once per day
        today = datetime.now().strftime("%Y-%m-%d")
        if today != self._last_cleanup:
            self._last_cleanup = today
            self._cleanup_old_files()

    def _cleanup_old_files(self) -> None:
        """Delete JSONL files older than retention_days."""
        cutoff = datetime.now() - timedelta(days=self.retention_days)
        removed = 0
        for f in self.directory.glob(f"{self.prefix}_*.jsonl"):
            try:
                # Parse date from filename: prefix_YYYY-MM-DD.jsonl
                date_str = f.stem.removeprefix(f"{self.prefix}_")
                file_date = datetime.strptime(date_str, "%Y-%m-%d")
                if file_date < cutoff:
                    f.unlink()
                    removed += 1
            except (ValueError, OSError):
                continue
        if removed:
            log.info("JSONL cleanup: removed %d file(s) older than %d days", removed, self.retention_days)
