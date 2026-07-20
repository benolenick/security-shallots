"""Hash-based alert deduplication with time window."""

from __future__ import annotations

import time
from collections import OrderedDict

from shallots.store.models import Alert


class Deduplicator:
    """In-memory dedup using hash + time window.

    Keeps a sliding window of seen hashes. Alerts with the same
    source + signature_id + src_ip + dst_ip + proto within the window
    are considered duplicates.
    """

    def __init__(self, window_seconds: int = 600, max_entries: int = 50000):
        self.window = window_seconds
        self.max_entries = max_entries
        self._seen: OrderedDict[str, float] = OrderedDict()

    def is_duplicate(self, alert: Alert) -> bool:
        """Check if alert is a duplicate. Returns True if so."""
        now = time.monotonic()
        self._evict(now)

        h = alert.dedup_hash
        if not h:
            return False

        if h in self._seen:
            # Update timestamp for this hash
            self._seen.move_to_end(h)
            self._seen[h] = now
            return True

        self._seen[h] = now
        return False

    def _evict(self, now: float) -> None:
        """Remove expired entries."""
        while self._seen:
            key, ts = next(iter(self._seen.items()))
            if now - ts > self.window:
                self._seen.popitem(last=False)
            else:
                break
        # Cap size
        while len(self._seen) > self.max_entries:
            self._seen.popitem(last=False)
