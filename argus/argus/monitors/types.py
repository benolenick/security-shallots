from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class ThreatSignal:
    event_type: str
    title: str
    description: str
    severity: str
    confidence: float
    category: str
    details: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="milliseconds"))


def expand_config_path(path: str) -> str:
    """Expand shell-style and Windows-style environment variables in config paths."""
    expanded = os.path.expanduser(os.path.expandvars(str(path)))

    def replace_percent_var(match: re.Match[str]) -> str:
        return os.environ.get(match.group(1), match.group(0))

    expanded = re.sub(r"%([^%\\/]+)%", replace_percent_var, expanded)
    if os.sep == "/":
        expanded = expanded.replace("\\", "/")
    return expanded
