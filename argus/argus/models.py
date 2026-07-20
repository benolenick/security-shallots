from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ArgusEvent:
    timestamp: str
    severity: int
    category: str
    description: str
    src_ip: str | None = None
    dst_ip: str | None = None
    detector: str = "unknown"
    raw: dict[str, Any] = field(default_factory=dict)
