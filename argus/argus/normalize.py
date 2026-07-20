from __future__ import annotations

from typing import Any

from .models import ArgusEvent


def normalize_alert(event: ArgusEvent) -> dict[str, Any]:
    return {
        "timestamp": event.timestamp,
        "source": "argus",
        "severity": max(1, min(15, int(event.severity))),
        "category": event.category,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "description": event.description,
        "raw": {
            "detector": event.detector,
            **event.raw,
        },
    }
