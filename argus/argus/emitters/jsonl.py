from __future__ import annotations

from pathlib import Path
from typing import Any
import json


class JsonlEmitter:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    async def emit(self, alert: dict[str, Any]) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(alert, separators=(",", ":"), ensure_ascii=True))
            f.write("\n")
