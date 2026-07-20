from __future__ import annotations

from typing import Protocol, Any


class Emitter(Protocol):
    async def emit(self, alert: dict[str, Any]) -> None:
        ...
