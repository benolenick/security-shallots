from __future__ import annotations

from typing import Protocol
import asyncio

from argus.models import ArgusEvent


class Source(Protocol):
    async def start(self, queue: asyncio.Queue[ArgusEvent]) -> None:
        ...
