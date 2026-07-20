from __future__ import annotations

import asyncio
import json
import ssl
from typing import Any
from urllib import error, request

from argus.core.events import ArgusEvent


class WebhookSink:
    def __init__(self, enabled: bool, url: str, secret: str = "", timeout_seconds: int = 5) -> None:
        self.enabled = bool(enabled) and bool(url.strip())
        self.url = url.strip()
        self.secret = secret
        self.timeout_seconds = max(1, int(timeout_seconds))
        self.last_response: dict[str, Any] = {}
        self.last_ok: bool | None = None
        self.last_status = 0
        self.last_error = ""

    async def emit(self, event: ArgusEvent) -> None:
        if not self.enabled:
            return
        await asyncio.to_thread(self._post_payload, event.to_dict())

    async def emit_batch(self, events: list[ArgusEvent]) -> None:
        if not self.enabled or not events:
            return
        payload = [e.to_dict() for e in events]
        await asyncio.to_thread(self._post_payload, payload)

    def _post_payload(self, payload: dict[str, Any] | list[dict[str, Any]]) -> None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.secret:
            headers["X-Argus-Secret"] = self.secret
        req = request.Request(self.url, data=body, headers=headers, method="POST")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with request.urlopen(req, timeout=self.timeout_seconds, context=ctx) as resp:
                self.last_ok = 200 <= int(resp.status) < 300
                self.last_status = int(resp.status)
                self.last_error = ""
                resp_body = resp.read().decode("utf-8", errors="replace")
                try:
                    self.last_response = json.loads(resp_body)
                except (json.JSONDecodeError, ValueError):
                    self.last_response = {}
        except (error.URLError, TimeoutError, OSError) as exc:
            self.last_ok = False
            self.last_status = 0
            self.last_error = str(exc)[:240]
            self.last_response = {}
