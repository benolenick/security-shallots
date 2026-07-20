"""Embed text via the local nomic-embed-text model (Ollama) for the edge-grounded
triage disposition memory. 768-dim vectors, local, ~free."""
from __future__ import annotations

import logging
import aiohttp

log = logging.getLogger(__name__)


async def embed_text(text: str, base_url: str = "http://127.0.0.1:11434",
                     model: str = "nomic-embed-text", timeout: float = 15.0):
    """Return the embedding vector for `text`, or None on any failure (never raises)."""
    text = (text or "").strip()
    if not text:
        return None
    try:
        to = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=to) as s:
            async with s.post(f"{base_url.rstrip('/')}/api/embeddings",
                              json={"model": model, "prompt": text}) as r:
                if r.status != 200:
                    log.debug("embed HTTP %d", r.status)
                    return None
                d = await r.json()
                return d.get("embedding") or None
    except Exception as e:
        log.debug("embed failed: %s", e)
        return None
