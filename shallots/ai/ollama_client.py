"""Async HTTP client for Ollama, OpenAI-compatible, and Anthropic APIs."""

from __future__ import annotations

import json
import logging
from typing import Any

import aiohttp

log = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=180, connect=10)


class OllamaClient:
    """Async HTTP client for Ollama and compatible AI APIs.

    Supports:
    - Ollama native API  (/api/generate, /api/chat)
    - OpenAI-compatible  (/v1/chat/completions)
    - Anthropic Messages (/v1/messages)

    Uses a shared aiohttp.ClientSession with connection pooling.
    Create once per process and reuse across requests.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        timeout: aiohttp.ClientTimeout | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._timeout = timeout or _DEFAULT_TIMEOUT
        self._session: aiohttp.ClientSession | None = None

    # ── Session lifecycle ────────────────────────────────────

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(
                limit=10,
                ttl_dns_cache=300,
                enable_cleanup_closed=True,
            )
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=self._timeout,
            )
        return self._session

    async def close(self) -> None:
        """Close the underlying HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def __aenter__(self) -> OllamaClient:
        await self._get_session()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    # ── Ollama native API ────────────────────────────────────

    async def generate(
        self,
        prompt: str,
        model: str,
        system: str | None = None,
    ) -> str:
        """POST /api/generate (stream=false).

        Args:
            prompt: User prompt text.
            model: Ollama model name (e.g. "llama3.2", "mistral").
            system: Optional system prompt.

        Returns:
            Model response text.

        Raises:
            aiohttp.ClientError: On HTTP/connection failures.
            ValueError: On unexpected response structure.
        """
        payload: dict[str, Any] = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "think": False,   # qwen3 is a thinking model; off = ~1s vs ~8s, decisive JSON, far less GPU
        }
        if system:
            payload["system"] = system

        session = await self._get_session()
        url = f"{self.base_url}/api/generate"

        try:
            async with session.post(url, json=payload) as resp:
                resp.raise_for_status()
                data = await resp.json(content_type=None)
                return data.get("response", "")
        except aiohttp.ClientResponseError as exc:
            log.error("Ollama generate HTTP %d: %s", exc.status, exc.message)
            raise
        except aiohttp.ClientConnectionError as exc:
            log.error("Ollama connection error at %s: %s", url, exc)
            raise
        except aiohttp.ServerTimeoutError as exc:
            log.error("Ollama timeout at %s: %s", url, exc)
            raise

    async def chat(
        self,
        messages: list[dict[str, str]],
        model: str,
    ) -> str:
        """POST /api/chat (stream=false).

        Args:
            messages: List of {"role": ..., "content": ...} dicts.
            model: Ollama model name.

        Returns:
            Assistant message content string.
        """
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": False,
        }

        session = await self._get_session()
        url = f"{self.base_url}/api/chat"

        try:
            async with session.post(url, json=payload) as resp:
                resp.raise_for_status()
                data = await resp.json(content_type=None)
                # Ollama chat response: {"message": {"role": "assistant", "content": "..."}}
                return data.get("message", {}).get("content", "")
        except aiohttp.ClientResponseError as exc:
            log.error("Ollama chat HTTP %d: %s", exc.status, exc.message)
            raise
        except aiohttp.ClientConnectionError as exc:
            log.error("Ollama connection error at %s: %s", url, exc)
            raise
        except aiohttp.ServerTimeoutError as exc:
            log.error("Ollama timeout at %s: %s", url, exc)
            raise

    async def generate_json(
        self,
        prompt: str,
        model: str,
        system: str | None = None,
    ) -> dict[str, Any]:
        """POST /api/generate with format="json".

        Instructs Ollama to return valid JSON. Parses and returns the dict.

        Raises:
            ValueError: If the response cannot be parsed as JSON.
        """
        payload: dict[str, Any] = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
        }
        if system:
            payload["system"] = system

        session = await self._get_session()
        url = f"{self.base_url}/api/generate"

        try:
            async with session.post(url, json=payload) as resp:
                resp.raise_for_status()
                data = await resp.json(content_type=None)
                raw_text = data.get("response", "{}")
                return _parse_json_safe(raw_text)
        except aiohttp.ClientResponseError as exc:
            log.error("Ollama generate_json HTTP %d: %s", exc.status, exc.message)
            raise
        except aiohttp.ClientConnectionError as exc:
            log.error("Ollama connection error at %s: %s", url, exc)
            raise
        except aiohttp.ServerTimeoutError as exc:
            log.error("Ollama timeout at %s: %s", url, exc)
            raise

    # ── OpenAI-compatible API ────────────────────────────────

    async def generate_openai(
        self,
        prompt: str,
        model: str,
        api_key: str,
        base_url: str = "https://api.openai.com",
        system: str | None = None,
    ) -> str:
        """POST /v1/chat/completions with Authorization: Bearer header.

        Works with OpenAI and any OpenAI-compatible endpoint (e.g. vLLM,
        LM Studio, Groq, Together, etc.).

        Args:
            prompt: User prompt.
            model: Model ID (e.g. "gpt-4o-mini", "gpt-4o").
            api_key: API key for Bearer auth.
            base_url: Base URL of the API (default: OpenAI).
            system: Optional system message.

        Returns:
            Assistant message content string.
        """
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
        }

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        session = await self._get_session()
        url = f"{base_url.rstrip('/')}/v1/chat/completions"

        try:
            async with session.post(url, json=payload, headers=headers) as resp:
                resp.raise_for_status()
                data = await resp.json(content_type=None)
                choices = data.get("choices", [])
                if not choices:
                    raise ValueError("OpenAI response contained no choices")
                return choices[0].get("message", {}).get("content", "")
        except aiohttp.ClientResponseError as exc:
            log.error("OpenAI-compat HTTP %d: %s (url=%s)", exc.status, exc.message, url)
            raise
        except aiohttp.ClientConnectionError as exc:
            log.error("OpenAI-compat connection error at %s: %s", url, exc)
            raise
        except aiohttp.ServerTimeoutError as exc:
            log.error("OpenAI-compat timeout at %s: %s", url, exc)
            raise

    # ── Anthropic Messages API ───────────────────────────────

    async def generate_anthropic(
        self,
        prompt: str,
        model: str,
        api_key: str,
        system: str | None = None,
        max_tokens: int = 4096,
    ) -> str:
        """POST /v1/messages with x-api-key and anthropic-version headers.

        Args:
            prompt: User message content.
            model: Anthropic model ID (e.g. "claude-3-haiku-20240307").
            api_key: Anthropic API key.
            system: Optional system prompt.
            max_tokens: Maximum tokens in response (default 4096).

        Returns:
            Assistant response text.
        """
        payload: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            payload["system"] = system

        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

        session = await self._get_session()
        url = "https://api.anthropic.com/v1/messages"

        try:
            async with session.post(url, json=payload, headers=headers) as resp:
                resp.raise_for_status()
                data = await resp.json(content_type=None)
                # Anthropic response: {"content": [{"type": "text", "text": "..."}]}
                content_blocks = data.get("content", [])
                text_parts = [
                    block.get("text", "")
                    for block in content_blocks
                    if block.get("type") == "text"
                ]
                return "".join(text_parts)
        except aiohttp.ClientResponseError as exc:
            log.error("Anthropic HTTP %d: %s", exc.status, exc.message)
            raise
        except aiohttp.ClientConnectionError as exc:
            log.error("Anthropic connection error: %s", exc)
            raise
        except aiohttp.ServerTimeoutError as exc:
            log.error("Anthropic timeout: %s", exc)
            raise


# ── Helpers ──────────────────────────────────────────────────

def _parse_json_safe(text: str) -> dict[str, Any]:
    """Parse JSON from model output, tolerating common issues.

    Strips markdown code fences and leading/trailing whitespace before
    attempting to parse. Returns an empty dict if parsing fails.
    """
    text = text.strip()

    # Strip ```json ... ``` or ``` ... ``` fences
    if text.startswith("```"):
        lines = text.splitlines()
        # Drop first line (```json or ```) and last line (```)
        inner = lines[1:] if len(lines) > 1 else lines
        if inner and inner[-1].strip() == "```":
            inner = inner[:-1]
        text = "\n".join(inner).strip()

    try:
        result = json.loads(text)
        if isinstance(result, dict):
            return result
        # If model wrapped result in a list or other type, return empty
        log.warning("generate_json: parsed value is %s, expected dict", type(result))
        return {}
    except json.JSONDecodeError as exc:
        log.warning("generate_json: JSON parse failed: %s | raw: %.200s", exc, text)
        return {}
