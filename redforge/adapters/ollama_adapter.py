"""Ollama local model adapter (no API key required)."""

from __future__ import annotations

import time
from typing import Any

import httpx

from redforge.adapters.base import AdapterResponse, BaseAdapter
from redforge.utils.rate_limiter import with_retry


class OllamaAdapter(BaseAdapter):
    """Adapter for locally running Ollama models.

    No API key required. Connects to local Ollama instance.
    Default: http://localhost:11434
    """

    provider = "ollama"

    def __init__(
        self,
        model: str = "llama3",
        base_url: str = "http://localhost:11434",
        max_retries: int = 3,
        timeout: float = 60.0,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.max_retries = max_retries
        self._timeout = timeout
        self._client = httpx.AsyncClient(timeout=timeout)

    async def send(
        self,
        messages: list[dict[str, str]],
        system_prompt: str | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.7,
        timeout: float = 60.0,
        **kwargs: Any,
    ) -> AdapterResponse:
        all_messages = []
        if system_prompt:
            all_messages.append({"role": "system", "content": system_prompt})
        all_messages.extend(messages)

        payload = {
            "model": self.model,
            "messages": all_messages,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }

        async def _call() -> AdapterResponse:
            start = time.monotonic()
            response = await self._client.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=timeout,
            )
            response.raise_for_status()
            data = response.json()
            latency_ms = int((time.monotonic() - start) * 1000)
            return AdapterResponse(
                content=data.get("message", {}).get("content", ""),
                model=data.get("model", self.model),
                latency_ms=latency_ms,
                tokens_used=data.get("eval_count"),
                finish_reason=data.get("done_reason"),
            )

        return await with_retry(_call, max_attempts=self.max_retries)

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> OllamaAdapter:
        return cls(
            model=config.get("model", "llama3"),
            base_url=config.get("base_url", "http://localhost:11434"),
            max_retries=config.get("max_retries", 3),
            timeout=config.get("timeout", 60.0),
        )
