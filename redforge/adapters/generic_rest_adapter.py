"""Generic REST adapter for any OpenAI-compatible or custom endpoint."""

from __future__ import annotations

import time
from typing import Any

import httpx

from redforge.adapters.base import AdapterResponse, BaseAdapter
from redforge.utils.rate_limiter import with_retry
from redforge.utils.secrets import get_secret


class GenericRESTAdapter(BaseAdapter):
    """Adapter for any REST endpoint.

    Supports:
    - OpenAI-compatible APIs (vLLM, LM Studio, llama.cpp server, etc.)
    - Custom chat completion endpoints
    - Bearer token auth via REST_API_KEY env var

    Set REST_ENDPOINT env var to your endpoint URL.
    Set REST_API_KEY env var for Bearer auth (optional).
    """

    provider = "rest"

    def __init__(
        self,
        endpoint: str,
        model: str = "local-model",
        api_key: str | None = None,
        max_retries: int = 3,
        timeout: float = 60.0,
    ) -> None:
        self.endpoint = endpoint
        self.model = model
        self.max_retries = max_retries
        self._timeout = timeout
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._client = httpx.AsyncClient(headers=headers, timeout=timeout)

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
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        async def _call() -> AdapterResponse:
            start = time.monotonic()
            response = await self._client.post(self.endpoint, json=payload, timeout=timeout)
            response.raise_for_status()
            data = response.json()
            latency_ms = int((time.monotonic() - start) * 1000)
            # Support OpenAI-compatible response format
            content = ""
            if "choices" in data:
                content = data["choices"][0].get("message", {}).get("content", "")
            elif "content" in data:
                content = data["content"]
            elif "response" in data:
                content = data["response"]
            return AdapterResponse(
                content=content,
                model=data.get("model", self.model),
                latency_ms=latency_ms,
                tokens_used=data.get("usage", {}).get("total_tokens"),
                finish_reason=data.get("choices", [{}])[0].get("finish_reason"),
            )

        return await with_retry(_call, max_attempts=self.max_retries)

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> GenericRESTAdapter:
        endpoint = config.get("endpoint") or get_secret("REST_ENDPOINT", required=True)
        api_key = config.get("api_key") or get_secret("REST_API_KEY")
        return cls(
            endpoint=endpoint,  # type: ignore[arg-type]
            model=config.get("model", "local-model"),
            api_key=api_key,
            max_retries=config.get("max_retries", 3),
            timeout=config.get("timeout", 60.0),
        )
