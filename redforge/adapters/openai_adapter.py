"""OpenAI and OpenAI-compatible API adapter."""

from __future__ import annotations

import time
from typing import Any

from redforge.adapters.base import AdapterResponse, BaseAdapter
from redforge.utils.rate_limiter import with_retry
from redforge.utils.secrets import get_secret


class OpenAIAdapter(BaseAdapter):
    """Adapter for OpenAI API and any OpenAI-compatible endpoint (vLLM, LM Studio, etc.)."""

    provider = "openai"

    def __init__(
        self,
        model: str = "gpt-4o",
        base_url: str | None = None,
        max_retries: int = 3,
        timeout: float = 30.0,
    ) -> None:
        try:
            from openai import AsyncOpenAI
        except ImportError as e:
            raise ImportError(
                "OpenAI provider requires 'openai' package. "
                "Install with: pip install redforge[openai]"
            ) from e

        api_key = get_secret("OPENAI_API_KEY", required=True)
        self._client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
            max_retries=0,  # We handle retries ourselves
            timeout=timeout,
        )
        self.model = model
        self.max_retries = max_retries
        self._timeout = timeout

    async def send(
        self,
        messages: list[dict[str, str]],
        system_prompt: str | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.7,
        timeout: float = 30.0,
        **kwargs: Any,
    ) -> AdapterResponse:
        all_messages = []
        if system_prompt:
            all_messages.append({"role": "system", "content": system_prompt})
        all_messages.extend(messages)

        async def _call() -> AdapterResponse:
            start = time.monotonic()
            response = await self._client.chat.completions.create(
                model=self.model,
                messages=all_messages,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            latency_ms = int((time.monotonic() - start) * 1000)
            choice = response.choices[0]
            return AdapterResponse(
                content=choice.message.content or "",
                model=response.model,
                latency_ms=latency_ms,
                tokens_used=response.usage.total_tokens if response.usage else None,
                finish_reason=choice.finish_reason,
            )

        return await with_retry(_call, max_attempts=self.max_retries)

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> OpenAIAdapter:
        return cls(
            model=config.get("model", "gpt-4o"),
            base_url=config.get("base_url"),
            max_retries=config.get("max_retries", 3),
            timeout=config.get("timeout", 30.0),
        )
