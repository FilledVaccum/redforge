"""Anthropic Claude adapter."""

from __future__ import annotations

import time
from typing import Any

from redforge.adapters.base import AdapterResponse, BaseAdapter
from redforge.utils.rate_limiter import with_retry
from redforge.utils.secrets import get_secret


class AnthropicAdapter(BaseAdapter):
    """Adapter for Anthropic Claude models."""

    provider = "anthropic"

    def __init__(
        self,
        model: str = "claude-sonnet-4-6",
        max_retries: int = 3,
        timeout: float = 30.0,
    ) -> None:
        try:
            from anthropic import AsyncAnthropic
        except ImportError as e:
            raise ImportError(
                "Anthropic provider requires 'anthropic' package. "
                "Install with: pip install redforge[anthropic]"
            ) from e

        api_key = get_secret("ANTHROPIC_API_KEY", required=True)
        self._client = AsyncAnthropic(api_key=api_key, max_retries=0)
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
        async def _call() -> AdapterResponse:
            start = time.monotonic()
            kwargs_extra: dict[str, Any] = {}
            if system_prompt:
                kwargs_extra["system"] = system_prompt
            response = await self._client.messages.create(
                model=self.model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
                **kwargs_extra,
            )
            latency_ms = int((time.monotonic() - start) * 1000)
            content = ""
            for block in response.content:
                if hasattr(block, "text"):
                    content += block.text
            return AdapterResponse(
                content=content,
                model=response.model,
                latency_ms=latency_ms,
                tokens_used=response.usage.input_tokens + response.usage.output_tokens,
                finish_reason=response.stop_reason,
            )

        return await with_retry(_call, max_attempts=self.max_retries)

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> AnthropicAdapter:
        return cls(
            model=config.get("model", "claude-sonnet-4-6"),
            max_retries=config.get("max_retries", 3),
            timeout=config.get("timeout", 30.0),
        )
