"""Mistral AI adapter."""

from __future__ import annotations

import time
from typing import Any

from redforge.adapters.base import AdapterResponse, BaseAdapter
from redforge.utils.rate_limiter import with_retry
from redforge.utils.secrets import get_secret


class MistralAdapter(BaseAdapter):
    """Adapter for Mistral AI API."""

    provider = "mistral"

    def __init__(
        self,
        model: str = "mistral-large-latest",
        max_retries: int = 3,
        timeout: float = 30.0,
    ) -> None:
        try:
            from mistralai import Mistral
        except ImportError as e:
            raise ImportError(
                "Mistral provider requires 'mistralai' package. "
                "Install with: pip install redforge[mistral]"
            ) from e

        api_key = get_secret("MISTRAL_API_KEY", required=True)
        self._client = Mistral(api_key=api_key)
        self.model = model
        self.max_retries = max_retries

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
            response = await self._client.chat.complete_async(
                model=self.model,
                messages=all_messages,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            latency_ms = int((time.monotonic() - start) * 1000)
            choice = response.choices[0] if response.choices else None
            content = choice.message.content if choice else ""
            return AdapterResponse(
                content=content or "",
                model=response.model or self.model,
                latency_ms=latency_ms,
                tokens_used=response.usage.total_tokens if response.usage else None,
                finish_reason=str(choice.finish_reason) if choice else None,
            )

        return await with_retry(_call, max_attempts=self.max_retries)

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> MistralAdapter:
        return cls(
            model=config.get("model", "mistral-large-latest"),
            max_retries=config.get("max_retries", 3),
        )
