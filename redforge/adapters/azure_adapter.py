"""Azure OpenAI adapter."""

from __future__ import annotations

import time
from typing import Any

from redforge.adapters.base import AdapterResponse, BaseAdapter
from redforge.utils.rate_limiter import with_retry
from redforge.utils.secrets import get_secret


class AzureAdapter(BaseAdapter):
    """Adapter for Azure OpenAI Service."""

    provider = "azure"

    def __init__(
        self,
        deployment: str = "gpt-4o",
        api_version: str = "2024-02-01",
        max_retries: int = 3,
        timeout: float = 30.0,
    ) -> None:
        try:
            from openai import AsyncAzureOpenAI
        except ImportError as e:
            raise ImportError(
                "Azure provider requires 'openai' package. "
                "Install with: pip install redforge[openai]"
            ) from e

        api_key = get_secret("AZURE_OPENAI_API_KEY", required=True)
        endpoint = get_secret("AZURE_OPENAI_ENDPOINT", required=True)
        self._client = AsyncAzureOpenAI(
            api_key=api_key,
            azure_endpoint=endpoint,
            api_version=api_version,
            max_retries=0,
        )
        self.deployment = deployment
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
            response = await self._client.chat.completions.create(
                model=self.deployment,
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
    def from_config(cls, config: dict[str, Any]) -> AzureAdapter:
        return cls(
            deployment=config.get("deployment", "gpt-4o"),
            api_version=config.get("api_version", "2024-02-01"),
            max_retries=config.get("max_retries", 3),
        )
