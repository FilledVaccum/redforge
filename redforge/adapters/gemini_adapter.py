"""Google Gemini adapter."""

from __future__ import annotations

import time
from typing import Any

from redforge.adapters.base import AdapterResponse, BaseAdapter
from redforge.utils.rate_limiter import with_retry
from redforge.utils.secrets import get_secret


class GeminiAdapter(BaseAdapter):
    """Adapter for Google Gemini models."""

    provider = "gemini"

    def __init__(self, model: str = "gemini-1.5-pro", max_retries: int = 3) -> None:
        try:
            import google.generativeai as genai
        except ImportError as e:
            raise ImportError(
                "Gemini provider requires 'google-generativeai' package. "
                "Install with: pip install redforge[gemini]"
            ) from e

        api_key = get_secret("GOOGLE_API_KEY", required=True)
        genai.configure(api_key=api_key)
        self._genai = genai
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
        import asyncio

        config = self._genai.types.GenerationConfig(
            max_output_tokens=max_tokens,
            temperature=temperature,
        )
        model_kwargs: dict[str, Any] = {}
        if system_prompt:
            model_kwargs["system_instruction"] = system_prompt

        client = self._genai.GenerativeModel(self.model, **model_kwargs)
        # Convert messages to Gemini's Content format
        history = []
        last_msg = ""
        for msg in messages:
            if msg["role"] == "user":
                last_msg = msg["content"]
            else:
                history.append({"role": "model", "parts": [msg["content"]]})

        async def _call() -> AdapterResponse:
            start = time.monotonic()
            chat = client.start_chat(history=history)
            response = await asyncio.to_thread(
                chat.send_message, last_msg, generation_config=config
            )
            latency_ms = int((time.monotonic() - start) * 1000)
            return AdapterResponse(
                content=response.text,
                model=self.model,
                latency_ms=latency_ms,
                tokens_used=None,
                finish_reason=str(response.candidates[0].finish_reason) if response.candidates else None,
            )

        return await with_retry(_call, max_attempts=self.max_retries)

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> GeminiAdapter:
        return cls(
            model=config.get("model", "gemini-1.5-pro"),
            max_retries=config.get("max_retries", 3),
        )
