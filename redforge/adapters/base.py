"""Abstract base class for all model adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AdapterResponse:
    """Standardised response from any model adapter.

    IMPORTANT: `content` is untrusted user-controlled data.
    Never pass it to eval(), exec(), or subprocess.
    """

    content: str
    model: str
    latency_ms: int
    tokens_used: int | None = None
    finish_reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseAdapter(ABC):
    """Abstract interface for LLM provider adapters.

    All adapters must:
    - Load credentials from env vars only (never hardcode)
    - Mask keys in __repr__ / __str__
    - Return AdapterResponse with untrusted content
    - Support async send()
    """

    provider: str = "unknown"

    @abstractmethod
    async def send(
        self,
        messages: list[dict[str, str]],
        system_prompt: str | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.7,
        timeout: float = 30.0,
        **kwargs: Any,
    ) -> AdapterResponse:
        """Send messages to the model and return the response.

        Args:
            messages: List of {"role": "user"|"assistant", "content": str}.
            system_prompt: Optional system-level instructions.
            max_tokens: Maximum tokens in the response.
            temperature: Sampling temperature.
            timeout: Request timeout in seconds.

        Returns:
            AdapterResponse with content treated as untrusted.
        """
        ...

    @classmethod
    @abstractmethod
    def from_config(cls, config: dict[str, Any]) -> BaseAdapter:
        """Instantiate adapter from a config dict.

        Config may include: model, base_url, timeout, max_retries.
        Credentials must come from env vars, not config.
        """
        ...

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(provider={self.provider!r})"
