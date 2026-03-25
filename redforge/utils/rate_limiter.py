"""Rate limiting and retry logic with exponential backoff.

Handles provider-specific rate limits gracefully without crashing scans.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Provider-specific rate limit errors (checked by string matching to avoid
# importing provider SDKs unless installed)
_RATE_LIMIT_SIGNALS = [
    "rate limit",
    "rate_limit",
    "429",
    "too many requests",
    "quota exceeded",
    "resource exhausted",
    "throttl",
]


def _is_rate_limit_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(signal in msg for signal in _RATE_LIMIT_SIGNALS)


async def with_retry(
    fn: Callable[..., Awaitable[T]],
    *args: Any,
    max_attempts: int = 5,
    min_wait: float = 1.0,
    max_wait: float = 60.0,
    **kwargs: Any,
) -> T:
    """Call an async function with exponential backoff on rate limit errors.

    Args:
        fn: Async callable to retry.
        max_attempts: Maximum number of total attempts.
        min_wait: Minimum wait seconds between retries.
        max_wait: Maximum wait seconds between retries.

    Returns:
        The result of fn(*args, **kwargs).

    Raises:
        RuntimeError: If all attempts are exhausted.
        Exception: Any non-rate-limit exception from fn.
    """
    last_exc: Exception | None = None
    attempt = 0

    while attempt < max_attempts:
        try:
            return await fn(*args, **kwargs)
        except Exception as exc:
            if _is_rate_limit_error(exc):
                attempt += 1
                wait = min(min_wait * (2 ** (attempt - 1)), max_wait)
                logger.warning(
                    "Rate limit hit (attempt %d/%d), backing off %.1fs: %s",
                    attempt,
                    max_attempts,
                    wait,
                    str(exc)[:100],
                )
                await asyncio.sleep(wait)
                last_exc = exc
            else:
                raise

    raise RuntimeError(f"Max retries exceeded: {last_exc}") from last_exc


class TokenBucket:
    """Simple token bucket for client-side rate limiting."""

    def __init__(self, rate: float, capacity: float) -> None:
        self.rate = rate          # tokens per second
        self.capacity = capacity  # max tokens
        self._tokens = capacity
        self._last_refill = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
        self._last_refill = now

    async def acquire(self, tokens: float = 1.0) -> None:
        """Wait until tokens are available."""
        while True:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return
            wait = (tokens - self._tokens) / self.rate
            await asyncio.sleep(wait)
