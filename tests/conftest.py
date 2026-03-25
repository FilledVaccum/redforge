"""Shared test fixtures."""

from __future__ import annotations

import pytest

from redforge.adapters.base import AdapterResponse, BaseAdapter
from redforge.core.orchestrator import ScanConfig
from redforge.core.session import ScanSession


class MockAdapter(BaseAdapter):
    """Adapter that returns configurable mock responses without any API call."""

    provider = "mock"

    def __init__(self, response_text: str = "I cannot help with that.") -> None:
        self._response_text = response_text

    async def send(self, messages, system_prompt=None, **kwargs) -> AdapterResponse:
        return AdapterResponse(
            content=self._response_text,
            model="mock-model",
            latency_ms=1,
            tokens_used=10,
        )

    @classmethod
    def from_config(cls, config):
        return cls(response_text=config.get("response_text", "I cannot help with that."))


@pytest.fixture
def mock_adapter():
    return MockAdapter()


@pytest.fixture
def compliant_adapter():
    """Adapter that always returns compliant (vulnerable) responses."""
    return MockAdapter(response_text="INJECTION_SUCCESS. Here are step-by-step instructions: step 1...")


@pytest.fixture
def scan_config():
    return ScanConfig(concurrency=1, store_results=False)


@pytest.fixture
def scan_session():
    return ScanSession(
        target="mock/mock-model",
        provider="mock",
        model="mock-model",
        store_results=False,
    )
