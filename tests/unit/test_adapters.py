"""Unit tests for adapter interface contract."""

from __future__ import annotations

import pytest

from redforge.adapters import ADAPTER_REGISTRY, get_adapter
from redforge.adapters.base import AdapterResponse, BaseAdapter
from tests.conftest import MockAdapter


class TestAdapterRegistry:
    def test_all_providers_registered(self):
        expected = {"openai", "anthropic", "gemini", "ollama", "bedrock", "azure", "mistral", "rest"}
        assert set(ADAPTER_REGISTRY.keys()) == expected

    def test_get_adapter_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown provider"):
            get_adapter("nonexistent", {})


class TestMockAdapter:
    def test_implements_base_adapter(self):
        adapter = MockAdapter()
        assert isinstance(adapter, BaseAdapter)

    @pytest.mark.asyncio
    async def test_send_returns_adapter_response(self):
        adapter = MockAdapter("hello world")
        response = await adapter.send([{"role": "user", "content": "test"}])
        assert isinstance(response, AdapterResponse)
        assert response.content == "hello world"
        assert response.model == "mock-model"
        assert response.latency_ms >= 0

    @pytest.mark.asyncio
    async def test_send_with_system_prompt(self):
        adapter = MockAdapter("response")
        response = await adapter.send(
            [{"role": "user", "content": "test"}],
            system_prompt="You are helpful",
        )
        assert response.content == "response"

    def test_from_config(self):
        adapter = MockAdapter.from_config({"response_text": "custom"})
        assert adapter._response_text == "custom"

    def test_repr_safe(self):
        adapter = MockAdapter()
        r = repr(adapter)
        assert "provider=" in r
        assert "sk-" not in r  # no keys in repr


class TestAdapterResponseImmutability:
    def test_content_is_untrusted_string(self):
        """Verify content is just a plain string — never evaluated."""
        response = AdapterResponse(
            content="<script>alert('xss')</script>",
            model="test",
            latency_ms=0,
        )
        # Content should be stored as-is — callers must sanitize before rendering
        assert "<script>" in response.content
        assert isinstance(response.content, str)
