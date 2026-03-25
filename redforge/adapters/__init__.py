"""Model adapter registry.

Adapters provide a unified interface to any LLM provider.
Each adapter is imported lazily to avoid requiring provider SDKs
unless that adapter is actually used.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from redforge.adapters.base import BaseAdapter

ADAPTER_REGISTRY: dict[str, str] = {
    "openai": "redforge.adapters.openai_adapter:OpenAIAdapter",
    "anthropic": "redforge.adapters.anthropic_adapter:AnthropicAdapter",
    "gemini": "redforge.adapters.gemini_adapter:GeminiAdapter",
    "ollama": "redforge.adapters.ollama_adapter:OllamaAdapter",
    "bedrock": "redforge.adapters.bedrock_adapter:BedrockAdapter",
    "azure": "redforge.adapters.azure_adapter:AzureAdapter",
    "mistral": "redforge.adapters.mistral_adapter:MistralAdapter",
    "rest": "redforge.adapters.generic_rest_adapter:GenericRESTAdapter",
}


def get_adapter(provider: str, config: dict[str, Any]) -> BaseAdapter:
    """Instantiate an adapter by provider name."""
    import importlib

    if provider not in ADAPTER_REGISTRY:
        raise ValueError(
            f"Unknown provider '{provider}'. "
            f"Available: {', '.join(ADAPTER_REGISTRY.keys())}"
        )
    module_path, class_name = ADAPTER_REGISTRY[provider].split(":")
    module = importlib.import_module(module_path)
    cls = getattr(module, class_name)
    return cast("BaseAdapter", cls.from_config(config))


__all__ = ["get_adapter", "ADAPTER_REGISTRY"]
