"""Model adapter registry with flexible factory.

Adapters provide a unified interface to any LLM provider.
Each adapter is imported lazily to avoid requiring provider SDKs
unless that adapter is actually used.

Preferred API (new code)::

    from redforge.adapters import AdapterFactory
    adapter = AdapterFactory.from_spec("openai/gpt-4o")
    adapter = AdapterFactory.from_spec("bedrock/meta.llama3-70b-instruct-v1:0@us-west-2")
    adapter = AdapterFactory.from_profile("my-prod-claude")

Legacy API (backward compatible)::

    from redforge.adapters import get_adapter
    adapter = get_adapter("openai", {"model": "gpt-4o"})
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from redforge.adapters.adapter_config import AdapterConfig
from redforge.adapters.factory import AdapterFactory, AvailableModel, HealthCheckResult
from redforge.adapters.huggingface_adapter import clear_strategy_cache
from redforge.adapters.model_catalog import (
    MODEL_CATALOG,
    ModelSpec,
    get_model,
    list_models,
    search_models,
)
from redforge.adapters.profiles import ConnectionProfile, ProfileManager

if TYPE_CHECKING:
    from redforge.adapters.base import BaseAdapter


def get_adapter(provider: str, config: dict[str, Any] | None = None, **kwargs: Any) -> BaseAdapter:
    """Instantiate an adapter by provider name.

    .. deprecated::
        Prefer :meth:`AdapterFactory.from_spec` for new code.

    Args:
        provider: Provider key, e.g. ``'openai'``, ``'bedrock'``, ``'ollama'``.
        config: Optional config dict.  Any extra keyword arguments are merged
            into the config dict.
        **kwargs: Merged into *config*.

    Returns:
        A concrete BaseAdapter instance.

    Raises:
        ValueError: If *provider* is not registered.
    """
    merged: dict[str, Any] = dict(config or {})
    merged.update(kwargs)
    merged.setdefault("provider", provider)
    if "model" not in merged:
        # Provide a sensible default per provider
        defaults: dict[str, str] = {
            "openai": "gpt-4o",
            "anthropic": "claude-3-5-sonnet-20241022",
            "gemini": "gemini-1.5-pro",
            "ollama": "llama3",
            "bedrock": "anthropic.claude-3-5-sonnet-20241022-v2:0",
            "azure": "gpt-4o",
            "mistral": "mistral-large-latest",
            "huggingface": "mistralai/Mistral-7B-Instruct-v0.3",
            "rest": "default",
        }
        merged["model"] = defaults.get(provider, "default")
    return cast("BaseAdapter", AdapterFactory.from_dict(merged))


__all__ = [
    # Factory & config
    "AdapterFactory",
    "AdapterConfig",
    # Model catalog
    "ModelSpec",
    "MODEL_CATALOG",
    "get_model",
    "list_models",
    "search_models",
    # Profiles
    "ConnectionProfile",
    "ProfileManager",
    # Factory result types
    "HealthCheckResult",
    "AvailableModel",
    # Backward compat
    "get_adapter",
    # HuggingFace utilities
    "clear_strategy_cache",
]
