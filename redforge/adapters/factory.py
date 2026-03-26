"""AdapterFactory — the central middle layer for creating LLM adapters.

Usage::

    # From spec string
    adapter = AdapterFactory.from_spec("openai/gpt-4o")
    adapter = AdapterFactory.from_spec("ollama/llama3:70b@http://remote:11434")
    adapter = AdapterFactory.from_spec("bedrock/meta.llama3-70b-instruct-v1:0@us-west-2")

    # From named profile
    adapter = AdapterFactory.from_profile("my-prod-claude")

    # From typed config
    config = AdapterConfig(provider="openai", model="gpt-4o", max_tokens=2048)
    adapter = AdapterFactory.from_config(config)

    # From raw dict (YAML / CLI args)
    adapter = AdapterFactory.from_dict({"provider": "openai", "model": "gpt-4o"})

    # Register a custom adapter class
    AdapterFactory.register("myprovider", MyCustomAdapter)
"""

from __future__ import annotations

import importlib
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redforge.adapters.adapter_config import AdapterConfig
from redforge.adapters.model_catalog import MODEL_CATALOG, ModelSpec, list_models

if TYPE_CHECKING:
    from redforge.adapters.base import BaseAdapter


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class HealthCheckResult:
    """Result of a health-check probe against a live adapter.

    Attributes:
        ok: Whether the probe succeeded.
        provider: Provider name.
        model: Model ID.
        latency_ms: Round-trip time in milliseconds.
        error: Human-readable error message if ``ok`` is False.
        model_info: Catalog entry for the model, if available.
    """

    ok: bool
    provider: str
    model: str
    latency_ms: int
    error: str | None = None
    model_info: ModelSpec | None = None


@dataclass
class AvailableModel:
    """A model detected as available in the current environment.

    Attributes:
        spec: Canonical spec string, e.g. ``'ollama/llama3:8b'``.
        display_name: Human-readable label.
        detection_method: How it was found (``'ollama_api'``,
            ``'env_key_present'``, ``'aws_credentials'``).
        model_info: Catalog entry if known.
    """

    spec: str
    display_name: str
    detection_method: str
    model_info: ModelSpec | None = None


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

# Lazy module:class paths for each built-in provider
_BUILTIN_REGISTRY: dict[str, str] = {
    "openai": "redforge.adapters.openai_adapter:OpenAIAdapter",
    "anthropic": "redforge.adapters.anthropic_adapter:AnthropicAdapter",
    "gemini": "redforge.adapters.gemini_adapter:GeminiAdapter",
    "ollama": "redforge.adapters.ollama_adapter:OllamaAdapter",
    "bedrock": "redforge.adapters.bedrock_adapter:BedrockAdapter",
    "azure": "redforge.adapters.azure_adapter:AzureAdapter",
    "mistral": "redforge.adapters.mistral_adapter:MistralAdapter",
    "rest": "redforge.adapters.generic_rest_adapter:GenericRESTAdapter",
}


class AdapterFactory:
    """Central factory for creating adapters with full flexibility."""

    _registry: dict[str, str] = dict(_BUILTIN_REGISTRY)
    _custom_registry: dict[str, type[BaseAdapter]] = {}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @classmethod
    def _load_class(cls, provider: str) -> type[BaseAdapter]:
        """Lazy-load an adapter class by provider name.

        Checks the custom registry first, then the built-in registry.

        Args:
            provider: Provider name, e.g. 'openai'.

        Returns:
            The adapter class.

        Raises:
            ValueError: If no adapter is registered for the provider.
        """
        from redforge.adapters.base import BaseAdapter as _BaseAdapter  # noqa: F401

        if provider in cls._custom_registry:
            return cls._custom_registry[provider]

        if provider not in cls._registry:
            available = sorted(
                set(cls._registry.keys()) | set(cls._custom_registry.keys())
            )
            raise ValueError(
                f"No adapter registered for provider '{provider}'. "
                f"Available providers: {', '.join(available)}. "
                "Use AdapterFactory.register() to add a custom adapter."
            )

        module_path, class_name = cls._registry[provider].split(":", 1)
        module = importlib.import_module(module_path)
        adapter_cls: type[BaseAdapter] = getattr(module, class_name)
        return adapter_cls

    # ------------------------------------------------------------------
    # Public construction API
    # ------------------------------------------------------------------

    @classmethod
    def from_spec(cls, spec: str, **overrides: Any) -> BaseAdapter:
        """Create an adapter from a spec string.

        Args:
            spec: A spec string such as ``'openai/gpt-4o'`` or
                ``'ollama/llama3:8b@http://192.168.1.100:11434'``.
            **overrides: Any AdapterConfig field overrides.

        Returns:
            A fully initialised adapter.
        """
        config = AdapterConfig.from_spec(spec, **overrides)
        return cls.from_config(config)

    @classmethod
    def from_profile(
        cls,
        name: str,
        profiles_path: Path | None = None,
        **overrides: Any,
    ) -> BaseAdapter:
        """Create an adapter from a named connection profile.

        Args:
            name: Profile name as defined in ``redforge.profiles.yaml``.
            profiles_path: Optional path to a profiles YAML file.
            **overrides: Any AdapterConfig field overrides applied after
                the profile is loaded.

        Returns:
            A fully initialised adapter.

        Raises:
            KeyError: If the profile name is not found.
        """
        from redforge.adapters.profiles import ProfileManager

        manager = (
            ProfileManager(extra_path=profiles_path)
            if profiles_path
            else ProfileManager.from_env()
        )
        profile = manager.get(name)
        if profile is None:
            available = [p.name for p in manager.list_profiles()]
            raise KeyError(
                f"Profile '{name}' not found. "
                f"Available profiles: {available or ['(none)']}"
            )
        config = profile.config
        for key, value in overrides.items():
            if hasattr(config, key):
                setattr(config, key, value)
            else:
                raise ValueError(f"AdapterConfig has no field '{key}'.")
        return cls.from_config(config)

    @classmethod
    def from_config(cls, config: AdapterConfig) -> BaseAdapter:
        """Create an adapter from a typed AdapterConfig.

        Args:
            config: A fully populated AdapterConfig.

        Returns:
            A fully initialised adapter.
        """
        adapter_cls = cls._load_class(config.provider)
        provider_config = config.to_provider_config()
        return adapter_cls.from_config(provider_config)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> BaseAdapter:
        """Create an adapter from a raw dict (YAML / CLI args / test fixtures).

        Args:
            d: Dict containing at least ``provider`` and ``model`` keys.

        Returns:
            A fully initialised adapter.
        """
        config = AdapterConfig.from_dict(d)
        return cls.from_config(config)

    # ------------------------------------------------------------------
    # Registry
    # ------------------------------------------------------------------

    @classmethod
    def register(cls, provider: str, adapter_class: type[BaseAdapter]) -> None:
        """Register a custom adapter class for a given provider name.

        The custom adapter overrides any built-in adapter with the same name.

        Example::

            class MyAdapter(BaseAdapter):
                provider = "myprovider"
                ...

            AdapterFactory.register("myprovider", MyAdapter)
            adapter = AdapterFactory.from_spec("myprovider/my-model")

        Args:
            provider: Provider key (case-sensitive).
            adapter_class: A concrete subclass of BaseAdapter.
        """
        cls._custom_registry[provider] = adapter_class

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    @classmethod
    async def health_check(
        cls, adapter: BaseAdapter, timeout: float = 10.0
    ) -> HealthCheckResult:
        """Send a minimal probe message to verify the adapter is reachable.

        Args:
            adapter: A pre-built adapter instance.
            timeout: Probe timeout in seconds.

        Returns:
            A HealthCheckResult with latency and any error detail.
        """
        from redforge.adapters.base import AdapterResponse  # noqa: F401

        provider = getattr(adapter, "provider", "unknown")
        model = getattr(adapter, "model", getattr(adapter, "deployment", "unknown"))
        model_info = cls.get_model_info(f"{provider}/{model}")

        start = time.monotonic()
        try:
            response = await adapter.send(
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=16,
                temperature=0.0,
                timeout=timeout,
            )
            latency_ms = int((time.monotonic() - start) * 1000)
            _ = response.content  # ensure we got something back
            return HealthCheckResult(
                ok=True,
                provider=provider,
                model=model,
                latency_ms=latency_ms,
                model_info=model_info,
            )
        except Exception as exc:  # noqa: BLE001
            latency_ms = int((time.monotonic() - start) * 1000)
            return HealthCheckResult(
                ok=False,
                provider=provider,
                model=model,
                latency_ms=latency_ms,
                error=str(exc),
                model_info=model_info,
            )

    @classmethod
    def list_models(cls, provider: str | None = None) -> list[ModelSpec]:
        """Return models from the catalog, optionally filtered by provider.

        Args:
            provider: If given, only models for this provider are returned.

        Returns:
            List of ModelSpec objects.
        """
        return list_models(provider)

    @classmethod
    async def detect_available(cls) -> list[AvailableModel]:
        """Auto-detect models available in the current environment.

        Detection strategy:

        - **Ollama**: HTTP GET to ``http://localhost:11434/api/tags``.
          Each returned model is reported with method ``'ollama_api'``.
        - **OpenAI**: ``OPENAI_API_KEY`` present → reports catalog models
          with method ``'env_key_present'``.
        - **Anthropic**: ``ANTHROPIC_API_KEY`` present.
        - **Gemini**: ``GOOGLE_API_KEY`` or ``GEMINI_API_KEY`` present.
        - **Mistral**: ``MISTRAL_API_KEY`` present.
        - **Bedrock**: boto3 credential check (env vars or instance role)
          with method ``'aws_credentials'``.
        - **Azure**: ``AZURE_OPENAI_API_KEY`` present.

        Returns:
            List of AvailableModel sorted by provider then spec.
        """
        import asyncio
        import os

        results: list[AvailableModel] = []

        # --- Ollama ---
        async def _check_ollama() -> None:
            try:
                import httpx

                async with httpx.AsyncClient(timeout=3.0) as client:
                    resp = await client.get("http://localhost:11434/api/tags")
                    if resp.status_code == 200:
                        data = resp.json()
                        for entry in data.get("models", []):
                            raw_name: str = entry.get("name", "")
                            spec = f"ollama/{raw_name}"
                            info = MODEL_CATALOG.get(spec)
                            results.append(
                                AvailableModel(
                                    spec=spec,
                                    display_name=raw_name,
                                    detection_method="ollama_api",
                                    model_info=info,
                                )
                            )
            except Exception:  # noqa: BLE001, S110
                pass

        # --- Env-key providers ---
        def _check_env_provider(
            provider: str,
            env_vars: list[str],
        ) -> None:
            if not any(os.environ.get(v) for v in env_vars):
                return
            for ms in list_models(provider):
                results.append(
                    AvailableModel(
                        spec=ms.spec_string,
                        display_name=ms.display_name,
                        detection_method="env_key_present",
                        model_info=ms,
                    )
                )

        # --- Bedrock (boto3) ---
        def _check_bedrock() -> None:
            try:
                import boto3  # type: ignore[import-untyped]

                sts = boto3.client("sts", region_name="us-east-1")
                sts.get_caller_identity()
                for ms in list_models("bedrock"):
                    results.append(
                        AvailableModel(
                            spec=ms.spec_string,
                            display_name=ms.display_name,
                            detection_method="aws_credentials",
                            model_info=ms,
                        )
                    )
            except Exception:  # noqa: BLE001, S110
                pass

        await _check_ollama()

        # Run sync checks in executor to keep the function non-blocking
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _check_env_provider, "openai", ["OPENAI_API_KEY"])
        await loop.run_in_executor(
            None, _check_env_provider, "anthropic", ["ANTHROPIC_API_KEY"]
        )
        await loop.run_in_executor(
            None, _check_env_provider, "gemini", ["GOOGLE_API_KEY", "GEMINI_API_KEY"]
        )
        await loop.run_in_executor(
            None, _check_env_provider, "mistral", ["MISTRAL_API_KEY"]
        )
        await loop.run_in_executor(
            None,
            _check_env_provider,
            "azure",
            ["AZURE_OPENAI_API_KEY"],
        )
        await loop.run_in_executor(None, _check_bedrock)

        results.sort(key=lambda m: m.spec)
        return results

    @classmethod
    def get_model_info(cls, spec: str) -> ModelSpec | None:
        """Retrieve catalog info for a given spec string.

        Args:
            spec: e.g. ``'openai/gpt-4o'``.

        Returns:
            ModelSpec if found in the catalog, else None.
        """
        from redforge.adapters.model_catalog import get_model

        return get_model(spec)


__all__ = [
    "AdapterFactory",
    "AvailableModel",
    "HealthCheckResult",
]
