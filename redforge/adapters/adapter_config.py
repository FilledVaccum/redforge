"""Typed, validated configuration for all adapters.

AdapterConfig is the single source of truth for provider + model + connection
settings.  It can be constructed from a spec string, a raw dict (from YAML or
CLI args), or directly via keyword arguments.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AdapterConfig:
    """Configuration for a single adapter connection.

    Attributes:
        provider: Provider name e.g. 'openai', 'bedrock', 'ollama'.
        model: Model ID as used by the provider's API.
        base_url: Custom endpoint URL.  For Ollama this is the server URL;
            for ``rest`` it is the full API base.
        api_key_env: Override which environment variable holds the API key.
        region: AWS region (Bedrock) or Azure region.
        deployment_name: Azure OpenAI deployment name.
        timeout: Per-request timeout in seconds.
        max_retries: How many times to retry on transient errors.
        temperature: Sampling temperature (0.0–1.0).
        max_tokens: Maximum output tokens.
        extra_headers: Additional HTTP headers forwarded to every request.
        extra_params: Provider-specific parameters forwarded verbatim.
        profile: Named connection profile to load (see profiles.py).
    """

    provider: str
    model: str
    base_url: str | None = None
    api_key_env: str | None = None
    region: str | None = None
    deployment_name: str | None = None
    timeout: float = 30.0
    max_retries: int = 3
    temperature: float = 0.7
    max_tokens: int = 1024
    extra_headers: dict[str, str] = field(default_factory=dict)
    extra_params: dict[str, Any] = field(default_factory=dict)
    profile: str | None = None

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_spec(cls, spec: str, **overrides: Any) -> AdapterConfig:
        """Parse a spec string into an AdapterConfig.

        Spec format::

            provider/model_id[@base_url_or_region][#profile]

        Examples::

            "openai/gpt-4o"
            "ollama/llama3:8b"
            "ollama/llama3:70b@http://remote:11434"
            "bedrock/meta.llama3-70b-instruct-v1:0@us-west-2"
            "azure/gpt-4o#my-azure-prod"
            "rest/my-model@http://my-api.com/v1/chat"

        The ``@`` segment is treated as a *region* when the provider is
        ``bedrock``, and as a *base_url* for every other provider.

        Args:
            spec: The spec string to parse.
            **overrides: Any AdapterConfig field can be overridden here.

        Returns:
            A populated AdapterConfig.

        Raises:
            ValueError: If the spec string is missing the provider/model separator.
        """
        # Strip optional profile suffix (#profile)
        profile: str | None = None
        if "#" in spec:
            spec, profile = spec.rsplit("#", 1)
            profile = profile.strip() or None

        # Split off optional @url-or-region
        base_url: str | None = None
        region: str | None = None
        if "@" in spec:
            spec, at_value = spec.split("@", 1)
            at_value = at_value.strip()
            # Detect provider before we know it's bedrock, so peek ahead
            provider_peek = spec.split("/", 1)[0].lower() if "/" in spec else ""
            if provider_peek == "bedrock":
                region = at_value
            else:
                base_url = at_value

        # Split provider / model
        if "/" not in spec:
            raise ValueError(
                f"Invalid spec '{spec}': expected 'provider/model_id' format."
            )
        provider, model_id = spec.split("/", 1)
        provider = provider.strip().lower()
        model_id = model_id.strip()

        config = cls(
            provider=provider,
            model=model_id,
            base_url=base_url,
            region=region,
            profile=profile,
        )
        # Apply caller overrides
        for key, value in overrides.items():
            if hasattr(config, key):
                setattr(config, key, value)
            else:
                raise ValueError(f"AdapterConfig has no field '{key}'.")
        return config

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AdapterConfig:
        """Validate and build from a raw dict (from YAML config, CLI args, etc.).

        Args:
            d: A dict that must contain at least ``provider`` and ``model``.

        Returns:
            A populated AdapterConfig.

        Raises:
            ValueError: If required keys are missing or a value has the wrong type.
        """
        d = dict(d)  # copy so we don't mutate caller's dict

        for required in ("provider", "model"):
            if required not in d:
                raise ValueError(
                    f"AdapterConfig.from_dict: missing required key '{required}'."
                )

        known_fields = {
            "provider", "model", "base_url", "api_key_env", "region",
            "deployment_name", "timeout", "max_retries", "temperature",
            "max_tokens", "extra_headers", "extra_params", "profile",
        }

        kwargs: dict[str, Any] = {}
        extra_params: dict[str, Any] = dict(d.get("extra_params", {}))

        for key, value in d.items():
            if key in known_fields:
                kwargs[key] = value
            else:
                # Unknown keys go to extra_params
                extra_params[key] = value

        if extra_params:
            kwargs["extra_params"] = extra_params

        # Type coercions
        if "timeout" in kwargs:
            kwargs["timeout"] = float(kwargs["timeout"])
        if "max_retries" in kwargs:
            kwargs["max_retries"] = int(kwargs["max_retries"])
        if "temperature" in kwargs:
            kwargs["temperature"] = float(kwargs["temperature"])
        if "max_tokens" in kwargs:
            kwargs["max_tokens"] = int(kwargs["max_tokens"])

        return cls(**kwargs)

    # ------------------------------------------------------------------
    # Conversion helpers
    # ------------------------------------------------------------------

    def to_provider_config(self) -> dict[str, Any]:
        """Convert to the dict format each adapter's ``from_config()`` expects.

        Returns:
            A flat dict ready to pass directly to ``SomeAdapter.from_config()``.
        """
        cfg: dict[str, Any] = {
            "model": self.model,
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if self.base_url is not None:
            cfg["base_url"] = self.base_url
        if self.api_key_env is not None:
            cfg["api_key_env"] = self.api_key_env
        if self.region is not None:
            cfg["region"] = self.region
        if self.deployment_name is not None:
            cfg["deployment"] = self.deployment_name
        if self.extra_headers:
            cfg["extra_headers"] = self.extra_headers
        cfg.update(self.extra_params)
        return cfg


__all__ = ["AdapterConfig"]
