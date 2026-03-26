"""Model catalog: ModelSpec dataclass and MODEL_CATALOG registry.

Covers every major model across OpenAI, Anthropic, Google Gemini,
AWS Bedrock (all families), Azure OpenAI, Mistral, and Ollama.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


@dataclass
class ModelSpec:
    """Specification for a single LLM model."""

    provider: str
    model_id: str
    display_name: str
    context_window: int
    max_output_tokens: int
    supports_system_prompt: bool
    supports_vision: bool
    supports_function_calling: bool
    input_cost_per_1k: float | None  # USD; None = free/unknown
    output_cost_per_1k: float | None
    rate_limit_rpm: int | None  # None = unknown
    tags: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)

    @property
    def spec_string(self) -> str:
        """Return canonical spec string, e.g. 'openai/gpt-4o'."""
        return f"{self.provider}/{self.model_id}"


# ---------------------------------------------------------------------------
# Bedrock family detection
# ---------------------------------------------------------------------------


class BedrockModelFamily(str, Enum):
    """Model families hosted on AWS Bedrock, each with a different body format."""

    ANTHROPIC = "anthropic"
    META_LLAMA = "meta_llama"
    MISTRAL = "mistral"
    AMAZON_TITAN = "amazon_titan"
    COHERE = "cohere"
    AI21 = "ai21"


def get_bedrock_family(model_id: str) -> BedrockModelFamily:
    """Detect the Bedrock model family from a model ID prefix.

    Args:
        model_id: Bedrock model ID such as 'anthropic.claude-3-5-sonnet-20241022-v2:0'.

    Returns:
        The matching BedrockModelFamily enum value.

    Raises:
        ValueError: If the model ID doesn't match any known family.
    """
    lower = model_id.lower()
    if lower.startswith("anthropic."):
        return BedrockModelFamily.ANTHROPIC
    if lower.startswith("meta."):
        return BedrockModelFamily.META_LLAMA
    if lower.startswith("mistral."):
        return BedrockModelFamily.MISTRAL
    if lower.startswith("amazon."):
        return BedrockModelFamily.AMAZON_TITAN
    if lower.startswith("cohere."):
        return BedrockModelFamily.COHERE
    if lower.startswith("ai21."):
        return BedrockModelFamily.AI21
    raise ValueError(
        f"Unknown Bedrock model family for model_id '{model_id}'. "
        "Supported prefixes: anthropic., meta., mistral., amazon., cohere., ai21."
    )


# ---------------------------------------------------------------------------
# MODEL_CATALOG
# ---------------------------------------------------------------------------

def _spec(  # noqa: PLR0913
    provider: str,
    model_id: str,
    display_name: str,
    context_window: int,
    max_output_tokens: int,
    supports_system_prompt: bool = True,
    supports_vision: bool = False,
    supports_function_calling: bool = False,
    input_cost_per_1k: float | None = None,
    output_cost_per_1k: float | None = None,
    rate_limit_rpm: int | None = None,
    tags: list[str] | None = None,
    aliases: list[str] | None = None,
) -> tuple[str, ModelSpec]:
    """Build a (key, ModelSpec) tuple for MODEL_CATALOG."""
    ms = ModelSpec(
        provider=provider,
        model_id=model_id,
        display_name=display_name,
        context_window=context_window,
        max_output_tokens=max_output_tokens,
        supports_system_prompt=supports_system_prompt,
        supports_vision=supports_vision,
        supports_function_calling=supports_function_calling,
        input_cost_per_1k=input_cost_per_1k,
        output_cost_per_1k=output_cost_per_1k,
        rate_limit_rpm=rate_limit_rpm,
        tags=tags or [],
        aliases=aliases or [],
    )
    return ms.spec_string, ms


MODEL_CATALOG: dict[str, ModelSpec] = dict(
    [
        # ---------------------------------------------------------------
        # OpenAI
        # ---------------------------------------------------------------
        _spec(
            "openai", "gpt-4o", "GPT-4o",
            context_window=128_000, max_output_tokens=16_384,
            supports_vision=True, supports_function_calling=True,
            input_cost_per_1k=0.005, output_cost_per_1k=0.015,
            rate_limit_rpm=500,
            tags=["chat", "vision", "function-calling", "latest"],
            aliases=["gpt4o", "gpt-4o-latest"],
        ),
        _spec(
            "openai", "gpt-4o-mini", "GPT-4o Mini",
            context_window=128_000, max_output_tokens=16_384,
            supports_vision=True, supports_function_calling=True,
            input_cost_per_1k=0.00015, output_cost_per_1k=0.0006,
            rate_limit_rpm=500,
            tags=["chat", "vision", "function-calling", "cheap"],
            aliases=["gpt4o-mini"],
        ),
        _spec(
            "openai", "gpt-4-turbo", "GPT-4 Turbo",
            context_window=128_000, max_output_tokens=4_096,
            supports_vision=True, supports_function_calling=True,
            input_cost_per_1k=0.01, output_cost_per_1k=0.03,
            rate_limit_rpm=500,
            tags=["chat", "vision", "function-calling"],
            aliases=["gpt4-turbo"],
        ),
        _spec(
            "openai", "gpt-3.5-turbo", "GPT-3.5 Turbo",
            context_window=16_385, max_output_tokens=4_096,
            supports_function_calling=True,
            input_cost_per_1k=0.0005, output_cost_per_1k=0.0015,
            rate_limit_rpm=3_500,
            tags=["chat", "function-calling", "cheap"],
            aliases=["gpt35", "gpt-3.5"],
        ),
        _spec(
            "openai", "o1", "o1",
            context_window=200_000, max_output_tokens=100_000,
            supports_vision=True,
            input_cost_per_1k=0.015, output_cost_per_1k=0.06,
            rate_limit_rpm=500,
            tags=["reasoning", "latest"],
            aliases=["o1-latest"],
        ),
        _spec(
            "openai", "o1-mini", "o1 Mini",
            context_window=128_000, max_output_tokens=65_536,
            input_cost_per_1k=0.003, output_cost_per_1k=0.012,
            rate_limit_rpm=500,
            tags=["reasoning", "cheap"],
            aliases=[],
        ),
        _spec(
            "openai", "o3-mini", "o3 Mini",
            context_window=200_000, max_output_tokens=100_000,
            supports_function_calling=True,
            input_cost_per_1k=0.0011, output_cost_per_1k=0.0044,
            rate_limit_rpm=500,
            tags=["reasoning", "cheap", "latest"],
            aliases=[],
        ),
        # ---------------------------------------------------------------
        # Anthropic
        # ---------------------------------------------------------------
        _spec(
            "anthropic", "claude-3-5-sonnet-20241022", "Claude 3.5 Sonnet",
            context_window=200_000, max_output_tokens=8_192,
            supports_vision=True, supports_function_calling=True,
            input_cost_per_1k=0.003, output_cost_per_1k=0.015,
            rate_limit_rpm=1_000,
            tags=["chat", "vision", "function-calling", "latest"],
            aliases=["claude-3.5-sonnet", "claude-3-5-sonnet", "sonnet-3-5"],
        ),
        _spec(
            "anthropic", "claude-3-5-haiku-20241022", "Claude 3.5 Haiku",
            context_window=200_000, max_output_tokens=8_192,
            supports_vision=True, supports_function_calling=True,
            input_cost_per_1k=0.0008, output_cost_per_1k=0.004,
            rate_limit_rpm=1_000,
            tags=["chat", "function-calling", "cheap", "latest"],
            aliases=["claude-3.5-haiku", "claude-3-5-haiku", "haiku-3-5"],
        ),
        _spec(
            "anthropic", "claude-3-opus-20240229", "Claude 3 Opus",
            context_window=200_000, max_output_tokens=4_096,
            supports_vision=True, supports_function_calling=True,
            input_cost_per_1k=0.015, output_cost_per_1k=0.075,
            rate_limit_rpm=1_000,
            tags=["chat", "vision", "function-calling", "powerful"],
            aliases=["claude-3-opus", "opus"],
        ),
        _spec(
            "anthropic", "claude-3-sonnet-20240229", "Claude 3 Sonnet",
            context_window=200_000, max_output_tokens=4_096,
            supports_vision=True, supports_function_calling=True,
            input_cost_per_1k=0.003, output_cost_per_1k=0.015,
            rate_limit_rpm=1_000,
            tags=["chat", "vision", "function-calling"],
            aliases=["claude-3-sonnet", "sonnet"],
        ),
        _spec(
            "anthropic", "claude-3-haiku-20240307", "Claude 3 Haiku",
            context_window=200_000, max_output_tokens=4_096,
            supports_vision=True, supports_function_calling=True,
            input_cost_per_1k=0.00025, output_cost_per_1k=0.00125,
            rate_limit_rpm=1_000,
            tags=["chat", "cheap", "function-calling"],
            aliases=["claude-3-haiku", "haiku"],
        ),
        # ---------------------------------------------------------------
        # Google Gemini
        # ---------------------------------------------------------------
        _spec(
            "gemini", "gemini-1.5-pro", "Gemini 1.5 Pro",
            context_window=2_000_000, max_output_tokens=8_192,
            supports_vision=True, supports_function_calling=True,
            input_cost_per_1k=0.00125, output_cost_per_1k=0.005,
            rate_limit_rpm=360,
            tags=["chat", "vision", "function-calling", "long-context"],
            aliases=["gemini-pro-1.5"],
        ),
        _spec(
            "gemini", "gemini-1.5-flash", "Gemini 1.5 Flash",
            context_window=1_000_000, max_output_tokens=8_192,
            supports_vision=True, supports_function_calling=True,
            input_cost_per_1k=0.000075, output_cost_per_1k=0.0003,
            rate_limit_rpm=1_000,
            tags=["chat", "vision", "function-calling", "cheap"],
            aliases=["gemini-flash-1.5"],
        ),
        _spec(
            "gemini", "gemini-2.0-flash", "Gemini 2.0 Flash",
            context_window=1_000_000, max_output_tokens=8_192,
            supports_vision=True, supports_function_calling=True,
            input_cost_per_1k=0.0001, output_cost_per_1k=0.0004,
            rate_limit_rpm=2_000,
            tags=["chat", "vision", "function-calling", "latest"],
            aliases=["gemini-flash-2.0", "gemini-2-flash"],
        ),
        _spec(
            "gemini", "gemini-2.0-flash-lite", "Gemini 2.0 Flash Lite",
            context_window=1_000_000, max_output_tokens=8_192,
            supports_vision=True,
            input_cost_per_1k=0.000075, output_cost_per_1k=0.0003,
            rate_limit_rpm=4_000,
            tags=["chat", "vision", "cheap", "latest"],
            aliases=["gemini-flash-lite-2.0"],
        ),
        # ---------------------------------------------------------------
        # AWS Bedrock — Anthropic
        # ---------------------------------------------------------------
        _spec(
            "bedrock", "anthropic.claude-3-5-sonnet-20241022-v2:0",
            "Claude 3.5 Sonnet (Bedrock)",
            context_window=200_000, max_output_tokens=8_192,
            supports_vision=True, supports_function_calling=True,
            input_cost_per_1k=0.003, output_cost_per_1k=0.015,
            tags=["chat", "vision", "function-calling", "bedrock", "anthropic-family"],
            aliases=["bedrock/claude-3.5-sonnet"],
        ),
        _spec(
            "bedrock", "anthropic.claude-3-opus-20240229-v1:0",
            "Claude 3 Opus (Bedrock)",
            context_window=200_000, max_output_tokens=4_096,
            supports_vision=True, supports_function_calling=True,
            input_cost_per_1k=0.015, output_cost_per_1k=0.075,
            tags=["chat", "vision", "bedrock", "anthropic-family"],
            aliases=["bedrock/claude-3-opus"],
        ),
        _spec(
            "bedrock", "anthropic.claude-3-haiku-20240307-v1:0",
            "Claude 3 Haiku (Bedrock)",
            context_window=200_000, max_output_tokens=4_096,
            supports_vision=True, supports_function_calling=True,
            input_cost_per_1k=0.00025, output_cost_per_1k=0.00125,
            tags=["chat", "cheap", "bedrock", "anthropic-family"],
            aliases=["bedrock/claude-3-haiku"],
        ),
        # ---------------------------------------------------------------
        # AWS Bedrock — Meta Llama
        # ---------------------------------------------------------------
        _spec(
            "bedrock", "meta.llama3-70b-instruct-v1:0",
            "Llama 3 70B Instruct (Bedrock)",
            context_window=8_192, max_output_tokens=8_192,
            input_cost_per_1k=0.00265, output_cost_per_1k=0.0035,
            tags=["chat", "instruct", "bedrock", "meta-llama-family"],
            aliases=["bedrock/llama3-70b"],
        ),
        _spec(
            "bedrock", "meta.llama3-8b-instruct-v1:0",
            "Llama 3 8B Instruct (Bedrock)",
            context_window=8_192, max_output_tokens=8_192,
            input_cost_per_1k=0.0003, output_cost_per_1k=0.0006,
            tags=["chat", "instruct", "cheap", "bedrock", "meta-llama-family"],
            aliases=["bedrock/llama3-8b"],
        ),
        _spec(
            "bedrock", "meta.llama3-1-405b-instruct-v1:0",
            "Llama 3.1 405B Instruct (Bedrock)",
            context_window=128_000, max_output_tokens=8_192,
            input_cost_per_1k=0.00532, output_cost_per_1k=0.016,
            tags=["chat", "instruct", "powerful", "bedrock", "meta-llama-family"],
            aliases=["bedrock/llama3-405b"],
        ),
        # ---------------------------------------------------------------
        # AWS Bedrock — Mistral
        # ---------------------------------------------------------------
        _spec(
            "bedrock", "mistral.mistral-large-2402-v1:0",
            "Mistral Large (Bedrock)",
            context_window=32_000, max_output_tokens=8_192,
            supports_function_calling=True,
            input_cost_per_1k=0.004, output_cost_per_1k=0.012,
            tags=["chat", "bedrock", "mistral-family"],
            aliases=["bedrock/mistral-large"],
        ),
        _spec(
            "bedrock", "mistral.mixtral-8x7b-instruct-v0:1",
            "Mixtral 8x7B Instruct (Bedrock)",
            context_window=32_000, max_output_tokens=4_096,
            input_cost_per_1k=0.00045, output_cost_per_1k=0.0007,
            tags=["chat", "instruct", "cheap", "bedrock", "mistral-family"],
            aliases=["bedrock/mixtral-8x7b"],
        ),
        # ---------------------------------------------------------------
        # AWS Bedrock — Amazon Titan
        # ---------------------------------------------------------------
        _spec(
            "bedrock", "amazon.titan-text-premier-v1:0",
            "Amazon Titan Text Premier (Bedrock)",
            context_window=32_000, max_output_tokens=3_072,
            input_cost_per_1k=0.0008, output_cost_per_1k=0.0024,
            tags=["chat", "bedrock", "amazon-titan-family"],
            aliases=["bedrock/titan-premier"],
        ),
        _spec(
            "bedrock", "amazon.titan-text-express-v1",
            "Amazon Titan Text Express (Bedrock)",
            context_window=8_192, max_output_tokens=8_192,
            input_cost_per_1k=0.0002, output_cost_per_1k=0.0006,
            tags=["chat", "cheap", "bedrock", "amazon-titan-family"],
            aliases=["bedrock/titan-express"],
        ),
        # ---------------------------------------------------------------
        # AWS Bedrock — Cohere
        # ---------------------------------------------------------------
        _spec(
            "bedrock", "cohere.command-r-plus-v1:0",
            "Cohere Command R+ (Bedrock)",
            context_window=128_000, max_output_tokens=4_096,
            supports_function_calling=True,
            input_cost_per_1k=0.003, output_cost_per_1k=0.015,
            tags=["chat", "rag", "bedrock", "cohere-family"],
            aliases=["bedrock/command-r-plus"],
        ),
        _spec(
            "bedrock", "cohere.command-r-v1:0",
            "Cohere Command R (Bedrock)",
            context_window=128_000, max_output_tokens=4_096,
            supports_function_calling=True,
            input_cost_per_1k=0.0005, output_cost_per_1k=0.0015,
            tags=["chat", "rag", "cheap", "bedrock", "cohere-family"],
            aliases=["bedrock/command-r"],
        ),
        # ---------------------------------------------------------------
        # AWS Bedrock — AI21
        # ---------------------------------------------------------------
        _spec(
            "bedrock", "ai21.jamba-1-5-large-v1:0",
            "AI21 Jamba 1.5 Large (Bedrock)",
            context_window=256_000, max_output_tokens=4_096,
            input_cost_per_1k=0.002, output_cost_per_1k=0.008,
            tags=["chat", "bedrock", "ai21-family"],
            aliases=["bedrock/jamba-1-5-large"],
        ),
        # ---------------------------------------------------------------
        # Azure OpenAI
        # ---------------------------------------------------------------
        _spec(
            "azure", "gpt-4o", "GPT-4o (Azure)",
            context_window=128_000, max_output_tokens=16_384,
            supports_vision=True, supports_function_calling=True,
            input_cost_per_1k=0.005, output_cost_per_1k=0.015,
            tags=["chat", "vision", "function-calling", "azure"],
            aliases=["azure/gpt-4o"],
        ),
        _spec(
            "azure", "gpt-4-turbo", "GPT-4 Turbo (Azure)",
            context_window=128_000, max_output_tokens=4_096,
            supports_vision=True, supports_function_calling=True,
            input_cost_per_1k=0.01, output_cost_per_1k=0.03,
            tags=["chat", "vision", "function-calling", "azure"],
            aliases=["azure/gpt-4-turbo"],
        ),
        # ---------------------------------------------------------------
        # Mistral (direct API)
        # ---------------------------------------------------------------
        _spec(
            "mistral", "mistral-large-latest", "Mistral Large (Latest)",
            context_window=128_000, max_output_tokens=8_192,
            supports_function_calling=True,
            input_cost_per_1k=0.002, output_cost_per_1k=0.006,
            rate_limit_rpm=60,
            tags=["chat", "function-calling", "latest"],
            aliases=["mistral-large"],
        ),
        _spec(
            "mistral", "mistral-small-latest", "Mistral Small (Latest)",
            context_window=32_000, max_output_tokens=8_192,
            supports_function_calling=True,
            input_cost_per_1k=0.0002, output_cost_per_1k=0.0006,
            rate_limit_rpm=60,
            tags=["chat", "cheap", "latest"],
            aliases=["mistral-small"],
        ),
        _spec(
            "mistral", "codestral-latest", "Codestral (Latest)",
            context_window=32_000, max_output_tokens=8_192,
            input_cost_per_1k=0.001, output_cost_per_1k=0.003,
            rate_limit_rpm=60,
            tags=["code", "latest"],
            aliases=["codestral"],
        ),
        _spec(
            "mistral", "open-mixtral-8x22b", "Mixtral 8x22B",
            context_window=64_000, max_output_tokens=8_192,
            supports_function_calling=True,
            input_cost_per_1k=0.002, output_cost_per_1k=0.006,
            rate_limit_rpm=60,
            tags=["chat", "function-calling", "powerful"],
            aliases=["mixtral-8x22b"],
        ),
        # ---------------------------------------------------------------
        # Ollama (local — no cost)
        # ---------------------------------------------------------------
        _spec(
            "ollama", "llama3.2", "Llama 3.2",
            context_window=128_000, max_output_tokens=4_096,
            input_cost_per_1k=0.0, output_cost_per_1k=0.0,
            tags=["chat", "local", "free"],
            aliases=["llama3.2"],
        ),
        _spec(
            "ollama", "llama3.1", "Llama 3.1",
            context_window=128_000, max_output_tokens=4_096,
            input_cost_per_1k=0.0, output_cost_per_1k=0.0,
            tags=["chat", "local", "free"],
            aliases=["llama3.1"],
        ),
        _spec(
            "ollama", "llama3", "Llama 3",
            context_window=8_192, max_output_tokens=4_096,
            input_cost_per_1k=0.0, output_cost_per_1k=0.0,
            tags=["chat", "local", "free"],
            aliases=["llama3", "llama-3"],
        ),
        _spec(
            "ollama", "mistral", "Mistral (Ollama)",
            context_window=32_768, max_output_tokens=4_096,
            input_cost_per_1k=0.0, output_cost_per_1k=0.0,
            tags=["chat", "local", "free"],
            aliases=[],
        ),
        _spec(
            "ollama", "mixtral", "Mixtral (Ollama)",
            context_window=32_768, max_output_tokens=4_096,
            input_cost_per_1k=0.0, output_cost_per_1k=0.0,
            tags=["chat", "local", "free"],
            aliases=[],
        ),
        _spec(
            "ollama", "codellama", "Code Llama (Ollama)",
            context_window=16_384, max_output_tokens=4_096,
            input_cost_per_1k=0.0, output_cost_per_1k=0.0,
            tags=["code", "local", "free"],
            aliases=[],
        ),
        _spec(
            "ollama", "qwen2.5", "Qwen 2.5 (Ollama)",
            context_window=32_768, max_output_tokens=4_096,
            input_cost_per_1k=0.0, output_cost_per_1k=0.0,
            tags=["chat", "local", "free"],
            aliases=[],
        ),
        _spec(
            "ollama", "gemma2", "Gemma 2 (Ollama)",
            context_window=8_192, max_output_tokens=4_096,
            input_cost_per_1k=0.0, output_cost_per_1k=0.0,
            tags=["chat", "local", "free"],
            aliases=[],
        ),
        _spec(
            "ollama", "phi3.5", "Phi-3.5 (Ollama)",
            context_window=128_000, max_output_tokens=4_096,
            input_cost_per_1k=0.0, output_cost_per_1k=0.0,
            tags=["chat", "local", "free", "small"],
            aliases=[],
        ),
        _spec(
            "ollama", "deepseek-r1", "DeepSeek R1 (Ollama)",
            context_window=65_536, max_output_tokens=8_192,
            input_cost_per_1k=0.0, output_cost_per_1k=0.0,
            tags=["reasoning", "local", "free"],
            aliases=[],
        ),
        _spec(
            "ollama", "llava", "LLaVA (Ollama)",
            context_window=4_096, max_output_tokens=4_096,
            supports_vision=True,
            input_cost_per_1k=0.0, output_cost_per_1k=0.0,
            tags=["vision", "local", "free"],
            aliases=[],
        ),
    ]
)

# ---------------------------------------------------------------------------
# Alias index — built once at import time
# ---------------------------------------------------------------------------

_ALIAS_INDEX: dict[str, str] = {}
for _key, _ms in MODEL_CATALOG.items():
    for _alias in _ms.aliases:
        _ALIAS_INDEX[_alias.lower()] = _key


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def get_model(spec: str) -> ModelSpec | None:
    """Look up a ModelSpec by spec string (e.g. 'openai/gpt-4o').

    Also resolves aliases.

    Args:
        spec: A canonical spec string or a known alias.

    Returns:
        ModelSpec if found, else None.
    """
    if spec in MODEL_CATALOG:
        return MODEL_CATALOG[spec]
    # Try alias resolution
    resolved = resolve_alias(spec)
    if resolved:
        return MODEL_CATALOG.get(resolved)
    return None


def list_models(provider: str | None = None) -> list[ModelSpec]:
    """Return all known models, optionally filtered by provider.

    Args:
        provider: If given, only models for this provider are returned.

    Returns:
        List of ModelSpec objects.
    """
    if provider is None:
        return list(MODEL_CATALOG.values())
    return [ms for ms in MODEL_CATALOG.values() if ms.provider == provider]


def resolve_alias(alias: str) -> str | None:
    """Resolve a short alias to a canonical spec string.

    Args:
        alias: A short name such as 'claude-3.5' or 'gpt4o'.

    Returns:
        Canonical spec string (e.g. 'anthropic/claude-3-5-sonnet-20241022') or None.
    """
    return _ALIAS_INDEX.get(alias.lower())


def search_models(query: str) -> list[ModelSpec]:
    """Fuzzy-search models by display name, model ID, tag, or alias.

    The search is case-insensitive and returns models whose display_name,
    model_id, tags, or aliases contain the query string.

    Args:
        query: Search term.

    Returns:
        List of matching ModelSpec objects, ordered by how early the match
        appears in the display_name (earlier = higher rank).
    """
    q = query.lower()
    results: list[tuple[int, ModelSpec]] = []
    for ms in MODEL_CATALOG.values():
        haystack = " ".join(
            [ms.display_name, ms.model_id, ms.provider] + ms.tags + ms.aliases
        ).lower()
        idx = haystack.find(q)
        if idx >= 0:
            results.append((idx, ms))
    results.sort(key=lambda t: t[0])
    return [ms for _, ms in results]


__all__ = [
    "BedrockModelFamily",
    "MODEL_CATALOG",
    "ModelSpec",
    "get_bedrock_family",
    "get_model",
    "list_models",
    "resolve_alias",
    "search_models",
]


# Satisfy type checker — _spec is used only at module level
_spec_return: Any = None  # noqa: F841
