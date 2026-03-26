"""HuggingFace adapter — works with any of the millions of models on the Hub.

Modes
─────
inference_api   Default. Serverless Inference API — any public model works.
                Requires HF_TOKEN for gated models and higher rate limits.
                Automatically detects the right API path for each model and
                falls back through the full strategy chain if needed.

endpoint        Dedicated Inference Endpoint (your own hosted URL).
                Set base_url to your endpoint URL.
                Auto-detected when base_url looks like an HF endpoint URL.

tgi             Text Generation Inference server (self-hosted or HF-hosted).
                OpenAI-compatible — works with any TGI ≥ 2.0 deployment.
                Set base_url to http://your-tgi-host:8080.

local           Run directly via transformers + torch on this machine.
                No network call, no API key. Requires:
                  pip install "redforge[huggingface-local]"

Strategy fallback chain (inference_api only)
────────────────────────────────────────────
For any model, the adapter automatically walks this chain until one works:

  1. chat_completion   — OpenAI-compat Messages API (95%+ of modern models)
  2. text_generation   — Raw prompt, non-chat base / instruct models
  3. text2text         — Encoder-decoder: T5, BART, Flan-T5, mT5, NLLB…
  4. conversational    — Legacy HF dialog pipeline (BlenderBot, etc.)

The winning strategy is cached per model_id with a 1-hour TTL, so
every subsequent call on the same model skips detection entirely.

On first call for an unknown model, a lightweight HF Hub API lookup
(GET /api/models/{id}?fields=pipeline_tag, 5 s timeout) retrieves the
authoritative pipeline_tag and pre-selects the best starting point —
reducing fallback attempts on exotic models.

No catalog entry is needed. Any model ID that resolves on HuggingFace
Hub (public or private with HF_TOKEN) will work.

Env vars
────────
HF_TOKEN        HuggingFace API token. Required for:
                  - Gated models (Llama, Gemma, Mistral, etc.)
                  - Private models / Inference Endpoints
                  - Higher rate limits on Inference API
                Get yours at https://huggingface.co/settings/tokens

Usage examples
──────────────
  # Any public model — no catalog entry needed
  AdapterFactory.from_spec("huggingface/mistralai/Mistral-7B-Instruct-v0.3")
  AdapterFactory.from_spec("huggingface/google/flan-t5-large")
  AdapterFactory.from_spec("huggingface/facebook/blenderbot-400M-distill")

  # Gated model (needs HF_TOKEN)
  AdapterFactory.from_spec("huggingface/meta-llama/Meta-Llama-3.1-8B-Instruct")

  # Your Inference Endpoint (auto-detected from URL, or set mode=endpoint)
  AdapterFactory.from_spec("huggingface/my-model@https://xyz.us-east-1.aws.endpoints.huggingface.cloud")

  # Self-hosted TGI
  AdapterFactory.from_spec("huggingface/tgi@http://my-tgi-server:8080")

  # Local — downloads model weights, zero network during scan
  AdapterFactory.from_dict({"provider": "huggingface", "model": "microsoft/Phi-3.5-mini-instruct", "mode": "local"})
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from redforge.adapters.base import AdapterResponse, BaseAdapter
from redforge.utils.rate_limiter import with_retry
from redforge.utils.secrets import get_secret

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Strategy constants
# ---------------------------------------------------------------------------

_STRAT_CHAT          = "chat_completion"
_STRAT_TEXT_GEN      = "text_generation"
_STRAT_TEXT2TEXT     = "text2text_generation"
_STRAT_CONVERSATIONAL = "conversational"

# Ordered fallback chain for inference_api mode.
# Every model will be tried against each strategy until one responds.
_FALLBACK_CHAIN: list[str] = [
    _STRAT_CHAT,
    _STRAT_TEXT_GEN,
    _STRAT_TEXT2TEXT,
    _STRAT_CONVERSATIONAL,
]

# HuggingFace pipeline_tag → best initial strategy.
# "Best" = the one most likely to succeed on first attempt given the tag.
# If the initial strategy fails, the waterfall still tries the rest.
_TAG_TO_STRATEGY: dict[str, str] = {
    "text-generation":              _STRAT_CHAT,         # try chat first, fallback to text_gen
    "text2text-generation":         _STRAT_TEXT2TEXT,    # T5, BART, Flan-T5
    "conversational":               _STRAT_CHAT,         # modern HF uses chat API
    "summarization":                _STRAT_TEXT2TEXT,    # seq2seq, repurpose input as prompt
    "translation":                  _STRAT_TEXT2TEXT,    # seq2seq
    "question-answering":           _STRAT_TEXT_GEN,     # extractive QA — use text_gen
    "fill-mask":                    _STRAT_TEXT_GEN,     # BERT-style — text_gen as fallback
    "feature-extraction":           _STRAT_TEXT_GEN,     # embedding model — text_gen last resort
    "image-to-text":                _STRAT_CHAT,         # multimodal — try chat
    "visual-question-answering":    _STRAT_CHAT,         # multimodal
    "document-question-answering":  _STRAT_CHAT,
    "zero-shot-classification":     _STRAT_TEXT_GEN,
    "text-classification":          _STRAT_TEXT_GEN,
    "token-classification":         _STRAT_TEXT_GEN,
    "automatic-speech-recognition": _STRAT_TEXT_GEN,    # ASR — text fallback
}

# Signals that indicate the model doesn't support THIS strategy path —
# should skip to next strategy, NOT retry.
_STRATEGY_SKIP_SIGNALS: frozenset[str] = frozenset([
    "422", "400",
    "not supported", "unsupported",
    "unknown task", "no pipeline",
    "does not support", "not available",
    "badrequest", "unprocessable entity",
    "task is not supported",
])

# Signals that indicate a transient condition — retry same strategy, NOT skip.
_TRANSIENT_SIGNALS: frozenset[str] = frozenset([
    "429", "503", "502", "500",
    "model is currently loading",
    "timeout", "timed out",
    "unavailable", "overloaded",
    "connection", "read error",
])

# ---------------------------------------------------------------------------
# Module-level strategy cache (shared across all HuggingFaceAdapter instances)
# ---------------------------------------------------------------------------
# model_id → (winning_strategy, monotonic_timestamp)
_strategy_cache: dict[str, tuple[str, float]] = {}
_STRATEGY_TTL = 3600.0  # 1 hour


def _cache_get(model_id: str) -> str | None:
    entry = _strategy_cache.get(model_id)
    if entry and (time.monotonic() - entry[1]) < _STRATEGY_TTL:
        return entry[0]
    return None


def _cache_set(model_id: str, strategy: str) -> None:
    _strategy_cache[model_id] = (strategy, time.monotonic())


def clear_strategy_cache() -> None:
    """Clear the module-level strategy cache. Useful in tests."""
    _strategy_cache.clear()


# ---------------------------------------------------------------------------
# Hub capability probe
# ---------------------------------------------------------------------------

async def _fetch_pipeline_tag(model_id: str, token: str | None) -> str | None:
    """Fetch the authoritative pipeline_tag from HF Hub API.

    Uses httpx (already a core redforge dependency).
    Never raises — returns None if Hub is unreachable or model unknown.
    Timeout is deliberately short (5 s) so it never blocks a scan.
    """
    import httpx  # already in core deps

    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    url = f"https://huggingface.co/api/models/{model_id}?fields=pipeline_tag"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url, headers=headers)
        if resp.status_code == 200:
            tag = resp.json().get("pipeline_tag")
            if tag:
                logger.debug("HF Hub pipeline_tag for %s: %s", model_id, tag)
            return tag
        if resp.status_code == 404:
            logger.debug("HF Hub: model %s not found (404)", model_id)
        # Any other status: fall through to None
    except Exception as exc:  # noqa: BLE001
        logger.debug("HF Hub lookup failed for %s: %s", model_id, exc)
    return None


def _strategy_from_tag(pipeline_tag: str | None) -> str:
    """Map a pipeline_tag to the best initial strategy. Defaults to chat."""
    if pipeline_tag is None:
        # Unknown tag: default to chat (most models on Hub support it)
        return _STRAT_CHAT
    return _TAG_TO_STRATEGY.get(pipeline_tag, _STRAT_CHAT)


def _fallback_chain_from(initial: str) -> list[str]:
    """Return the full fallback chain starting at the given strategy."""
    try:
        idx = _FALLBACK_CHAIN.index(initial)
        return _FALLBACK_CHAIN[idx:]
    except ValueError:
        return list(_FALLBACK_CHAIN)  # Unknown strategy: try all


# ---------------------------------------------------------------------------
# Error classification
# ---------------------------------------------------------------------------

def _is_strategy_error(exc: Exception) -> bool:
    """Return True if the error means 'this strategy is wrong for the model'.

    Returns False for transient errors (rate limit, timeout, server down)
    which should be retried on the same strategy.
    """
    msg = str(exc).lower()
    # Transient conditions take priority — do NOT switch strategies
    if any(sig in msg for sig in _TRANSIENT_SIGNALS):
        return False
    return any(sig in msg for sig in _STRATEGY_SKIP_SIGNALS)


# ---------------------------------------------------------------------------
# Prompt formatting
# ---------------------------------------------------------------------------

def _build_prompt(
    messages: list[dict[str, str]],
    system_prompt: str | None,
) -> str:
    """Simple prompt for non-chat text_generation models."""
    parts: list[str] = []
    if system_prompt:
        parts.append(f"System: {system_prompt}\n")
    for msg in messages:
        role = msg.get("role", "user").capitalize()
        content = msg.get("content", "")
        parts.append(f"{role}: {content}")
    parts.append("Assistant:")
    return "\n".join(parts)


def _build_text2text_input(
    messages: list[dict[str, str]],
    system_prompt: str | None,
) -> str:
    """Flatten to a single string for encoder-decoder (T5/BART) models."""
    parts: list[str] = []
    if system_prompt:
        parts.append(system_prompt)
    for msg in messages:
        if msg.get("role") == "user":
            parts.append(msg.get("content", ""))
    return " ".join(filter(None, parts))


# ---------------------------------------------------------------------------
# Mode auto-detection helpers
# ---------------------------------------------------------------------------

def _detect_mode(mode: str, base_url: str | None) -> str:
    """Infer mode from base_url when mode is still the default."""
    if mode != "inference_api" or not base_url:
        return mode
    url_lower = base_url.lower()
    # HF Dedicated Inference Endpoints always contain this domain
    if "endpoints.huggingface.cloud" in url_lower:
        return "endpoint"
    # TGI deployments typically listen on :8080
    if ":8080" in url_lower:
        return "tgi"
    # Any other explicit URL is treated as a dedicated endpoint
    return "endpoint"


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

class HuggingFaceAdapter(BaseAdapter):
    """HuggingFace adapter — works with any model on the Hub.

    No catalog entry required. Pass any HuggingFace model ID and the adapter
    will automatically detect the right API strategy via the Hub API and a
    full fallback waterfall (chat → text_generation → text2text → conversational).

    Args:
        model:            HuggingFace model ID (e.g. "mistralai/Mistral-7B-Instruct-v0.3")
                          or "tgi" when using a TGI server.
        mode:             "inference_api" | "endpoint" | "tgi" | "local"
                          Auto-detected from base_url when not specified explicitly.
        base_url:         Custom endpoint URL (required for "endpoint" and "tgi" modes).
        max_new_tokens:   Max tokens to generate.
        timeout:          Request timeout in seconds.
        max_retries:      Retry attempts on transient errors.
        device:           For local mode — "cpu", "cuda", "mps", or "auto".
        torch_dtype:      For local mode — "auto", "float16", "bfloat16", "float32".
        trust_remote_code: For local mode — set True for models needing custom code.
    """

    provider = "huggingface"

    def __init__(
        self,
        model: str,
        mode: str = "inference_api",
        base_url: str | None = None,
        max_new_tokens: int = 1024,
        timeout: float = 60.0,
        max_retries: int = 3,
        device: str = "auto",
        torch_dtype: str = "auto",
        trust_remote_code: bool = False,
    ) -> None:
        self.model = model
        self.mode = _detect_mode(mode, base_url)
        self.base_url = base_url
        self.max_new_tokens = max_new_tokens
        self._timeout = timeout
        self.max_retries = max_retries
        self._device = device
        self._torch_dtype = torch_dtype
        self._trust_remote_code = trust_remote_code
        self._token: str | None = get_secret("HF_TOKEN", required=False)

        if self.mode == "local":
            self._pipeline = self._load_local_pipeline()
            self._client = None
        else:
            self._pipeline = None
            self._client = self._build_client()

        # tgi / endpoint: always OpenAI-compat chat, pin the strategy immediately
        if self.mode in ("tgi", "endpoint"):
            _cache_set(self.model, _STRAT_CHAT)

    # ── Client construction ───────────────────────────────────────────────

    def _build_client(self) -> Any:
        try:
            from huggingface_hub import InferenceClient  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "HuggingFace adapter requires 'huggingface_hub'. "
                "Install with: pip install huggingface_hub"
            ) from exc

        if self.mode == "tgi":
            url = (self.base_url or "http://localhost:8080") + "/v1/chat/completions"
            return InferenceClient(model=url, token=self._token, timeout=self._timeout)

        if self.mode == "endpoint":
            if not self.base_url:
                raise ValueError(
                    "mode='endpoint' requires base_url set to your Inference Endpoint URL.\n"
                    "Example: https://xyz.us-east-1.aws.endpoints.huggingface.cloud"
                )
            return InferenceClient(model=self.base_url, token=self._token, timeout=self._timeout)

        # inference_api — model ID routes to the serverless API
        return InferenceClient(model=self.model, token=self._token, timeout=self._timeout)

    def _load_local_pipeline(self) -> Any:
        try:
            import torch  # noqa: F401
            from transformers import pipeline  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "Local HuggingFace inference requires transformers + torch.\n"
                "Install with: pip install 'redforge[huggingface-local]'\n"
                "  or: pip install transformers torch accelerate"
            ) from exc

        import torch

        dtype_map = {
            "float16":  torch.float16,
            "bfloat16": torch.bfloat16,
            "float32":  torch.float32,
            "auto":     "auto",
        }
        dtype = dtype_map.get(self._torch_dtype, "auto")

        return pipeline(
            "text-generation",
            model=self.model,
            device_map=self._device,
            torch_dtype=dtype,
            trust_remote_code=self._trust_remote_code,
        )

    # ── Strategy resolution ───────────────────────────────────────────────

    async def _resolve_initial_strategy(self) -> str:
        """Determine the best starting strategy for this model.

        Check order:
          1. Module-level cache (instantaneous, 1 h TTL)
          2. HF Hub API (best-effort, 5 s timeout) → pipeline_tag → strategy
          3. Heuristic default: chat_completion
        """
        cached = _cache_get(self.model)
        if cached:
            return cached

        # Best-effort Hub API lookup — non-blocking, never fails the scan
        tag = await _fetch_pipeline_tag(self.model, self._token)
        strategy = _strategy_from_tag(tag)
        logger.debug("Initial strategy for %s: %s (tag=%s)", self.model, strategy, tag)
        return strategy

    # ── Core send ─────────────────────────────────────────────────────────

    async def send(
        self,
        messages: list[dict[str, str]],
        system_prompt: str | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.7,
        timeout: float = 60.0,
        **kwargs: Any,
    ) -> AdapterResponse:
        effective_max = max_tokens or self.max_new_tokens

        if self.mode == "local":
            return await self._send_local(messages, system_prompt, effective_max, temperature)

        if self.mode in ("tgi", "endpoint"):
            # These are always OpenAI-compat — no fallback needed
            return await self._send_chat(messages, system_prompt, effective_max, temperature)

        return await self._send_with_fallback(messages, system_prompt, effective_max, temperature)

    # ── Fallback waterfall (inference_api only) ────────────────────────────

    async def _send_with_fallback(
        self,
        messages: list[dict[str, str]],
        system_prompt: str | None,
        max_tokens: int,
        temperature: float,
    ) -> AdapterResponse:
        """Walk the strategy chain until one succeeds; cache the winner."""
        initial = await self._resolve_initial_strategy()
        chain = _fallback_chain_from(initial)
        last_exc: Exception | None = None

        for strategy in chain:
            try:
                result = await self._dispatch(strategy, messages, system_prompt, max_tokens, temperature)
                # Cache the winner for this model
                _cache_set(self.model, strategy)
                if strategy != initial:
                    logger.info(
                        "HF model %s: strategy '%s' succeeded (initial '%s' failed) — cached",
                        self.model, strategy, initial,
                    )
                return result

            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if _is_strategy_error(exc):
                    logger.debug(
                        "HF model %s: strategy '%s' inapplicable (%s…) — trying next",
                        self.model, strategy, str(exc)[:80],
                    )
                    continue
                # Transient error (timeout, rate limit, 5xx) — surface it
                raise

        raise RuntimeError(
            f"Model '{self.model}' did not respond to any strategy "
            f"({', '.join(chain)}). "
            f"Last error: {last_exc}"
        ) from last_exc

    async def _dispatch(
        self,
        strategy: str,
        messages: list[dict[str, str]],
        system_prompt: str | None,
        max_tokens: int,
        temperature: float,
    ) -> AdapterResponse:
        if strategy == _STRAT_CHAT:
            return await self._send_chat(messages, system_prompt, max_tokens, temperature)
        if strategy == _STRAT_TEXT_GEN:
            return await self._send_text_generation(messages, system_prompt, max_tokens, temperature)
        if strategy == _STRAT_TEXT2TEXT:
            return await self._send_text2text(messages, system_prompt, max_tokens, temperature)
        if strategy == _STRAT_CONVERSATIONAL:
            return await self._send_conversational(messages, system_prompt, max_tokens, temperature)
        raise ValueError(f"Unknown strategy: {strategy!r}")

    # ── Strategy implementations ──────────────────────────────────────────

    async def _send_chat(
        self,
        messages: list[dict[str, str]],
        system_prompt: str | None,
        max_tokens: int,
        temperature: float,
    ) -> AdapterResponse:
        """OpenAI-compat Messages API — supported by most modern HF models."""
        all_messages: list[dict[str, str]] = []
        if system_prompt:
            all_messages.append({"role": "system", "content": system_prompt})
        all_messages.extend(messages)
        client = self._client

        async def _call() -> AdapterResponse:
            start = time.monotonic()
            response = await asyncio.to_thread(
                client.chat_completion,
                messages=all_messages,
                max_tokens=max_tokens,
                temperature=temperature,
                stream=False,
            )
            latency_ms = int((time.monotonic() - start) * 1000)
            content = response.choices[0].message.content or ""
            return AdapterResponse(
                content=content,
                model=self.model,
                latency_ms=latency_ms,
                tokens_used=getattr(response, "usage", None) and response.usage.total_tokens,
                finish_reason=response.choices[0].finish_reason,
                metadata={"mode": self.mode, "strategy": _STRAT_CHAT},
            )

        return await with_retry(_call, max_attempts=self.max_retries)

    async def _send_text_generation(
        self,
        messages: list[dict[str, str]],
        system_prompt: str | None,
        max_tokens: int,
        temperature: float,
    ) -> AdapterResponse:
        """Raw text_generation — for base models and older instruct models."""
        prompt = _build_prompt(messages, system_prompt)
        client = self._client

        async def _call() -> AdapterResponse:
            start = time.monotonic()
            result = await asyncio.to_thread(
                client.text_generation,
                prompt=prompt,
                max_new_tokens=max_tokens,
                temperature=temperature,
                return_full_text=False,
                do_sample=temperature > 0,
            )
            latency_ms = int((time.monotonic() - start) * 1000)
            content = result if isinstance(result, str) else str(result)
            return AdapterResponse(
                content=content.strip(),
                model=self.model,
                latency_ms=latency_ms,
                metadata={"mode": self.mode, "strategy": _STRAT_TEXT_GEN},
            )

        return await with_retry(_call, max_attempts=self.max_retries)

    async def _send_text2text(
        self,
        messages: list[dict[str, str]],
        system_prompt: str | None,
        max_tokens: int,
        temperature: float,
    ) -> AdapterResponse:
        """Encoder-decoder models: T5, BART, Flan-T5, mT5, NLLB, MarianMT…"""
        text_input = _build_text2text_input(messages, system_prompt)
        client = self._client

        async def _call() -> AdapterResponse:
            start = time.monotonic()
            # text_generation with short prompt works for most seq2seq via HF API
            result = await asyncio.to_thread(
                client.text_generation,
                prompt=text_input,
                max_new_tokens=max_tokens,
                temperature=temperature,
                return_full_text=False,
                do_sample=temperature > 0,
            )
            latency_ms = int((time.monotonic() - start) * 1000)
            if isinstance(result, str):
                content = result
            elif hasattr(result, "generated_text"):
                content = result.generated_text
            else:
                content = str(result)
            return AdapterResponse(
                content=content.strip(),
                model=self.model,
                latency_ms=latency_ms,
                metadata={"mode": self.mode, "strategy": _STRAT_TEXT2TEXT},
            )

        return await with_retry(_call, max_attempts=self.max_retries)

    async def _send_conversational(
        self,
        messages: list[dict[str, str]],
        system_prompt: str | None,
        max_tokens: int,
        temperature: float,
    ) -> AdapterResponse:
        """Legacy HF conversational pipeline — BlenderBot and similar dialog models."""
        client = self._client

        # Build past_user_inputs / generated_responses from message history
        past_user: list[str] = []
        past_gen: list[str] = []
        current_input = ""

        for i, msg in enumerate(messages):
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "user":
                is_last = (i == len(messages) - 1)
                if is_last:
                    current_input = content
                else:
                    past_user.append(content)
            elif role == "assistant":
                past_gen.append(content)

        if not current_input and messages:
            current_input = messages[-1].get("content", "")

        async def _call() -> AdapterResponse:
            start = time.monotonic()
            response = await asyncio.to_thread(
                client.conversational,
                text=current_input,
                past_user_inputs=past_user or None,
                generated_responses=past_gen or None,
                parameters={
                    "max_new_tokens": max_tokens,
                    "temperature": temperature,
                },
            )
            latency_ms = int((time.monotonic() - start) * 1000)
            if hasattr(response, "generated_text"):
                content = response.generated_text
            elif isinstance(response, dict):
                content = response.get("generated_text", str(response))
            else:
                content = str(response)
            return AdapterResponse(
                content=content.strip(),
                model=self.model,
                latency_ms=latency_ms,
                metadata={"mode": self.mode, "strategy": _STRAT_CONVERSATIONAL},
            )

        return await with_retry(_call, max_attempts=self.max_retries)

    # ── Local transformers pipeline ────────────────────────────────────────

    async def _send_local(
        self,
        messages: list[dict[str, str]],
        system_prompt: str | None,
        max_tokens: int,
        temperature: float,
    ) -> AdapterResponse:
        """Run via local transformers pipeline — three internal fallbacks."""
        pipe = self._pipeline
        all_messages: list[dict[str, str]] = []
        if system_prompt:
            all_messages.append({"role": "system", "content": system_prompt})
        all_messages.extend(messages)

        def _run() -> AdapterResponse:
            start = time.monotonic()
            content = ""

            # Attempt 1: modern chat template (apply_chat_template via messages=)
            try:
                out = pipe(
                    all_messages,
                    max_new_tokens=max_tokens,
                    temperature=temperature if temperature > 0 else None,
                    do_sample=temperature > 0,
                    pad_token_id=pipe.tokenizer.eos_token_id,  # type: ignore[union-attr]
                )
                content = out[0]["generated_text"][-1]["content"]
            except (KeyError, TypeError, AttributeError, IndexError):
                pass

            # Attempt 2: plain text prompt (base models, older instruct)
            if not content:
                try:
                    prompt = _build_prompt(messages, system_prompt)
                    out2 = pipe(
                        prompt,
                        max_new_tokens=max_tokens,
                        temperature=temperature if temperature > 0 else None,
                        do_sample=temperature > 0,
                    )
                    generated = out2[0]["generated_text"]
                    # Slice off the input prompt to get only new tokens
                    content = generated[len(prompt):] if generated.startswith(prompt) else generated
                except Exception as _e:  # noqa: BLE001
                    logger.debug("Local pipeline text prompt fallback failed: %s", _e)

            # Attempt 3: text2text / seq2seq (T5, BART, Flan)
            if not content:
                text_input = _build_text2text_input(messages, system_prompt)
                out3 = pipe(text_input, max_new_tokens=max_tokens)
                raw = out3[0].get("generated_text", "") if isinstance(out3[0], dict) else str(out3[0])
                content = raw

            latency_ms = int((time.monotonic() - start) * 1000)
            return AdapterResponse(
                content=content.strip(),
                model=self.model,
                latency_ms=latency_ms,
                metadata={"mode": "local", "strategy": "pipeline"},
            )

        return await asyncio.to_thread(_run)

    # ── Config / repr ──────────────────────────────────────────────────────

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> HuggingFaceAdapter:
        return cls(
            model=config.get("model", ""),
            mode=config.get("mode", "inference_api"),
            base_url=config.get("base_url"),
            max_new_tokens=config.get("max_new_tokens", config.get("max_tokens", 1024)),
            timeout=config.get("timeout", 60.0),
            max_retries=config.get("max_retries", 3),
            device=config.get("device", "auto"),
            torch_dtype=config.get("torch_dtype", "auto"),
            trust_remote_code=config.get("trust_remote_code", False),
        )

    def __repr__(self) -> str:
        cached_strat = _cache_get(self.model)
        strat_str = cached_strat or "auto"
        return (
            f"HuggingFaceAdapter(model={self.model!r}, mode={self.mode!r}, "
            f"strategy={strat_str!r})"
        )


__all__ = [
    "HuggingFaceAdapter",
    "clear_strategy_cache",
]
