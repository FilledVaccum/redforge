"""HuggingFace adapter — four modes, any model on the Hub.

Modes
─────
inference_api   Default. Serverless Inference API — any public model works.
                Requires HF_TOKEN for gated models and higher rate limits.
                Uses new Messages API (OpenAI-compatible chat completions)
                when the model supports it, falls back to text_generation.

endpoint        Dedicated Inference Endpoint (your own hosted URL).
                Set base_url to your endpoint URL.
                Same Messages API as inference_api.

tgi             Text Generation Inference server (self-hosted or HF-hosted).
                OpenAI-compatible — works with any TGI ≥ 2.0 deployment.
                Set base_url to http://your-tgi-host:8080.

local           Run directly via transformers + torch on this machine.
                No network call, no API key. Requires:
                  pip install "redforge[huggingface-local]"

Env vars
────────
HF_TOKEN        HuggingFace API token. Required for:
                  - Gated models (Llama, Gemma, etc.)
                  - Private models / Inference Endpoints
                  - Higher rate limits on Inference API
                Get yours at https://huggingface.co/settings/tokens

Usage examples
──────────────
  # Any public model — Inference API (no token needed for ungated)
  AdapterFactory.from_spec("huggingface/mistralai/Mistral-7B-Instruct-v0.3")

  # Gated model (needs HF_TOKEN in env)
  AdapterFactory.from_spec("huggingface/meta-llama/Meta-Llama-3.1-8B-Instruct")

  # Your Inference Endpoint
  AdapterFactory.from_spec("huggingface/my-model@https://xyz.us-east-1.aws.endpoints.huggingface.cloud")

  # Self-hosted TGI
  AdapterFactory.from_spec("huggingface/tgi@http://my-tgi-server:8080")

  # Local (downloads model weights)
  AdapterFactory.from_dict({"provider": "huggingface", "model": "...", "mode": "local"})
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from redforge.adapters.base import AdapterResponse, BaseAdapter
from redforge.utils.rate_limiter import with_retry
from redforge.utils.secrets import get_secret

# Models known to support the Messages API on the Inference API.
# All others fall back to text_generation with prompt formatting.
_CHAT_CAPABLE_PREFIXES = (
    "meta-llama/",
    "mistralai/",
    "google/gemma",
    "microsoft/Phi",
    "Qwen/Qwen",
    "deepseek-ai/",
    "HuggingFaceH4/",
    "tiiuae/falcon",
    "bigcode/",
    "codellama/",
    "NovaSky-Berkeley/",
    "openai-community/",
    "teknium/",
    "01-ai/",
    "01ai/",
    "internlm/",
    "CohereForAI/",
)


def _looks_chat_capable(model_id: str) -> bool:
    """Heuristic: does this model ID look like a chat/instruct model?"""
    low = model_id.lower()
    return (
        any(model_id.startswith(p) for p in _CHAT_CAPABLE_PREFIXES)
        or any(k in low for k in ("instruct", "chat", "it", "-chat", "assistant", "zephyr", "hermes"))
    )


def _build_prompt(
    messages: list[dict[str, str]],
    system_prompt: str | None,
) -> str:
    """Minimal prompt builder for non-chat text_generation fallback."""
    parts: list[str] = []
    if system_prompt:
        parts.append(f"System: {system_prompt}\n")
    for msg in messages:
        role = msg.get("role", "user").capitalize()
        content = msg.get("content", "")
        parts.append(f"{role}: {content}")
    parts.append("Assistant:")
    return "\n".join(parts)


class HuggingFaceAdapter(BaseAdapter):
    """HuggingFace adapter — Inference API, Endpoints, TGI, or local pipeline.

    Args:
        model:         HuggingFace model ID (e.g. "meta-llama/Meta-Llama-3.1-8B-Instruct")
                       or "tgi" when using a TGI server that serves a single model.
        mode:          "inference_api" | "endpoint" | "tgi" | "local"
        base_url:      Custom endpoint URL (required for "endpoint" and "tgi" modes,
                       and for remote Ollama-style inference servers).
        max_new_tokens: Max tokens to generate (HF calls this max_new_tokens).
        timeout:       Request timeout in seconds.
        max_retries:   Retry attempts on transient errors.
        device:        For local mode — "cpu", "cuda", "mps", or "auto".
        torch_dtype:   For local mode — "auto", "float16", "bfloat16", "float32".
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
        self.mode = mode
        self.base_url = base_url
        self.max_new_tokens = max_new_tokens
        self._timeout = timeout
        self.max_retries = max_retries
        self._device = device
        self._torch_dtype = torch_dtype
        self._trust_remote_code = trust_remote_code

        if mode == "local":
            self._pipeline = self._load_local_pipeline()
            self._client = None
        else:
            self._pipeline = None
            self._client = self._build_client()

        self._use_chat_api = (mode in ("tgi",)) or _looks_chat_capable(model)

    # ── Client construction ───────────────────────────────────────────────

    def _build_client(self) -> Any:
        try:
            from huggingface_hub import InferenceClient  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "HuggingFace adapter requires 'huggingface_hub'. "
                "Install with: pip install huggingface_hub"
            ) from exc

        token = get_secret("HF_TOKEN", required=False)

        if self.mode == "tgi":
            # TGI: OpenAI-compat endpoint, model served by the server
            url = (self.base_url or "http://localhost:8080") + "/v1/chat/completions"
            return InferenceClient(
                model=url,
                token=token,
                timeout=self._timeout,
            )

        if self.mode == "endpoint":
            if not self.base_url:
                raise ValueError(
                    "mode='endpoint' requires base_url set to your Inference Endpoint URL.\n"
                    "Example: https://xyz.us-east-1.aws.endpoints.huggingface.cloud"
                )
            return InferenceClient(
                model=self.base_url,
                token=token,
                timeout=self._timeout,
            )

        # inference_api — standard serverless API
        return InferenceClient(
            model=self.model,
            token=token,
            timeout=self._timeout,
        )

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

        if self._use_chat_api:
            return await self._send_chat(messages, system_prompt, effective_max, temperature)

        return await self._send_text_generation(messages, system_prompt, effective_max, temperature)

    # ── Chat completions path (Messages API — most modern HF models) ──────

    async def _send_chat(
        self,
        messages: list[dict[str, str]],
        system_prompt: str | None,
        max_tokens: int,
        temperature: float,
    ) -> AdapterResponse:
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
                metadata={"mode": self.mode, "api": "chat_completion"},
            )

        try:
            return await with_retry(_call, max_attempts=self.max_retries)
        except Exception:
            # Chat API not supported — fall back to text_generation
            self._use_chat_api = False
            return await self._send_text_generation(
                messages, system_prompt, max_tokens, temperature
            )

    # ── text_generation path (older / base models) ────────────────────────

    async def _send_text_generation(
        self,
        messages: list[dict[str, str]],
        system_prompt: str | None,
        max_tokens: int,
        temperature: float,
    ) -> AdapterResponse:
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
            # result is a string when return_full_text=False
            content = result if isinstance(result, str) else str(result)
            return AdapterResponse(
                content=content.strip(),
                model=self.model,
                latency_ms=latency_ms,
                metadata={"mode": self.mode, "api": "text_generation"},
            )

        return await with_retry(_call, max_attempts=self.max_retries)

    # ── Local transformers pipeline path ─────────────────────────────────

    async def _send_local(
        self,
        messages: list[dict[str, str]],
        system_prompt: str | None,
        max_tokens: int,
        temperature: float,
    ) -> AdapterResponse:
        pipe = self._pipeline
        all_messages: list[dict[str, str]] = []
        if system_prompt:
            all_messages.append({"role": "system", "content": system_prompt})
        all_messages.extend(messages)

        def _run() -> AdapterResponse:
            start = time.monotonic()
            # Modern transformers supports apply_chat_template via messages=
            try:
                out = pipe(
                    all_messages,
                    max_new_tokens=max_tokens,
                    temperature=temperature if temperature > 0 else None,
                    do_sample=temperature > 0,
                    pad_token_id=pipe.tokenizer.eos_token_id,  # type: ignore[union-attr]
                )
                content = out[0]["generated_text"][-1]["content"]
            except (KeyError, TypeError):
                # Fallback: treat as plain text generation
                prompt = _build_prompt(messages, system_prompt)
                out2 = pipe(
                    prompt,
                    max_new_tokens=max_tokens,
                    temperature=temperature if temperature > 0 else None,
                    do_sample=temperature > 0,
                )
                content = out2[0]["generated_text"][len(prompt):]
            latency_ms = int((time.monotonic() - start) * 1000)
            return AdapterResponse(
                content=content.strip(),
                model=self.model,
                latency_ms=latency_ms,
                metadata={"mode": "local"},
            )

        return await asyncio.to_thread(_run)

    # ── Config / repr ─────────────────────────────────────────────────────

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
        return (
            f"HuggingFaceAdapter(model={self.model!r}, mode={self.mode!r}, "
            f"base_url={self.base_url!r})"
        )
