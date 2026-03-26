"""AWS Bedrock adapter — supports ALL model families.

Each model family hosted on Bedrock uses a different request/response body
format.  This adapter detects the family automatically and builds the correct
payload:

- **Anthropic Claude**  — ``messages`` API with ``anthropic_version``
- **Meta Llama**        — prompt string with ``<|begin_of_text|>`` formatting
- **Mistral**           — prompt string with ``<s>[INST]`` formatting
- **Amazon Titan**      — ``inputText`` + ``textGenerationConfig``
- **Cohere Command-R**  — ``message`` + ``chat_history``
- **AI21 Jamba**        — OpenAI-style ``messages`` array
"""

from __future__ import annotations

import json
import time
from typing import Any

from redforge.adapters.base import AdapterResponse, BaseAdapter
from redforge.adapters.model_catalog import BedrockModelFamily, get_bedrock_family
from redforge.utils.rate_limiter import with_retry


class BedrockAdapter(BaseAdapter):
    """Adapter for AWS Bedrock models (all families).

    Credentials are loaded by boto3 in the standard priority order:
      1. ``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY`` env vars
      2. ``AWS_PROFILE`` env var
      3. EC2 instance role / ECS task role (auto-detected)
    """

    provider = "bedrock"

    def __init__(
        self,
        model: str = "anthropic.claude-3-5-sonnet-20241022-v2:0",
        region: str = "us-east-1",
        max_retries: int = 3,
        timeout: float = 60.0,
    ) -> None:
        """Initialise the Bedrock adapter.

        Args:
            model: Full Bedrock model ID including family prefix and version suffix.
            region: AWS region that hosts the model.
            max_retries: Number of retry attempts on transient errors.
            timeout: Per-request timeout in seconds.

        Raises:
            ImportError: If ``boto3`` is not installed.
        """
        try:
            import boto3  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "Bedrock provider requires 'boto3'. "
                "Install with: pip install redforge[bedrock]"
            ) from exc

        self._client = boto3.client("bedrock-runtime", region_name=region)
        self.model = model
        self.region = region
        self.max_retries = max_retries
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Body builders — one per model family
    # ------------------------------------------------------------------

    def _build_llama_prompt(
        self,
        messages: list[dict[str, Any]],
        system_prompt: str | None,
    ) -> str:
        """Build a Llama-3 chat prompt string from a message list.

        Uses the ``<|begin_of_text|>`` / ``<|start_header_id|>`` / ``<|eot_id|>``
        token format expected by all Llama-3 instruct models.

        Args:
            messages: List of ``{"role": ..., "content": ...}`` dicts.
            system_prompt: Optional system-level instructions.

        Returns:
            A fully-formatted prompt string ready to pass in ``"prompt"``.
        """
        parts: list[str] = ["<|begin_of_text|>"]

        if system_prompt:
            parts.append(
                f"<|start_header_id|>system<|end_header_id|>\n\n"
                f"{system_prompt}<|eot_id|>"
            )

        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            parts.append(
                f"<|start_header_id|>{role}<|end_header_id|>\n\n{content}<|eot_id|>"
            )

        parts.append("<|start_header_id|>assistant<|end_header_id|>\n\n")
        return "".join(parts)

    def _llama_body(
        self,
        messages: list[dict[str, Any]],
        system_prompt: str | None,
        max_tokens: int,
        temperature: float,
    ) -> dict[str, Any]:
        """Build the request body for Meta Llama models.

        Args:
            messages: Conversation messages.
            system_prompt: Optional system instruction.
            max_tokens: Maximum generation length.
            temperature: Sampling temperature.

        Returns:
            Request body dict for ``invoke_model``.
        """
        prompt = self._build_llama_prompt(messages, system_prompt)
        return {
            "prompt": prompt,
            "max_gen_len": max_tokens,
            "temperature": temperature,
        }

    def _build_mistral_prompt(
        self,
        messages: list[dict[str, Any]],
        system_prompt: str | None,
    ) -> str:
        """Build a Mistral instruct prompt from a message list.

        Uses the ``<s>[INST]…[/INST]`` format.  The system prompt, if any,
        is prepended to the first user message.

        Args:
            messages: Conversation messages.
            system_prompt: Optional system instruction.

        Returns:
            A formatted prompt string.
        """
        parts: list[str] = []
        first_user = True
        for msg in messages:
            role = msg.get("role", "user")
            content = str(msg.get("content", ""))
            if role == "user":
                if first_user and system_prompt:
                    content = f"{system_prompt}\n{content}"
                    first_user = False
                parts.append(f"<s>[INST] {content} [/INST]")
            elif role == "assistant":
                parts.append(f" {content}</s>")
        return "".join(parts)

    def _mistral_body(
        self,
        messages: list[dict[str, Any]],
        system_prompt: str | None,
        max_tokens: int,
        temperature: float,
    ) -> dict[str, Any]:
        """Build the request body for Mistral models on Bedrock.

        Args:
            messages: Conversation messages.
            system_prompt: Optional system instruction.
            max_tokens: Maximum generation length.
            temperature: Sampling temperature.

        Returns:
            Request body dict for ``invoke_model``.
        """
        prompt = self._build_mistral_prompt(messages, system_prompt)
        return {
            "prompt": prompt,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

    def _titan_body(
        self,
        messages: list[dict[str, Any]],
        system_prompt: str | None,
        max_tokens: int,
        temperature: float,
    ) -> dict[str, Any]:
        """Build the request body for Amazon Titan models.

        Titan uses a single ``inputText`` string; the system prompt and all
        messages are concatenated with newlines.

        Args:
            messages: Conversation messages.
            system_prompt: Optional system instruction.
            max_tokens: Maximum generation length.
            temperature: Sampling temperature.

        Returns:
            Request body dict for ``invoke_model``.
        """
        pieces: list[str] = []
        if system_prompt:
            pieces.append(system_prompt)
        for msg in messages:
            pieces.append(str(msg.get("content", "")))
        input_text = "\n".join(pieces)
        return {
            "inputText": input_text,
            "textGenerationConfig": {
                "maxTokenCount": max_tokens,
                "temperature": temperature,
            },
        }

    def _cohere_body(
        self,
        messages: list[dict[str, Any]],
        system_prompt: str | None,
        max_tokens: int,
        temperature: float,
    ) -> dict[str, Any]:
        """Build the request body for Cohere Command-R models.

        The last user message becomes ``message``; earlier turns become
        ``chat_history`` in Cohere's ``{"role": "USER"|"CHATBOT", "message": str}``
        format.  A system prompt is passed via the ``preamble`` key.

        Args:
            messages: Conversation messages.
            system_prompt: Optional system instruction (becomes ``preamble``).
            max_tokens: Maximum generation length.
            temperature: Sampling temperature.

        Returns:
            Request body dict for ``invoke_model``.
        """
        chat_history: list[dict[str, str]] = []
        last_msg = ""

        role_map = {"user": "USER", "assistant": "CHATBOT"}
        for msg in messages[:-1]:
            cohere_role = role_map.get(str(msg.get("role", "user")), "USER")
            chat_history.append(
                {"role": cohere_role, "message": str(msg.get("content", ""))}
            )
        if messages:
            last_msg = str(messages[-1].get("content", ""))

        body: dict[str, Any] = {
            "message": last_msg,
            "chat_history": chat_history,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system_prompt:
            body["preamble"] = system_prompt
        return body

    def _ai21_body(
        self,
        messages: list[dict[str, Any]],
        system_prompt: str | None,
        max_tokens: int,
        temperature: float,
    ) -> dict[str, Any]:
        """Build the request body for AI21 Jamba models.

        AI21 Jamba uses an OpenAI-style ``messages`` array, making it the
        simplest family to support.

        Args:
            messages: Conversation messages.
            system_prompt: Optional system instruction.
            max_tokens: Maximum generation length.
            temperature: Sampling temperature.

        Returns:
            Request body dict for ``invoke_model``.
        """
        all_messages: list[dict[str, Any]] = []
        if system_prompt:
            all_messages.append({"role": "system", "content": system_prompt})
        all_messages.extend(messages)
        return {
            "messages": all_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

    def _anthropic_body(
        self,
        messages: list[dict[str, Any]],
        system_prompt: str | None,
        max_tokens: int,
        temperature: float,
    ) -> dict[str, Any]:
        """Build the request body for Anthropic Claude models on Bedrock.

        Args:
            messages: Conversation messages.
            system_prompt: Optional system instruction.
            max_tokens: Maximum generation length.
            temperature: Sampling temperature.

        Returns:
            Request body dict for ``invoke_model``.
        """
        body: dict[str, Any] = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "messages": messages,
            "temperature": temperature,
        }
        if system_prompt:
            body["system"] = system_prompt
        return body

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def _build_request_body(
        self,
        messages: list[dict[str, Any]],
        system_prompt: str | None,
        max_tokens: int,
        temperature: float,
    ) -> dict[str, Any]:
        """Route to the correct body builder based on the model family.

        Args:
            messages: Conversation messages.
            system_prompt: Optional system instruction.
            max_tokens: Maximum output tokens.
            temperature: Sampling temperature.

        Returns:
            A request body dict ready to JSON-encode for ``invoke_model``.

        Raises:
            ValueError: If the model ID doesn't match any known Bedrock family.
        """
        family = get_bedrock_family(self.model)
        if family == BedrockModelFamily.ANTHROPIC:
            return self._anthropic_body(messages, system_prompt, max_tokens, temperature)
        if family == BedrockModelFamily.META_LLAMA:
            return self._llama_body(messages, system_prompt, max_tokens, temperature)
        if family == BedrockModelFamily.MISTRAL:
            return self._mistral_body(messages, system_prompt, max_tokens, temperature)
        if family == BedrockModelFamily.AMAZON_TITAN:
            return self._titan_body(messages, system_prompt, max_tokens, temperature)
        if family == BedrockModelFamily.COHERE:
            return self._cohere_body(messages, system_prompt, max_tokens, temperature)
        if family == BedrockModelFamily.AI21:
            return self._ai21_body(messages, system_prompt, max_tokens, temperature)
        # Unreachable given the enum, but keeps mypy happy
        raise ValueError(f"Unhandled BedrockModelFamily: {family}")

    def _extract_response_content(self, result: dict[str, Any]) -> tuple[str, int | None, str | None]:
        """Extract (content, tokens_used, finish_reason) from a Bedrock response dict.

        Each model family returns content in a different key structure.

        Args:
            result: Parsed JSON response from ``invoke_model``.

        Returns:
            A ``(content, tokens_used, finish_reason)`` tuple.
        """
        family = get_bedrock_family(self.model)

        if family == BedrockModelFamily.ANTHROPIC:
            content = ""
            for block in result.get("content", []):
                if block.get("type") == "text":
                    content += block.get("text", "")
            tokens = result.get("usage", {}).get("output_tokens")
            finish = result.get("stop_reason")
            return content, tokens, finish

        if family == BedrockModelFamily.META_LLAMA:
            content = result.get("generation", "")
            tokens = result.get("generation_token_count")
            finish = result.get("stop_reason")
            return content, tokens, finish

        if family == BedrockModelFamily.MISTRAL:
            outputs = result.get("outputs", [])
            content = outputs[0].get("text", "") if outputs else ""
            finish = outputs[0].get("stop_reason") if outputs else None
            return content, None, finish

        if family == BedrockModelFamily.AMAZON_TITAN:
            results = result.get("results", [])
            content = results[0].get("outputText", "") if results else ""
            finish = results[0].get("completionReason") if results else None
            tokens = result.get("inputTextTokenCount")
            return content, tokens, finish

        if family == BedrockModelFamily.COHERE:
            content = result.get("text", "")
            finish = result.get("finish_reason")
            return content, None, finish

        if family == BedrockModelFamily.AI21:
            choices = result.get("choices", [])
            content = choices[0].get("message", {}).get("content", "") if choices else ""
            finish = choices[0].get("finish_reason") if choices else None
            tokens = result.get("usage", {}).get("completion_tokens")
            return content, tokens, finish

        return "", None, None

    # ------------------------------------------------------------------
    # Core send / streaming
    # ------------------------------------------------------------------

    async def send(
        self,
        messages: list[dict[str, str]],
        system_prompt: str | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.7,
        timeout: float = 60.0,
        **kwargs: Any,
    ) -> AdapterResponse:
        """Send messages to a Bedrock model and return the response.

        Args:
            messages: Conversation messages as ``{"role": ..., "content": ...}`` dicts.
            system_prompt: Optional system-level instruction.
            max_tokens: Maximum output tokens.
            temperature: Sampling temperature.
            timeout: Request timeout in seconds (not enforced by boto3 directly,
                but passed for compatibility with the base interface).
            **kwargs: Ignored; present for interface compatibility.

        Returns:
            A standardised AdapterResponse.
        """
        import asyncio

        body = self._build_request_body(
            list(messages), system_prompt, max_tokens, temperature
        )

        async def _call() -> AdapterResponse:
            start = time.monotonic()
            response = await asyncio.to_thread(
                self._client.invoke_model,
                modelId=self.model,
                body=json.dumps(body),
                contentType="application/json",
                accept="application/json",
            )
            latency_ms = int((time.monotonic() - start) * 1000)
            result: dict[str, Any] = json.loads(response["body"].read())
            content, tokens_used, finish_reason = self._extract_response_content(result)
            return AdapterResponse(
                content=content,
                model=self.model,
                latency_ms=latency_ms,
                tokens_used=tokens_used,
                finish_reason=finish_reason,
            )

        return await with_retry(_call, max_attempts=self.max_retries)

    async def send_streaming(
        self,
        messages: list[dict[str, str]],
        system_prompt: str | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.7,
        **kwargs: Any,
    ) -> AdapterResponse:
        """Stream a response from Bedrock using ``invoke_model_with_response_stream``.

        Collects all streamed chunks and returns a single AdapterResponse.
        Anthropic Claude streaming chunks use the ``contentBlockDelta`` event
        type; other families return ``chunk`` events.

        Args:
            messages: Conversation messages.
            system_prompt: Optional system instruction.
            max_tokens: Maximum output tokens.
            temperature: Sampling temperature.
            **kwargs: Ignored.

        Returns:
            A fully assembled AdapterResponse.
        """
        import asyncio

        body = self._build_request_body(
            list(messages), system_prompt, max_tokens, temperature
        )

        async def _call() -> AdapterResponse:
            start = time.monotonic()
            response = await asyncio.to_thread(
                self._client.invoke_model_with_response_stream,
                modelId=self.model,
                body=json.dumps(body),
                contentType="application/json",
                accept="application/json",
            )
            latency_ms = int((time.monotonic() - start) * 1000)

            content_parts: list[str] = []
            family = get_bedrock_family(self.model)

            for event in response.get("body", []):
                chunk_data = event.get("chunk", {})
                raw = chunk_data.get("bytes", b"")
                if not raw:
                    continue
                chunk_json: dict[str, Any] = json.loads(raw)

                if family == BedrockModelFamily.ANTHROPIC:
                    if chunk_json.get("type") == "content_block_delta":
                        delta = chunk_json.get("delta", {})
                        if delta.get("type") == "text_delta":
                            content_parts.append(delta.get("text", ""))
                elif family == BedrockModelFamily.META_LLAMA:
                    content_parts.append(chunk_json.get("generation", ""))
                elif family == BedrockModelFamily.MISTRAL:
                    outputs = chunk_json.get("outputs", [])
                    if outputs:
                        content_parts.append(outputs[0].get("text", ""))
                elif family == BedrockModelFamily.AMAZON_TITAN:
                    content_parts.append(chunk_json.get("outputText", ""))
                elif family == BedrockModelFamily.COHERE:
                    content_parts.append(chunk_json.get("text", ""))
                elif family == BedrockModelFamily.AI21:
                    choices = chunk_json.get("choices", [])
                    if choices:
                        delta = choices[0].get("delta", {})
                        content_parts.append(delta.get("content", ""))

            return AdapterResponse(
                content="".join(content_parts),
                model=self.model,
                latency_ms=latency_ms,
            )

        return await with_retry(_call, max_attempts=self.max_retries)

    # ------------------------------------------------------------------
    # from_config
    # ------------------------------------------------------------------

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> BedrockAdapter:
        """Instantiate from a provider config dict.

        Expected keys (all optional with defaults):
          - ``model``: Bedrock model ID.
          - ``region``: AWS region (default ``'us-east-1'``).
          - ``max_retries``: Retry count (default ``3``).
          - ``timeout``: Timeout in seconds (default ``60.0``).

        Args:
            config: Config dict from AdapterConfig.to_provider_config().

        Returns:
            A ready-to-use BedrockAdapter.
        """
        return cls(
            model=config.get("model", "anthropic.claude-3-5-sonnet-20241022-v2:0"),
            region=config.get("region", "us-east-1"),
            max_retries=config.get("max_retries", 3),
            timeout=config.get("timeout", 60.0),
        )

    def __repr__(self) -> str:
        return (
            f"BedrockAdapter(model={self.model!r}, region={self.region!r})"
        )


__all__ = ["BedrockAdapter"]
