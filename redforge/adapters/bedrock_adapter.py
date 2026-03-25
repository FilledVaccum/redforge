"""AWS Bedrock adapter."""

from __future__ import annotations

import json
import time
from typing import Any

from redforge.adapters.base import AdapterResponse, BaseAdapter
from redforge.utils.rate_limiter import with_retry


class BedrockAdapter(BaseAdapter):
    """Adapter for AWS Bedrock models.

    Credentials loaded from:
    - AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY env vars
    - AWS_PROFILE env var
    - EC2 instance role / ECS task role (auto-detected by boto3)
    """

    provider = "bedrock"

    def __init__(
        self,
        model: str = "anthropic.claude-3-sonnet-20240229-v1:0",
        region: str = "us-east-1",
        max_retries: int = 3,
        timeout: float = 60.0,
    ) -> None:
        try:
            import boto3
        except ImportError as e:
            raise ImportError(
                "Bedrock provider requires 'boto3' package. "
                "Install with: pip install redforge[bedrock]"
            ) from e

        self._client = boto3.client("bedrock-runtime", region_name=region)
        self.model = model
        self.max_retries = max_retries
        self._timeout = timeout

    async def send(
        self,
        messages: list[dict[str, str]],
        system_prompt: str | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.7,
        timeout: float = 60.0,
        **kwargs: Any,
    ) -> AdapterResponse:
        import asyncio

        body: dict[str, Any] = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "messages": messages,
            "temperature": temperature,
        }
        if system_prompt:
            body["system"] = system_prompt

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
            result = json.loads(response["body"].read())
            content = ""
            for block in result.get("content", []):
                if block.get("type") == "text":
                    content += block.get("text", "")
            return AdapterResponse(
                content=content,
                model=self.model,
                latency_ms=latency_ms,
                tokens_used=result.get("usage", {}).get("output_tokens"),
                finish_reason=result.get("stop_reason"),
            )

        return await with_retry(_call, max_attempts=self.max_retries)

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> BedrockAdapter:
        return cls(
            model=config.get("model", "anthropic.claude-3-sonnet-20240229-v1:0"),
            region=config.get("region", "us-east-1"),
            max_retries=config.get("max_retries", 3),
        )
