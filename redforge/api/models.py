"""Pydantic request/response schemas for the RedForge REST API."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class ScanRequest(BaseModel):
    provider: str = Field(..., description="Model provider: openai, anthropic, ollama, etc.")
    model: str | None = Field(None, description="Model name/ID")
    authorization: str = Field(..., description="Authorization type: owned | authorized | research")
    probes: list[str] | None = Field(None, description="Specific probe IDs to run. None = all.")
    system_prompt: str | None = Field(None, max_length=10000, description="System prompt for the target model")
    dry_run: bool = Field(False, description="List probes without executing")

    @field_validator("authorization")
    @classmethod
    def validate_authorization(cls, v: str) -> str:
        if v not in ("owned", "authorized", "research"):
            raise ValueError("authorization must be 'owned', 'authorized', or 'research'")
        return v

    @field_validator("system_prompt")
    @classmethod
    def sanitize_system_prompt(cls, v: str | None) -> str | None:
        return v  # Stored as-is, but size-limited above


class ProbeInfo(BaseModel):
    id: str
    owasp_id: str
    mitre_atlas: str
    severity: str
    description: str
    tags: list[str]
    payload_count: int


class FindingResponse(BaseModel):
    probe_id: str
    owasp_id: str
    mitre_atlas: str
    severity: str
    score: float
    passed: bool
    evidence: str
    tags: list[str]
    # NOTE: raw payload and response are NOT included — stored locally only


class ScoreResponse(BaseModel):
    risk_score: float
    risk_level: str
    total_probes: int
    passed: int
    failed: int
    pass_rate: float
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int


class ScanResponse(BaseModel):
    session_id: str
    target: str
    provider: str
    model: str
    score: ScoreResponse
    findings: list[FindingResponse]
    started_at: str
    finished_at: str | None


class ErrorResponse(BaseModel):
    error: str
    detail: str | None = None
