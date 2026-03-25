"""Base classes for the RedForge guardrail scanner framework."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ScanAction(str, Enum):
    """Action to take based on scan result."""

    ALLOW = "allow"     # Content is safe, allow through
    WARN = "warn"       # Content is borderline, allow but log warning
    BLOCK = "block"     # Content is unsafe, block it


@dataclass
class BaseScanResult:
    """Result from a single scanner."""

    scanner_name: str
    action: ScanAction
    risk_score: float           # 0.0 (safe) → 1.0 (unsafe)
    reason: str
    matched_patterns: list[str] = field(default_factory=list)

    @property
    def is_flagged(self) -> bool:
        return self.action in (ScanAction.WARN, ScanAction.BLOCK)

    @property
    def is_blocked(self) -> bool:
        return self.action == ScanAction.BLOCK


class BaseScanner:
    """Abstract base class for all RedForge guardrail scanners.

    Subclass and implement scan() to create a new scanner.
    Scanners are stateless and thread-safe.
    """

    name: str = "base"
    direction: str = "both"     # "input", "output", or "both"
    block_threshold: float = 0.8
    warn_threshold: float = 0.5

    def scan(self, text: str, context: dict[str, str] | None = None) -> BaseScanResult:
        """Scan text and return a ScanResult.

        Args:
            text: The text to scan (UNTRUSTED — never eval/exec).
            context: Optional context dict (e.g. {"user_id": "...", "session": "..."}).

        Returns:
            BaseScanResult with action, risk_score, and reason.
        """
        raise NotImplementedError

    def _make_result(
        self,
        risk_score: float,
        reason: str,
        matched_patterns: list[str] | None = None,
    ) -> BaseScanResult:
        """Helper to create a ScanResult with proper action based on thresholds."""
        if risk_score >= self.block_threshold:
            action = ScanAction.BLOCK
        elif risk_score >= self.warn_threshold:
            action = ScanAction.WARN
        else:
            action = ScanAction.ALLOW

        return BaseScanResult(
            scanner_name=self.name,
            action=action,
            risk_score=risk_score,
            reason=reason,
            matched_patterns=matched_patterns or [],
        )


@dataclass
class PipelineScanResult:
    """Aggregated result from a GuardrailPipeline."""

    final_action: ScanAction
    overall_risk_score: float
    scanner_results: list[BaseScanResult] = field(default_factory=list)
    blocked_by: str | None = None    # Name of scanner that caused block

    @property
    def is_blocked(self) -> bool:
        return self.final_action == ScanAction.BLOCK

    @property
    def is_flagged(self) -> bool:
        return self.final_action in (ScanAction.WARN, ScanAction.BLOCK)

    def summary(self) -> str:
        flagged = [r for r in self.scanner_results if r.is_flagged]
        if not flagged:
            return "All scanners passed"
        return f"{len(flagged)}/{len(self.scanner_results)} scanners flagged: " + \
               ", ".join(r.scanner_name for r in flagged)


class GuardrailPipeline:
    """Chain multiple scanners for input or output scanning.

    The pipeline runs all scanners and aggregates results.
    If ANY scanner blocks, the pipeline blocks.
    The overall risk score is the maximum across all scanners.

    Usage:
        pipeline = GuardrailPipeline([
            InjectionScanner(),
            TokenBudgetScanner(max_tokens=1000),
        ])
        result = pipeline.scan(user_message)
        if result.is_blocked:
            return "Request blocked: " + result.blocked_by
    """

    def __init__(self, scanners: list[BaseScanner]) -> None:
        self._scanners = scanners

    def scan(
        self,
        text: str,
        context: dict[str, str] | None = None,
    ) -> PipelineScanResult:
        """Run all scanners and return aggregated result."""
        results: list[BaseScanResult] = []
        blocked_by: str | None = None

        for scanner in self._scanners:
            result = scanner.scan(text, context)
            results.append(result)
            if result.is_blocked and blocked_by is None:
                blocked_by = scanner.name

        if not results:
            return PipelineScanResult(
                final_action=ScanAction.ALLOW,
                overall_risk_score=0.0,
                scanner_results=[],
            )

        overall_score = max(r.risk_score for r in results)

        if any(r.is_blocked for r in results):
            final_action = ScanAction.BLOCK
        elif any(r.is_flagged for r in results):
            final_action = ScanAction.WARN
        else:
            final_action = ScanAction.ALLOW

        return PipelineScanResult(
            final_action=final_action,
            overall_risk_score=overall_score,
            scanner_results=results,
            blocked_by=blocked_by,
        )

    def add(self, scanner: BaseScanner) -> GuardrailPipeline:
        """Add a scanner to the pipeline (returns self for chaining)."""
        self._scanners.append(scanner)
        return self
