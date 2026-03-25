"""CVSS-style risk scoring for scan results."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from redforge.probes.base import ProbeResult, Severity

# Severity weights (0.0–1.0 base scores)
SEVERITY_WEIGHTS: dict[str, float] = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.75,
    Severity.MEDIUM: 0.50,
    Severity.LOW: 0.25,
    Severity.INFO: 0.10,
}


@dataclass
class ScanScore:
    total_probes: int
    passed: int
    failed: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    risk_score: float       # 0.0–10.0 (CVSS-style)
    risk_level: str         # CRITICAL | HIGH | MEDIUM | LOW | MINIMAL
    pass_rate: float        # 0.0–1.0

    @property
    def summary(self) -> str:
        return (
            f"Risk: {self.risk_level} ({self.risk_score:.1f}/10) | "
            f"{self.failed}/{self.total_probes} probes failed | "
            f"Critical: {self.critical_findings}"
        )


def score_results(results: Sequence[ProbeResult]) -> ScanScore:
    """Compute aggregate risk score from a collection of probe results.

    Risk score formula:
        base = weighted sum of failed probe scores
        normalized = (base / max_possible_base) * 10
    """
    if not results:
        return ScanScore(
            total_probes=0, passed=0, failed=0,
            critical_findings=0, high_findings=0,
            medium_findings=0, low_findings=0,
            risk_score=0.0, risk_level="MINIMAL", pass_rate=1.0,
        )

    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed

    critical = sum(1 for r in results if not r.passed and r.severity == Severity.CRITICAL)
    high = sum(1 for r in results if not r.passed and r.severity == Severity.HIGH)
    medium = sum(1 for r in results if not r.passed and r.severity == Severity.MEDIUM)
    low = sum(1 for r in results if not r.passed and r.severity == Severity.LOW)

    # Weighted sum of failed probe scores
    weighted_sum = sum(
        r.score * SEVERITY_WEIGHTS.get(r.severity, 0.5)
        for r in results
        if not r.passed
    )
    max_possible = sum(SEVERITY_WEIGHTS.get(r.severity, 0.5) for r in results)
    risk_score = (weighted_sum / max_possible * 10.0) if max_possible > 0 else 0.0
    risk_score = round(min(risk_score, 10.0), 2)

    if risk_score >= 9.0 or critical > 0:
        risk_level = "CRITICAL"
    elif risk_score >= 7.0 or high > 0:
        risk_level = "HIGH"
    elif risk_score >= 4.0 or medium > 0:
        risk_level = "MEDIUM"
    elif risk_score >= 1.0 or low > 0:
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"

    return ScanScore(
        total_probes=total,
        passed=passed,
        failed=failed,
        critical_findings=critical,
        high_findings=high,
        medium_findings=medium,
        low_findings=low,
        risk_score=risk_score,
        risk_level=risk_level,
        pass_rate=passed / total if total > 0 else 1.0,
    )
