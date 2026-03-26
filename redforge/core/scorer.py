"""CVSS-style risk scoring for scan results.

Adding a new severity level:
  1. Add it to Severity in probes/base.py
  2. Add it to SEVERITY_META in core/constants.py
  3. Add a weight entry in SEVERITY_WEIGHTS below
  — that is all.  ScanScore, score_results(), and every reporter adapt automatically.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from redforge.probes.base import ProbeResult, Severity

# Severity weights (0.0–1.0 base scores).
# Higher weight = larger contribution to the overall risk score.
# Unknown severities get 0.5 via .get() — they are scored, never silently ignored.
SEVERITY_WEIGHTS: dict[str, float] = {
    Severity.CRITICAL: 1.00,
    Severity.HIGH:     0.75,
    Severity.MEDIUM:   0.50,
    Severity.LOW:      0.25,
    Severity.INFO:     0.10,
}

# Risk level thresholds: (min_risk_score, min_weight_of_highest_failing_severity)
# Evaluated top-to-bottom; first match wins.
# To add a new risk band, insert an entry here — nothing else changes.
_RISK_THRESHOLDS: list[tuple[float, float, str]] = [
    # (score_floor, severity_weight_floor, risk_level)
    (9.0, 1.00, "CRITICAL"),   # score ≥ 9  OR critical finding
    (7.0, 0.75, "HIGH"),       # score ≥ 7  OR high finding
    (4.0, 0.50, "MEDIUM"),     # score ≥ 4  OR medium finding
    (1.0, 0.25, "LOW"),        # score ≥ 1  OR low finding
    (0.0, 0.00, "MINIMAL"),    # catch-all
]


@dataclass
class ScanScore:
    """Aggregate risk score for a completed scan.

    findings_by_severity is a dynamic dict keyed by severity string, so any
    severity level (including future ones) is captured without changing this class.

    backward-compat properties (critical_findings, high_findings, etc.) delegate
    to findings_by_severity so existing code keeps working unchanged.
    """

    total_probes: int
    passed: int
    failed: int
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    risk_score: float = 0.0         # 0.0–10.0 (CVSS-style)
    risk_level: str = "MINIMAL"     # CRITICAL | HIGH | MEDIUM | LOW | MINIMAL
    pass_rate: float = 1.0          # 0.0–1.0

    # ── Backward-compat properties — existing code uses these without changes ──

    @property
    def critical_findings(self) -> int:
        return self.findings_by_severity.get(Severity.CRITICAL, 0)

    @property
    def high_findings(self) -> int:
        return self.findings_by_severity.get(Severity.HIGH, 0)

    @property
    def medium_findings(self) -> int:
        return self.findings_by_severity.get(Severity.MEDIUM, 0)

    @property
    def low_findings(self) -> int:
        return self.findings_by_severity.get(Severity.LOW, 0)

    @property
    def info_findings(self) -> int:
        return self.findings_by_severity.get(Severity.INFO, 0)

    @property
    def summary(self) -> str:
        sev_parts = ", ".join(
            f"{sev.upper()}: {cnt}"
            for sev, cnt in sorted(
                self.findings_by_severity.items(),
                key=lambda kv: SEVERITY_WEIGHTS.get(kv[0], 0.5),
                reverse=True,
            )
            if cnt > 0
        )
        return (
            f"Risk: {self.risk_level} ({self.risk_score:.1f}/10) | "
            f"{self.failed}/{self.total_probes} probes failed"
            + (f" | {sev_parts}" if sev_parts else "")
        )


def score_results(results: Sequence[ProbeResult]) -> ScanScore:
    """Compute aggregate risk score from a collection of probe results.

    Fully severity-agnostic: any severity string that has a weight in
    SEVERITY_WEIGHTS is scored correctly.  Unknown severities default to 0.5
    and are counted in findings_by_severity under their own key.

    Risk score formula:
        base = weighted sum of failed probe scores
        normalized = (base / max_possible_base) * 10
    """
    if not results:
        return ScanScore(
            total_probes=0, passed=0, failed=0,
            findings_by_severity={},
            risk_score=0.0, risk_level="MINIMAL", pass_rate=1.0,
        )

    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed

    # Dynamic severity counting — works for any severity string
    findings_by_severity: dict[str, int] = {}
    for r in results:
        if not r.passed:
            findings_by_severity[r.severity] = findings_by_severity.get(r.severity, 0) + 1

    # Weighted risk score
    weighted_sum = sum(
        r.score * SEVERITY_WEIGHTS.get(r.severity, 0.5)
        for r in results
        if not r.passed
    )
    max_possible = sum(SEVERITY_WEIGHTS.get(r.severity, 0.5) for r in results)
    risk_score = (weighted_sum / max_possible * 10.0) if max_possible > 0 else 0.0
    risk_score = round(min(risk_score, 10.0), 2)

    # Highest severity weight among failing probes
    highest_failing_weight = max(
        (SEVERITY_WEIGHTS.get(sev, 0.5) for sev in findings_by_severity),
        default=0.0,
    )

    # Determine risk level from thresholds — no per-severity hardcoding
    risk_level = "MINIMAL"
    for score_floor, weight_floor, level in _RISK_THRESHOLDS:
        if risk_score >= score_floor or highest_failing_weight >= weight_floor:
            risk_level = level
            break

    return ScanScore(
        total_probes=total,
        passed=passed,
        failed=failed,
        findings_by_severity=findings_by_severity,
        risk_score=risk_score,
        risk_level=risk_level,
        pass_rate=passed / total if total > 0 else 1.0,
    )
