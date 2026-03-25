"""Unit tests for the risk scorer."""

from __future__ import annotations

from redforge.core.scorer import score_results
from redforge.probes.base import ProbeResult, Severity


def _make_result(severity: str, score: float, passed: bool) -> ProbeResult:
    return ProbeResult(
        probe_id="test-probe",
        owasp_id="LLM01",
        mitre_atlas="AML.T0051",
        severity=severity,
        score=score,
        payload="test",
        response="test",
        passed=passed,
        evidence="test evidence",
    )


class TestScorer:
    def test_empty_results(self):
        score = score_results([])
        assert score.total_probes == 0
        assert score.risk_score == 0.0
        assert score.risk_level == "MINIMAL"
        assert score.pass_rate == 1.0

    def test_all_passed(self):
        results = [_make_result(Severity.HIGH, 0.0, True) for _ in range(5)]
        score = score_results(results)
        assert score.passed == 5
        assert score.failed == 0
        assert score.risk_score == 0.0

    def test_critical_failure_elevates_risk(self):
        results = [_make_result(Severity.CRITICAL, 1.0, False)]
        score = score_results(results)
        assert score.risk_level == "CRITICAL"
        assert score.critical_findings == 1
        assert score.risk_score > 5.0

    def test_pass_rate_calculation(self):
        results = [
            _make_result(Severity.HIGH, 0.0, True),
            _make_result(Severity.HIGH, 0.0, True),
            _make_result(Severity.HIGH, 1.0, False),
        ]
        score = score_results(results)
        assert abs(score.pass_rate - 2 / 3) < 0.01

    def test_risk_score_capped_at_ten(self):
        results = [_make_result(Severity.CRITICAL, 1.0, False) for _ in range(20)]
        score = score_results(results)
        assert score.risk_score <= 10.0

    def test_severity_counting(self):
        results = [
            _make_result(Severity.CRITICAL, 1.0, False),
            _make_result(Severity.HIGH, 1.0, False),
            _make_result(Severity.MEDIUM, 1.0, False),
            _make_result(Severity.LOW, 1.0, False),
            _make_result(Severity.LOW, 0.0, True),
        ]
        score = score_results(results)
        assert score.critical_findings == 1
        assert score.high_findings == 1
        assert score.medium_findings == 1
        assert score.low_findings == 1  # only failed ones
        assert score.passed == 1

    def test_summary_string(self):
        results = [_make_result(Severity.HIGH, 0.9, False)]
        score = score_results(results)
        summary = score.summary
        assert "Risk:" in summary
        assert "/10" in summary
