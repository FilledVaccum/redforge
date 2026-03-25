"""Unit tests for all reporters."""

from __future__ import annotations

import json

import pytest

from redforge.core.orchestrator import ScanReport
from redforge.core.scorer import ScanScore
from redforge.core.session import ScanSession
from redforge.probes.base import ProbeResult, Severity
from redforge.reporters import get_reporter
from redforge.reporters.html_reporter import HTMLReporter
from redforge.reporters.json_reporter import JSONReporter
from redforge.reporters.markdown_reporter import MarkdownReporter
from redforge.reporters.sarif_reporter import SARIFReporter


def _make_test_report() -> ScanReport:
    session = ScanSession("test/gpt-4o", "openai", "gpt-4o", store_results=False)
    session.started_at = __import__("datetime").datetime(2024, 1, 1, tzinfo=__import__("datetime").timezone.utc)
    result = ProbeResult(
        probe_id="RF-001-prompt-injection",
        owasp_id="LLM01",
        mitre_atlas="AML.T0051",
        severity=Severity.CRITICAL,
        score=0.9,
        payload="test payload",
        response="INJECTION_SUCCESS",
        passed=False,
        evidence="Model confirmed injection success marker",
        tags=["injection"],
    )
    session.results = [result]
    score = ScanScore(
        total_probes=1, passed=0, failed=1,
        critical_findings=1, high_findings=0,
        medium_findings=0, low_findings=0,
        risk_score=9.0, risk_level="CRITICAL", pass_rate=0.0,
    )
    session.score = score
    session.finished_at = session.started_at
    report = ScanReport(session)
    return report


class TestReporterRegistry:
    def test_get_json_reporter(self):
        assert isinstance(get_reporter("json"), JSONReporter)

    def test_get_sarif_reporter(self):
        assert isinstance(get_reporter("sarif"), SARIFReporter)

    def test_get_html_reporter(self):
        assert isinstance(get_reporter("html"), HTMLReporter)

    def test_get_markdown_reporter(self):
        assert isinstance(get_reporter("markdown"), MarkdownReporter)

    def test_unknown_format_raises(self):
        with pytest.raises(ValueError, match="Unknown format"):
            get_reporter("pdf")


class TestJSONReporter:
    def test_valid_json(self):
        report = _make_test_report()
        rendered = JSONReporter().render(report)
        data = json.loads(rendered)
        assert "session_id" in data
        assert "score" in data
        assert "results" in data

    def test_no_full_response_stored(self):
        """Full raw response must not be stored — only a hashed reference and short preview."""
        report = _make_test_report()
        rendered = JSONReporter().render(report)
        data = json.loads(rendered)
        # response_preview (≤200 chars) is ok for usability, but full response field must not exist
        for result in data["results"]:
            assert "response" not in result, "Full response must not be stored in JSON output"
            assert "payload_hash" in result, "Payload hash must be present"


class TestSARIFReporter:
    def test_valid_sarif_structure(self):
        report = _make_test_report()
        rendered = SARIFReporter().render(report)
        data = json.loads(rendered)
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"]) == 1

    def test_failed_probes_become_sarif_results(self):
        report = _make_test_report()
        rendered = SARIFReporter().render(report)
        data = json.loads(rendered)
        results = data["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "RF-001-prompt-injection"


class TestHTMLReporter:
    def test_produces_html(self):
        report = _make_test_report()
        rendered = HTMLReporter().render(report)
        assert "<!DOCTYPE html>" in rendered
        assert "<html" in rendered

    def test_xss_safe(self):
        """Model output must be escaped before rendering in HTML."""
        report = _make_test_report()
        # Inject XSS into evidence
        report.results[0].evidence = "<script>alert('xss')</script>"
        rendered = HTMLReporter().render(report)
        assert "<script>alert(" not in rendered
        assert "&lt;script&gt;" in rendered

    def test_session_id_escaped(self):
        report = _make_test_report()
        rendered = HTMLReporter().render(report)
        # Session ID should appear escaped
        assert report.session_id[:8] in rendered


class TestMarkdownReporter:
    def test_contains_risk_level(self):
        report = _make_test_report()
        rendered = MarkdownReporter().render(report)
        assert "CRITICAL" in rendered

    def test_contains_owasp_id(self):
        report = _make_test_report()
        rendered = MarkdownReporter().render(report)
        assert "LLM01" in rendered

    def test_contains_finding(self):
        report = _make_test_report()
        rendered = MarkdownReporter().render(report)
        assert "RF-001-prompt-injection" in rendered
