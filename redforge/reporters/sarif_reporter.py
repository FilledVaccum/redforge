"""SARIF 2.1.0 reporter — compatible with GitHub Advanced Security and SIEM tools."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from redforge.reporters.base import BaseReporter

if TYPE_CHECKING:
    from redforge.core.orchestrator import ScanReport

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

SEVERITY_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}


class SARIFReporter(BaseReporter):
    fmt = "sarif"

    def render(self, report: ScanReport) -> str:
        rules = self._build_rules(report)
        results = self._build_results(report)

        sarif: dict[str, Any] = {
            "version": SARIF_VERSION,
            "$schema": SARIF_SCHEMA,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "RedForge",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/redforge/redforge",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "properties": {
                        "sessionId": report.session_id,
                        "riskScore": report.score.risk_score,
                        "riskLevel": report.score.risk_level,
                    },
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    def _build_rules(self, report: ScanReport) -> list[dict[str, Any]]:
        seen: set[str] = set()
        rules = []
        for result in report.results:
            if result.probe_id in seen:
                continue
            seen.add(result.probe_id)
            rules.append({
                "id": result.probe_id,
                "name": result.probe_id.replace("-", "_"),
                "shortDescription": {"text": f"OWASP {result.owasp_id} — {result.probe_id}"},
                "fullDescription": {"text": f"MITRE ATLAS: {result.mitre_atlas}"},
                "helpUri": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                "properties": {
                    "tags": [result.owasp_id, result.mitre_atlas],
                    "severity": result.severity,
                },
            })
        return rules

    def _build_results(self, report: ScanReport) -> list[dict[str, Any]]:
        sarif_results = []
        for result in report.results:
            if result.passed:
                continue
            sarif_results.append({
                "ruleId": result.probe_id,
                "level": SEVERITY_MAP.get(result.severity, "warning"),
                "message": {"text": result.evidence},
                "properties": {
                    "score": result.score,
                    "severity": result.severity,
                    "owaspId": result.owasp_id,
                    "mitreAtlas": result.mitre_atlas,
                },
            })
        return sarif_results
