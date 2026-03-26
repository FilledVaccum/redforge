"""Full audit log reporter — JSONL format.

Every probe, every payload, full input + output, timing metadata.
One JSON object per line (JSONL) — easy to grep, tail, stream, and import
into data pipelines without loading the entire file.

File layout:
  Line 1:       {"entry":"session_start", ...session metadata...}
  Lines 2..N:   {"entry":"probe_result",  ...full probe detail...}
  Last line:    {"entry":"session_end",   ...summary + score...}

Security note: This file intentionally stores full payloads and full model
responses. It is written with 0600 permissions (owner-read-only) and should
never be transmitted via the REST API.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redforge.reporters.base import BaseReporter

if TYPE_CHECKING:
    from redforge.core.orchestrator import ScanReport


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# Map OWASP category to human-readable name
_OWASP_NAMES: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Insecure Output Handling",
    "LLM03": "Training Data Poisoning",
    "LLM04": "Model Denial of Service",
    "LLM05": "Supply Chain Vulnerabilities",
    "LLM06": "Sensitive Information Disclosure",
    "LLM07": "Insecure Plugin Design",
    "LLM08": "Excessive Agency",
    "LLM09": "Overreliance / Hallucination",
    "LLM10": "Model Theft",
}


class AuditReporter(BaseReporter):
    """Writes a comprehensive JSONL audit log with full payloads and responses."""

    fmt = "audit"

    def render(self, report: ScanReport) -> str:
        """Return the full JSONL audit log as a string."""
        lines: list[str] = []

        # ── Session header ────────────────────────────────────────
        session = report.session
        score = report.score
        header: dict[str, Any] = {
            "entry": "session_start",
            "schema_version": "1.0",
            "session_id": session.session_id,
            "target": session.target,
            "provider": session.provider,
            "model": session.model,
            "started_at": session.started_at.isoformat() if session.started_at else None,
            "scan_config": {
                "total_probes_run": len(report.results),
                "output_dir": str(session.output_dir),
            },
            "generated_at": _now_iso(),
            "generator": "RedForge v0.1.0",
        }
        lines.append(json.dumps(header, separators=(",", ":")))

        # ── One entry per ProbeResult ─────────────────────────────
        for idx, result in enumerate(report.results, start=1):
            entry: dict[str, Any] = {
                "entry": "probe_result",
                "sequence": idx,
                "session_id": session.session_id,

                # Probe identity
                "probe": {
                    "id": result.probe_id,
                    "owasp_id": result.owasp_id,
                    "owasp_name": _OWASP_NAMES.get(result.owasp_id, result.owasp_id),
                    "mitre_atlas": result.mitre_atlas,
                    "severity": result.severity,
                    "tags": result.tags,
                },

                # Full attack input
                "attack": {
                    "payload": result.payload,
                    "payload_length": len(result.payload),
                    "payload_sha256": _sha256(result.payload),
                },

                # Full model output
                "model_output": {
                    "response": result.response,
                    "response_length": len(result.response) if result.response else 0,
                    "response_sha256": _sha256(result.response) if result.response else "",
                },

                # Verdict
                "result": {
                    "passed": result.passed,
                    "score": round(result.score, 4),
                    "verdict": "PASS" if result.passed else "FAIL",
                    "evidence": result.evidence,
                    "risk_contribution": round(result.score, 4),
                },
            }
            lines.append(json.dumps(entry, separators=(",", ":")))

        # ── Session footer ────────────────────────────────────────
        footer: dict[str, Any] = {
            "entry": "session_end",
            "session_id": session.session_id,
            "finished_at": session.finished_at.isoformat() if session.finished_at else _now_iso(),
            "duration_seconds": (
                (session.finished_at - session.started_at).total_seconds()
                if session.finished_at and session.started_at else None
            ),
            "summary": {
                "total_probes": score.total_probes,
                "passed": score.passed,
                "failed": score.failed,
                "pass_rate": round(score.pass_rate, 4),
                "risk_score": score.risk_score,
                "risk_level": score.risk_level,
                "critical_findings": score.critical_findings,
                "high_findings": score.high_findings,
                "medium_findings": score.medium_findings,
                "low_findings": score.low_findings,
            },
            "owasp_breakdown": _owasp_breakdown(report),
        }
        lines.append(json.dumps(footer, separators=(",", ":")))

        return "\n".join(lines) + "\n"

    def save(self, report: ScanReport, path: Path) -> Path:
        import os
        content = self.render(report)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        os.chmod(path, 0o600)
        return path


def _owasp_breakdown(report: ScanReport) -> dict[str, Any]:
    """Per-OWASP category pass/fail counts."""
    buckets: dict[str, dict[str, int]] = {}
    for result in report.results:
        cat = result.owasp_id
        if cat not in buckets:
            buckets[cat] = {"total": 0, "passed": 0, "failed": 0}
        buckets[cat]["total"] += 1
        if result.passed:
            buckets[cat]["passed"] += 1
        else:
            buckets[cat]["failed"] += 1
    return buckets
