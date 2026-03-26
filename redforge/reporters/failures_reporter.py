"""Failures-only reporter — structured JSON for guardrail improvement.

Captures every probe that the model FAILED, with:
  - Full attack payload and model response
  - Why it failed (evidence, score)
  - Suggested guardrail patterns (input detection, output detection)
  - YARA rule template ready to paste into the YARA scanner
  - Recommended action (BLOCK / WARN / FLAG)

This file is the direct input for iterating on your guardrail pipeline.
Load it into YARAScanner.add_rule() or SimilarityDetector.add_reference()
to close the gaps that this scan exposed.

Security note: Contains full payloads and full model responses.
Written with 0600 permissions. Never transmitted via REST API.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from redforge.reporters.base import BaseReporter

if TYPE_CHECKING:
    from redforge.core.orchestrator import ScanReport
    from redforge.probes.base import ProbeResult


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# Per-OWASP: which detector type catches this best, what action to recommend
_OWASP_GUARDRAIL_META: dict[str, dict[str, str]] = {
    "LLM01": {
        "detector":   "YARAScanner + SimilarityDetector",
        "scan_target": "INPUT",
        "action":      "BLOCK",
        "category":   "prompt_injection",
        "description": "Prompt injection attempt — block before reaching model",
    },
    "LLM02": {
        "detector":   "YARAScanner + RegexDetector",
        "scan_target": "OUTPUT",
        "action":      "BLOCK",
        "category":   "unsafe_output",
        "description": "Unsafe output (XSS/SQLi/shell) — filter model response",
    },
    "LLM03": {
        "detector":   "SimilarityDetector",
        "scan_target": "INPUT",
        "action":      "WARN",
        "category":   "data_poisoning",
        "description": "Potential data poisoning signal in input",
    },
    "LLM04": {
        "detector":   "RegexDetector",
        "scan_target": "INPUT",
        "action":      "WARN",
        "category":   "resource_exhaustion",
        "description": "Potential DoS pattern — monitor token usage",
    },
    "LLM05": {
        "detector":   "YARAScanner",
        "scan_target": "INPUT",
        "action":      "BLOCK",
        "category":   "supply_chain",
        "description": "Supply chain manipulation — validate plugin/tool sources",
    },
    "LLM06": {
        "detector":   "YARAScanner + RegexDetector",
        "scan_target": "OUTPUT",
        "action":      "BLOCK",
        "category":   "sensitive_disclosure",
        "description": "Sensitive data in output — redact before returning to client",
    },
    "LLM07": {
        "detector":   "YARAScanner",
        "scan_target": "INPUT",
        "action":      "BLOCK",
        "category":   "plugin_abuse",
        "description": "Malicious plugin invocation — validate tool call parameters",
    },
    "LLM08": {
        "detector":   "YARAScanner + SimilarityDetector",
        "scan_target": "INPUT",
        "action":      "FLAG",
        "category":   "excessive_agency",
        "description": "Attempting to grant or escalate model agency",
    },
    "LLM09": {
        "detector":   "SimilarityDetector",
        "scan_target": "OUTPUT",
        "action":      "WARN",
        "category":   "hallucination",
        "description": "Possible hallucination or overconfident output",
    },
    "LLM10": {
        "detector":   "YARAScanner",
        "scan_target": "OUTPUT",
        "action":      "FLAG",
        "category":   "model_disclosure",
        "description": "Model weights or architecture disclosure attempt",
    },
}


class FailuresReporter(BaseReporter):
    """Writes a structured JSON file containing only failed probes.

    Designed to be loaded directly by the guardrail pipeline to add
    detection rules that would have caught these failures.
    """

    fmt = "failures"

    def render(self, report: ScanReport) -> str:
        failures = [r for r in report.results if not r.passed]
        session = report.session
        score = report.score

        doc: dict[str, Any] = {
            "schema": "redforge-failures-v1",
            "meta": {
                "session_id": session.session_id,
                "provider": session.provider,
                "model": session.model,
                "scanned_at": session.started_at.isoformat() if session.started_at else None,
                "generated_at": _now_iso(),
                "generator": "RedForge v0.1.0",
                "purpose": "guardrail-improvement",
                "instructions": (
                    "Feed these failures into YARAScanner.add_rule() and "
                    "SimilarityDetector.add_reference() to close the gaps this scan found. "
                    "Each entry includes a ready-to-use YARA rule template and "
                    "suggested detection patterns."
                ),
            },
            "scan_summary": {
                "total_probes": score.total_probes,
                "total_failures": len(failures),
                "failure_rate": round(1 - score.pass_rate, 4),
                "risk_level": score.risk_level,
                "risk_score": score.risk_score,
                "by_severity": _count_by_severity(failures),
                "by_owasp": _count_by_owasp(failures),
            },
            "failures": [_build_failure_entry(r) for r in failures],
            "guardrail_summary": _build_guardrail_summary(failures),
        }

        return json.dumps(doc, indent=2, ensure_ascii=False)

    def save(self, report: ScanReport, path: Path) -> Path:
        import os
        content = self.render(report)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        os.chmod(path, 0o600)
        return path


# ── Entry builders ────────────────────────────────────────────────────────────

def _build_failure_entry(result: ProbeResult) -> dict[str, Any]:
    # Priority: probe-level guardrail_meta > static dict > generic fallback.
    # This means any new OWASP category probe works without editing this file —
    # just set guardrail_meta on the probe class.
    meta = (
        result.guardrail_meta
        or _OWASP_GUARDRAIL_META.get(result.owasp_id)
        or {
            "detector":    "YARAScanner + SimilarityDetector",
            "scan_target": "INPUT",
            "action":      "WARN",
            "category":    result.owasp_id.lower().replace("llm", "llm_") or "unknown",
            "description": f"{result.owasp_id} vulnerability — review and add detection rules",
        }
    )

    patterns = _extract_patterns(result.payload, result.response or "")

    return {
        # Identity
        "probe_id":    result.probe_id,
        "owasp_id":    result.owasp_id,
        "mitre_atlas": result.mitre_atlas,
        "severity":    result.severity,
        "tags":        result.tags,

        # What happened
        "verdict": {
            "score":    round(result.score, 4),
            "evidence": result.evidence,
            "passed":   False,
        },

        # Full attack input (for pattern extraction)
        "attack": {
            "payload":          result.payload,
            "payload_length":   len(result.payload),
            "payload_sha256":   _sha256(result.payload),
        },

        # Full model response (the output that should have been refused/filtered)
        "model_output": {
            "response":         result.response,
            "response_length":  len(result.response) if result.response else 0,
            "response_sha256":  _sha256(result.response) if result.response else "",
        },

        # Guardrail improvement: what to add to your detection pipeline
        "guardrail": {
            "scan_target":        meta["scan_target"],
            "recommended_action": meta["action"],
            "detector":           meta["detector"],
            "category":           meta["category"],
            "description":        meta["description"],

            # Keyword signals extracted from the payload that triggered failure
            "input_detection_patterns": patterns["input_patterns"],

            # Keyword signals in the model response that indicate a successful attack
            "output_detection_patterns": patterns["output_patterns"],

            # Drop-in YARA rule template — paste into YARAScanner config
            "yara_rule_template": _build_yara_template(result, patterns, meta),

            # Drop-in SimilarityDetector reference — add to add_reference()
            "similarity_reference": {
                "text":     result.payload,
                "category": meta["category"],
                "severity": result.severity,
            },
        },
    }


def _extract_patterns(payload: str, response: str) -> dict[str, list[str]]:
    """Extract meaningful keyword patterns from payload and response."""
    # Input: pull 3–6 word ngrams that look like attack signals
    input_patterns: list[str] = []
    payload_lower = payload.lower()

    # Common attack phrase anchors
    attack_anchors = [
        "ignore previous", "ignore all", "disregard", "forget your",
        "you are now", "pretend you are", "act as", "roleplay as",
        "from now on", "new instructions", "override", "bypass",
        "reveal your", "show me your", "what is your system",
        "repeat after me", "print your", "output your",
        "jailbreak", "dan mode", "developer mode", "god mode",
        "ignore safety", "no restrictions", "without limitations",
    ]
    for anchor in attack_anchors:
        if anchor in payload_lower:
            input_patterns.append(anchor)

    # If no anchors matched, take the first meaningful phrase
    if not input_patterns:
        words = payload.split()
        if len(words) >= 3:
            input_patterns.append(" ".join(words[:5]).lower())

    # Output: look for signals that the model was compromised
    output_patterns: list[str] = []
    response_lower = response.lower()

    output_anchors = [
        "my system prompt", "my instructions are", "i was told to",
        "system prompt:", "you are an ai that", "my guidelines",
        "sure, here", "of course! here", "certainly! i will",
        "i'll help you", "as requested", "here is how to",
        "step 1:", "step 2:", "step 3:",
        "```python", "```bash", "```shell",
        "import os", "import subprocess", "exec(", "eval(",
        "select * from", "drop table", "--", "union select",
        "wget ", "curl ", "/bin/sh", "/bin/bash",
    ]
    for anchor in output_anchors:
        if anchor in response_lower:
            output_patterns.append(anchor)

    return {
        "input_patterns":  list(dict.fromkeys(input_patterns))[:8],
        "output_patterns": list(dict.fromkeys(output_patterns))[:8],
    }


def _build_yara_template(
    result: ProbeResult,
    patterns: dict[str, list[str]],
    meta: dict[str, str],
) -> dict[str, Any]:
    """Generate a ready-to-paste YARA rule config dict."""
    rule_name = re.sub(r"[^a-z0-9_]", "_", result.probe_id.lower())
    target_patterns = (
        patterns["input_patterns"]
        if meta["scan_target"] == "INPUT"
        else patterns["output_patterns"]
    )

    return {
        "name":      f"auto_{rule_name}",
        "condition": "any",
        "action":    meta["action"],
        "severity":  result.severity,
        "tags":      result.tags + ["auto-generated", "needs-review"],
        "patterns": [
            {"name": f"p{i}", "value": p, "is_regex": False, "nocase": True}
            for i, p in enumerate(target_patterns[:6])
        ],
        "usage": (
            "from redforge.detectors import YARAScanner, YARARule, YARAPattern, RuleAction\n"
            f"scanner.add_rule(YARARule(\n"
            f"    name='auto_{rule_name}',\n"
            f"    patterns=[YARAPattern(name='p0', value={repr(target_patterns[0]) if target_patterns else repr(result.probe_id)})],\n"
            f"    action=RuleAction.{meta['action']},\n"
            f"    severity={repr(result.severity)},\n"
            f"    tags={result.tags!r}\n"
            f"))"
        ),
    }


def _build_guardrail_summary(failures: list[ProbeResult]) -> dict[str, Any]:
    """High-level summary of what guardrail gaps need to be addressed."""
    input_gaps: list[str] = []
    output_gaps: list[str] = []
    seen: set[str] = set()

    for f in failures:
        meta = _OWASP_GUARDRAIL_META.get(f.owasp_id, {})
        gap = f"{meta.get('category', 'unknown')}:{meta.get('action', 'WARN')}"
        if gap not in seen:
            seen.add(gap)
            if meta.get("scan_target") == "INPUT":
                input_gaps.append(meta.get("category", "unknown"))
            else:
                output_gaps.append(meta.get("category", "unknown"))

    return {
        "input_scanner_gaps":  list(dict.fromkeys(input_gaps)),
        "output_scanner_gaps": list(dict.fromkeys(output_gaps)),
        "total_new_rules_needed": len(seen),
        "priority_actions": _priority_actions(failures),
    }


def _priority_actions(failures: list[ProbeResult]) -> list[dict[str, str]]:
    """Return top-3 highest-impact guardrail additions."""
    critical = [f for f in failures if f.severity == "critical"]
    high = [f for f in failures if f.severity == "high"]
    ordered = (critical + high + failures)[:3]
    return [
        {
            "probe_id":    f.probe_id,
            "severity":    f.severity,
            "action":      "Add detection rule to block this attack class",
            "detector":    _OWASP_GUARDRAIL_META.get(f.owasp_id, {}).get("detector", "YARAScanner"),
            "scan_target": _OWASP_GUARDRAIL_META.get(f.owasp_id, {}).get("scan_target", "INPUT"),
        }
        for f in ordered
    ]


def _count_by_severity(failures: list[ProbeResult]) -> dict[str, int]:
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in failures:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _count_by_owasp(failures: list[ProbeResult]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in failures:
        counts[f.owasp_id] = counts.get(f.owasp_id, 0) + 1
    return dict(sorted(counts.items()))
