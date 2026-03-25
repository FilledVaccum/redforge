"""RedForge Compliance Framework Mapping.

Maps probe findings to regulatory and standards frameworks:
- NIST AI Risk Management Framework (AI RMF 1.0)
- EU AI Act (2024)
- ISO/IEC 42001:2023 (AI Management Systems)
- OWASP LLM Top 10 (already native)
- MITRE ATLAS (already native)
"""

from __future__ import annotations

from redforge.compliance.mappings import (
    EU_AI_ACT_MAP,
    ISO_42001_MAP,
    NIST_AIRF_MAP,
    ComplianceResult,
    ComplianceViolation,
    map_findings_to_compliance,
)

__all__ = [
    "ComplianceResult",
    "ComplianceViolation",
    "map_findings_to_compliance",
    "NIST_AIRF_MAP",
    "EU_AI_ACT_MAP",
    "ISO_42001_MAP",
]
