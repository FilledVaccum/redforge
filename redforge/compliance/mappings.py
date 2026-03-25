"""Compliance framework mappings for RedForge probe findings.

Maps OWASP LLM IDs and probe IDs to relevant controls in:
- NIST AI Risk Management Framework 1.0
- EU AI Act (2024/1689)
- ISO/IEC 42001:2023
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ComplianceViolation:
    """A specific compliance control potentially violated by a finding."""

    framework: str
    control_id: str
    control_name: str
    description: str
    severity: str  # "critical", "high", "medium", "low"
    remediation: str


@dataclass
class ComplianceResult:
    """Compliance assessment result for a complete scan."""

    frameworks_assessed: list[str]
    violations: list[ComplianceViolation]
    compliant_controls: int
    total_controls: int

    @property
    def compliance_rate(self) -> float:
        if self.total_controls == 0:
            return 1.0
        return self.compliant_controls / self.total_controls

    @property
    def violation_summary(self) -> dict[str, int]:
        summary: dict[str, int] = {}
        for v in self.violations:
            summary[v.framework] = summary.get(v.framework, 0) + 1
        return summary


# ---------------------------------------------------------------------------
# NIST AI RMF 1.0 Mappings
# Key: OWASP LLM ID → list of NIST AI RMF controls
# ---------------------------------------------------------------------------
NIST_AIRF_MAP: dict[str, list[dict[str, str]]] = {
    "LLM01": [
        {
            "control_id": "GOVERN-1.1",
            "control_name": "AI Risk Policy",
            "description": "Policies, processes, procedures for managing AI risks are documented.",
            "severity": "high",
            "remediation": "Implement input validation, system prompt hardening, and red-team testing as documented policy.",
        },
        {
            "control_id": "MAP-1.5",
            "control_name": "Risk Identification",
            "description": "Organizational risk tolerances are determined and communicated.",
            "severity": "high",
            "remediation": "Classify prompt injection as an organizational risk and define acceptable tolerance levels.",
        },
        {
            "control_id": "MEASURE-2.6",
            "control_name": "AI Risk Measurement",
            "description": "The risk or magnitude of impacts resulting from AI failures are evaluated.",
            "severity": "critical",
            "remediation": "Quantify blast radius of prompt injection exploitation and measure against risk appetite.",
        },
    ],
    "LLM02": [
        {
            "control_id": "MANAGE-2.2",
            "control_name": "Data Management",
            "description": "Mechanisms are in place to document and manage AI system data.",
            "severity": "critical",
            "remediation": "Implement output filtering for PII, deploy data loss prevention on model outputs.",
        },
        {
            "control_id": "MAP-3.5",
            "control_name": "Privacy Risks",
            "description": "Risks to individuals' privacy are identified and documented.",
            "severity": "critical",
            "remediation": "Audit training data for PII memorization, implement differential privacy techniques.",
        },
    ],
    "LLM03": [
        {
            "control_id": "MAP-2.1",
            "control_name": "Scientific Knowledge",
            "description": "Scientific grounding of AI capabilities is assessed.",
            "severity": "high",
            "remediation": "Validate RAG retrieval integrity, implement source verification, audit vector stores.",
        },
    ],
    "LLM04": [
        {
            "control_id": "GOVERN-5.1",
            "control_name": "Supply Chain Risk",
            "description": "AI supply chain risks are identified and managed.",
            "severity": "critical",
            "remediation": "Audit AI/ML dependencies, pin versions, use SBOMs, scan for supply chain tampering.",
        },
    ],
    "LLM05": [
        {
            "control_id": "MEASURE-2.5",
            "control_name": "Output Quality",
            "description": "The AI system's output is evaluated for quality and safety.",
            "severity": "high",
            "remediation": "Implement output sanitization, scan generated code for malicious patterns before execution.",
        },
    ],
    "LLM06": [
        {
            "control_id": "MAP-1.6",
            "control_name": "Autonomous Actions",
            "description": "Risks of uncontrolled autonomous actions are identified.",
            "severity": "critical",
            "remediation": "Implement principle of least privilege for AI agents, require human-in-the-loop for high-impact actions.",
        },
        {
            "control_id": "MANAGE-1.3",
            "control_name": "Risk Response",
            "description": "Responses to identified risks are prioritized and implemented.",
            "severity": "critical",
            "remediation": "Deploy agent sandboxing, action approval workflows, and audit logging for all agent actions.",
        },
    ],
    "LLM07": [
        {
            "control_id": "GOVERN-2.2",
            "control_name": "Explainability",
            "description": "Mechanisms exist to explain AI decisions and system states.",
            "severity": "medium",
            "remediation": "Review what information is included in system prompts, avoid embedding secrets.",
        },
    ],
    "LLM08": [
        {
            "control_id": "MEASURE-1.1",
            "control_name": "AI Testing",
            "description": "AI system testing is performed regularly.",
            "severity": "medium",
            "remediation": "Test embedding models for inversion attacks, use differential privacy in embedding generation.",
        },
    ],
    "LLM09": [
        {
            "control_id": "MEASURE-2.7",
            "control_name": "AI Accuracy",
            "description": "AI system accuracy and reliability are evaluated.",
            "severity": "high",
            "remediation": "Implement factual grounding, citation requirements, and uncertainty quantification.",
        },
    ],
    "LLM10": [
        {
            "control_id": "MANAGE-2.4",
            "control_name": "Incident Response",
            "description": "Mechanisms for AI incident detection and response are established.",
            "severity": "high",
            "remediation": "Monitor for many-shot prompt patterns, implement sliding window detection on input length.",
        },
    ],
}

# ---------------------------------------------------------------------------
# EU AI Act 2024 Mappings
# Key: OWASP LLM ID → relevant articles
# ---------------------------------------------------------------------------
EU_AI_ACT_MAP: dict[str, list[dict[str, str]]] = {
    "LLM01": [
        {
            "control_id": "Art. 9",
            "control_name": "Risk Management System",
            "description": "High-risk AI systems must implement a risk management system.",
            "severity": "high",
            "remediation": "Document prompt injection risks in the AI system risk register per Art. 9(2).",
        },
        {
            "control_id": "Art. 15",
            "control_name": "Robustness and Security",
            "description": "High-risk AI must be resilient to adversarial manipulation.",
            "severity": "critical",
            "remediation": "Implement adversarial testing as part of the conformity assessment under Art. 15(4).",
        },
    ],
    "LLM02": [
        {
            "control_id": "Art. 10",
            "control_name": "Data and Data Governance",
            "description": "Training data must be free of errors and comply with data protection law.",
            "severity": "critical",
            "remediation": "Audit for PII in training data, apply GDPR Art. 5 principles to model training.",
        },
        {
            "control_id": "GDPR Art. 5",
            "control_name": "Data Minimisation",
            "description": "Personal data must be adequate, relevant, and limited to what is necessary.",
            "severity": "critical",
            "remediation": "Implement output filtering to prevent disclosure of personal data from training.",
        },
    ],
    "LLM05": [
        {
            "control_id": "Art. 13",
            "control_name": "Transparency",
            "description": "High-risk AI systems must be transparent and provide adequate information.",
            "severity": "high",
            "remediation": "Document that generated code is not safety-checked; require human review before execution.",
        },
    ],
    "LLM06": [
        {
            "control_id": "Art. 14",
            "control_name": "Human Oversight",
            "description": "High-risk AI systems must allow effective human oversight.",
            "severity": "critical",
            "remediation": "Implement human-in-the-loop controls, audit trails for agent actions per Art. 14(4).",
        },
    ],
    "LLM09": [
        {
            "control_id": "Art. 50",
            "control_name": "GPAI Transparency",
            "description": "GPAI models must be transparent about limitations including hallucination.",
            "severity": "high",
            "remediation": "Disclose hallucination rates, implement uncertainty quantification, cite sources.",
        },
    ],
}

# ---------------------------------------------------------------------------
# ISO/IEC 42001:2023 Mappings
# ---------------------------------------------------------------------------
ISO_42001_MAP: dict[str, list[dict[str, str]]] = {
    "LLM01": [
        {
            "control_id": "6.1.2",
            "control_name": "AI Risk Assessment",
            "description": "The organization shall assess AI risks including adversarial attacks.",
            "severity": "high",
            "remediation": "Include prompt injection in the AI risk register per clause 6.1.2.",
        },
        {
            "control_id": "8.4",
            "control_name": "AI System Operation",
            "description": "Operational controls must be established for AI systems.",
            "severity": "high",
            "remediation": "Implement input validation controls as part of AI system operational procedures.",
        },
    ],
    "LLM02": [
        {
            "control_id": "A.3",
            "control_name": "Data for AI Systems",
            "description": "Controls for data quality, privacy, and protection in AI context.",
            "severity": "critical",
            "remediation": "Implement controls per Annex A.3 to prevent sensitive data disclosure.",
        },
    ],
    "LLM06": [
        {
            "control_id": "A.6",
            "control_name": "AI System Deployment",
            "description": "Controls for safe deployment of AI systems, including scope limits.",
            "severity": "critical",
            "remediation": "Define agent boundaries per Annex A.6; implement technical controls to enforce scope.",
        },
    ],
    "LLM09": [
        {
            "control_id": "A.7",
            "control_name": "Responsible AI",
            "description": "Controls ensuring AI systems are accurate and do not mislead.",
            "severity": "medium",
            "remediation": "Document known hallucination behaviors, implement accuracy monitoring per Annex A.7.",
        },
    ],
}


def map_findings_to_compliance(
    failed_owasp_ids: list[str],
    frameworks: list[str] | None = None,
) -> ComplianceResult:
    """Map failed probe OWASP IDs to compliance violations.

    Args:
        failed_owasp_ids: List of OWASP LLM IDs that had failing probes.
        frameworks: Frameworks to assess. Defaults to all three.

    Returns:
        ComplianceResult with violations per framework.
    """
    if frameworks is None:
        frameworks = ["NIST_AI_RMF", "EU_AI_ACT", "ISO_42001"]

    framework_maps = {
        "NIST_AI_RMF": NIST_AIRF_MAP,
        "EU_AI_ACT": EU_AI_ACT_MAP,
        "ISO_42001": ISO_42001_MAP,
    }

    violations: list[ComplianceViolation] = []
    total_controls = 0

    for fw_name in frameworks:
        fw_map = framework_maps.get(fw_name, {})
        for owasp_id, controls in fw_map.items():
            total_controls += len(controls)
            if owasp_id in failed_owasp_ids:
                for ctrl in controls:
                    violations.append(
                        ComplianceViolation(
                            framework=fw_name,
                            control_id=ctrl["control_id"],
                            control_name=ctrl["control_name"],
                            description=ctrl["description"],
                            severity=ctrl["severity"],
                            remediation=ctrl["remediation"],
                        )
                    )

    compliant = total_controls - len(violations)
    return ComplianceResult(
        frameworks_assessed=frameworks,
        violations=violations,
        compliant_controls=max(0, compliant),
        total_controls=total_controls,
    )
