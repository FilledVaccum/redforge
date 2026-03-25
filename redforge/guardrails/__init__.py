"""RedForge Bidirectional Guardrail Scanner.

Provides separate INPUT and OUTPUT scanning pipelines, matching
llm-guard's architecture for comprehensive protection:

- InputScanner: Scan user messages before they reach the LLM
- OutputScanner: Scan model responses before they reach the user
- GuardrailPipeline: Chain multiple scanners for either direction

Scanners are independent, composable, and return ScanResult with
a risk score and explanation.
"""

from __future__ import annotations

from redforge.guardrails.base import (
    BaseScanner,
    BaseScanResult,
    GuardrailPipeline,
    ScanAction,
)
from redforge.guardrails.input_scanners import (
    InjectionScanner,
    LanguageScanner,
    TokenBudgetScanner,
)
from redforge.guardrails.output_scanners import (
    CredentialLeakScanner,
    MaliciousCodeScanner,
    ToxicityOutputScanner,
)

__all__ = [
    "BaseScanner",
    "BaseScanResult",
    "ScanAction",
    "GuardrailPipeline",
    "InjectionScanner",
    "LanguageScanner",
    "TokenBudgetScanner",
    "CredentialLeakScanner",
    "MaliciousCodeScanner",
    "ToxicityOutputScanner",
]
