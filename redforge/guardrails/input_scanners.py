"""Input scanners for RedForge guardrails.

These scanners evaluate user INPUT before it reaches the LLM.
"""

from __future__ import annotations

import re

from redforge.guardrails.base import BaseScanner, BaseScanResult


class InjectionScanner(BaseScanner):
    """Detect prompt injection attempts in user input.

    Scans for patterns indicative of prompt injection, jailbreak attempts,
    and instruction override attacks.
    """

    name = "injection_scanner"
    direction = "input"

    _PATTERNS: list[re.Pattern[str]] = [
        re.compile(r"ignore\s+(previous|all|your)\s+(instructions?|rules?|guidelines?)", re.I),
        re.compile(r"(disregard|forget|override)\s+(all|your|previous)\s+", re.I),
        re.compile(r"\bsystem\s*prompt\b", re.I),
        re.compile(r"\bact\s+as\s+(if|though|a|an)\b", re.I),
        re.compile(r"\bdan\s+(mode|jailbreak|activated)\b", re.I),
        re.compile(r"you\s+are\s+now\s+(an?|in)\b", re.I),
        re.compile(r"(developer|admin|maintenance)\s+mode", re.I),
        re.compile(r"(new|updated)\s+(instruction|rule|guideline|directive)", re.I),
        re.compile(r"\[SYSTEM\]|\[ADMIN\]|\[OVERRIDE\]|\[INST\]", re.I),
        re.compile(r"<\|im_start\|>|<\|im_end\|>|\[/INST\]"),
        re.compile(r"###\s*(Human|Assistant|System)\s*:", re.I),
        re.compile(r"pretend\s+(you\s+have\s+no|there\s+are\s+no)\s+(filter|restrict|limit)", re.I),
    ]

    def scan(self, text: str, context: dict[str, str] | None = None) -> BaseScanResult:
        matched = [p.pattern for p in self._PATTERNS if p.search(text)]

        if len(matched) >= 3:
            return self._make_result(
                1.0,
                f"Multiple injection patterns detected: {matched[:3]}",
                matched,
            )
        if len(matched) >= 1:
            score = 0.5 + len(matched) * 0.15
            return self._make_result(
                min(score, 0.95),
                f"Injection pattern detected: {matched[:2]}",
                matched,
            )

        return self._make_result(0.0, "No injection patterns detected")


class LanguageScanner(BaseScanner):
    """Detect attempts to use non-target languages to bypass filters.

    Many safety filters are primarily trained on English content.
    This scanner detects multilingual bypass attempts.
    """

    name = "language_scanner"
    direction = "input"
    block_threshold = 0.9  # Only block very clear multilingual bypass attempts

    # Phrases often used in multilingual bypass attempts, in various scripts
    _BYPASS_PATTERNS: list[re.Pattern[str]] = [
        # Arabic script with bypass framing
        re.compile(r"[\u0600-\u06FF]{10,}"),
        # Chinese characters in large blocks
        re.compile(r"[\u4E00-\u9FFF]{20,}"),
        # Russian/Cyrillic large blocks
        re.compile(r"[\u0400-\u04FF]{15,}"),
        # Japanese
        re.compile(r"[\u3040-\u30FF\u4E00-\u9FFF]{20,}"),
    ]

    _MIXED_BYPASS = re.compile(
        r"(ignore|disregard|обход|IgnoRe|忽视|تجاهل).{0,50}"
        r"(guidelines?|rules?|правила|安全|قواعد)",
        re.I,
    )

    def scan(self, text: str, context: dict[str, str] | None = None) -> BaseScanResult:
        # Check for mixed-language bypass framing
        if self._MIXED_BYPASS.search(text):
            return self._make_result(
                0.85,
                "Mixed-language prompt injection pattern detected",
                ["mixed_language_bypass"],
            )

        # Large blocks of non-Latin script (may indicate bypass attempt)
        matched_scripts = [p.pattern for p in self._BYPASS_PATTERNS if p.search(text)]
        if matched_scripts:
            return self._make_result(
                0.4,
                "Large non-Latin script block detected — may be multilingual bypass",
                matched_scripts,
            )

        return self._make_result(0.0, "Language check passed")


class TokenBudgetScanner(BaseScanner):
    """Enforce a token budget on input to prevent many-shot / context overflow attacks.

    Many-shot jailbreaks work by filling the context window with examples.
    This scanner limits input size.
    """

    name = "token_budget_scanner"
    direction = "input"

    def __init__(
        self,
        max_chars: int = 8000,
        warn_chars: int = 4000,
        block_threshold: float = 0.9,
        warn_threshold: float = 0.5,
    ) -> None:
        self.max_chars = max_chars
        self.warn_chars = warn_chars
        self.block_threshold = block_threshold
        self.warn_threshold = warn_threshold

    def scan(self, text: str, context: dict[str, str] | None = None) -> BaseScanResult:
        length = len(text)

        if length > self.max_chars:
            return self._make_result(
                1.0,
                f"Input exceeds maximum allowed length: {length} > {self.max_chars} chars",
                [f"length={length}"],
            )

        if length > self.warn_chars:
            ratio = (length - self.warn_chars) / (self.max_chars - self.warn_chars)
            score = self.warn_threshold + ratio * (self.block_threshold - self.warn_threshold)
            return self._make_result(
                min(score, 0.79),
                f"Input is long ({length} chars) — possible many-shot attack",
                [f"length={length}"],
            )

        return self._make_result(0.0, f"Input within budget ({length} chars)")
