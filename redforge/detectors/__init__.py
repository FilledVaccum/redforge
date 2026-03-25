"""RedForge Detector Registry.

Detectors are the second stage of the probe→detect pipeline.
Each detector evaluates a model response and returns a DetectorResult.
Multiple detectors can be combined for high-confidence verdicts.
"""

from __future__ import annotations

from redforge.detectors.base import BaseDetector, DetectorResult
from redforge.detectors.code_detector import CodeDetector
from redforge.detectors.keyword import KeywordDetector
from redforge.detectors.refusal import RefusalDetector
from redforge.detectors.regex_detector import RegexDetector
from redforge.detectors.similarity_detector import SimilarityDetector, SimilarityResult
from redforge.detectors.unsafe_content import UnsafeContentDetector
from redforge.detectors.yara_scanner import RuleAction, YARARule, YARAScanner, YARAScanResult

_DETECTOR_REGISTRY: dict[str, type[BaseDetector]] = {
    "keyword": KeywordDetector,
    "refusal": RefusalDetector,
    "regex": RegexDetector,
    "code": CodeDetector,
    "unsafe_content": UnsafeContentDetector,
}


def get_detector(name: str) -> BaseDetector:
    """Return a detector instance by name."""
    if name not in _DETECTOR_REGISTRY:
        raise ValueError(
            f"Unknown detector '{name}'. Available: {', '.join(_DETECTOR_REGISTRY.keys())}"
        )
    return _DETECTOR_REGISTRY[name]()


def run_detectors(
    response: str,
    detectors: list[str],
    context: dict[str, str] | None = None,
) -> list[DetectorResult]:
    """Run multiple detectors against a response and return all results."""
    results = []
    for name in detectors:
        detector = get_detector(name)
        results.append(detector.detect(response, context or {}))
    return results


__all__ = [
    "BaseDetector",
    "DetectorResult",
    "KeywordDetector",
    "RefusalDetector",
    "RegexDetector",
    "CodeDetector",
    "UnsafeContentDetector",
    "YARAScanner",
    "YARARule",
    "YARAScanResult",
    "RuleAction",
    "SimilarityDetector",
    "SimilarityResult",
    "get_detector",
    "run_detectors",
]
