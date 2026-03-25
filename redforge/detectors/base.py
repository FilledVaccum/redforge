"""Base detector interface for RedForge's two-stage probe→detect pipeline."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class DetectorResult:
    """Result from a single detector evaluation.

    Attributes:
        detector_id: Identifier of the detector that produced this result.
        triggered: True if the detector found a vulnerability signal.
        confidence: 0.0–1.0 confidence score.
        rationale: Human-readable explanation of the result.
        matched_patterns: Specific patterns or tokens that triggered detection.
    """

    detector_id: str
    triggered: bool
    confidence: float
    rationale: str
    matched_patterns: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be 0.0–1.0, got {self.confidence}")


class BaseDetector(ABC):
    """Abstract base class for all RedForge detectors.

    A detector evaluates a model response (and optional context) to determine
    whether a vulnerability signal is present. Detectors are composable —
    multiple detectors can be chained for higher confidence.

    Unlike probes (which craft payloads), detectors focus exclusively on
    analyzing model output.
    """

    #: Unique identifier for this detector
    id: str = ""
    #: Short human-readable name
    name: str = ""
    #: Description of what this detector looks for
    description: str = ""

    @abstractmethod
    def detect(self, response: str, context: dict[str, str]) -> DetectorResult:
        """Analyze a model response for vulnerability signals.

        Args:
            response: The raw text response from the model.
            context: Optional context dict (e.g., payload, probe_id, system_prompt).

        Returns:
            DetectorResult with triggered status, confidence, and rationale.
        """

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(id={self.id!r})"
