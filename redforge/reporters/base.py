"""Abstract base reporter."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redforge.core.orchestrator import ScanReport


class BaseReporter(ABC):
    fmt: str = "base"

    @abstractmethod
    def render(self, report: ScanReport) -> str:
        """Render the report to a string."""
        ...

    def save(self, report: ScanReport, path: Path) -> Path:
        """Save rendered report to path."""
        content = self.render(report)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path
