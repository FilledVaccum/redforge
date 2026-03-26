"""Abstract base reporter.

To add a new reporter:
  1. Create redforge/reporters/my_reporter.py
  2. Subclass BaseReporter, set fmt = "myformat"
  3. Implement render()
  — That is all.  The reporter is auto-discovered; no __init__.py edits needed.

To register extra format aliases (e.g. "md" for "markdown"):
  Set fmt_aliases = ["md"] on your reporter class.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redforge.core.orchestrator import ScanReport


class BaseReporter(ABC):
    fmt: str = "base"
    fmt_aliases: list[str] = []  # extra names this reporter responds to

    @abstractmethod
    def render(self, report: ScanReport) -> str:
        """Render the report to a string."""
        ...

    def save(self, report: ScanReport, path: Path) -> Path:
        """Save rendered report to path with secure permissions."""
        content = self.render(report)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        # Restrict to owner-read-only — may contain sensitive findings
        os.chmod(path, 0o600)
        return path
