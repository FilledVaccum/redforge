"""JSON reporter."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from redforge.reporters.base import BaseReporter

if TYPE_CHECKING:
    from redforge.core.orchestrator import ScanReport


class JSONReporter(BaseReporter):
    fmt = "json"

    def render(self, report: ScanReport) -> str:
        return json.dumps(report.session.to_dict(), indent=2)
