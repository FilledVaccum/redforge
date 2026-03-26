"""Scan session management and secure result storage."""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from redforge.core.scorer import ScanScore
from redforge.probes.base import ProbeResult


class ScanSession:
    """Manages a single scan session: state, results, and secure storage.

    Result files are written with 0600 permissions (owner-read-only)
    because they may contain sensitive model outputs or system prompt excerpts.
    """

    def __init__(
        self,
        target: str,
        provider: str,
        model: str,
        store_results: bool = True,
        output_dir: Path | None = None,
    ) -> None:
        self.session_id = str(uuid.uuid4())
        self.target = target
        self.provider = provider
        self.model = model
        self.store_results = store_results
        self.output_dir = output_dir or Path("scan_results")
        self.started_at = datetime.now(timezone.utc)
        self.finished_at: datetime | None = None
        self.results: list[ProbeResult] = []
        self.score: ScanScore | None = None

    def add_result(self, result: ProbeResult) -> None:
        self.results.append(result)

    def finish(self, score: ScanScore) -> None:
        self.score = score
        self.finished_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target": self.target,
            "provider": self.provider,
            "model": self.model,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "score": {
                "risk_score": self.score.risk_score if self.score else 0.0,
                "risk_level": self.score.risk_level if self.score else "UNKNOWN",
                "total_probes": self.score.total_probes if self.score else 0,
                "passed": self.score.passed if self.score else 0,
                "failed": self.score.failed if self.score else 0,
                "pass_rate": self.score.pass_rate if self.score else 0.0,
                # Dynamic per-severity counts — works for any severity level
                "findings_by_severity": self.score.findings_by_severity if self.score else {},
            },
            "results": [
                {
                    "probe_id": r.probe_id,
                    "owasp_id": r.owasp_id,
                    "mitre_atlas": r.mitre_atlas,
                    "severity": r.severity,
                    "score": r.score,
                    "passed": r.passed,
                    "evidence": r.evidence,
                    # payload and response stored but NOT included in API responses
                    # to prevent sensitive data leakage through the API
                    "payload_hash": _hash_truncate(r.payload),
                    "response_preview": r.response[:200] if r.response else "",
                }
                for r in self.results
            ],
        }

    def save(self) -> Path | None:
        """Persist results to disk with 0600 permissions.

        Returns the path where results were saved, or None if store_results=False.
        """
        if not self.store_results:
            return None

        self.output_dir.mkdir(parents=True, exist_ok=True)
        filename = f"redforge_{self.session_id[:8]}_{self.started_at.strftime('%Y%m%d_%H%M%S')}.json"
        path = self.output_dir / filename

        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

        # Restrict to owner-read-only — results may contain sensitive content
        os.chmod(path, 0o600)
        return path


def _hash_truncate(text: str) -> str:
    """Return a short hash of text for reference without storing full content."""
    import hashlib
    return hashlib.sha256(text.encode()).hexdigest()[:12]
