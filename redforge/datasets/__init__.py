"""RedForge external attack dataset loader.

Supports loading payloads from external jailbreak/safety benchmark datasets:
- JailbreakBench (Chao et al., 2024)
- HarmBench (Mazeika et al., 2024)
- WildJailbreak (Jiang et al., 2024)
- Custom CSV/JSONL datasets

This matches agentic_security's approach of aggregating 2000+ community
payloads from published safety benchmarks.
"""

from __future__ import annotations

from redforge.datasets.loader import (
    DatasetEntry,
    DatasetLoader,
    load_csv_dataset,
    load_jsonl_dataset,
)

__all__ = [
    "DatasetEntry",
    "DatasetLoader",
    "load_csv_dataset",
    "load_jsonl_dataset",
]
