"""External attack dataset loader for RedForge.

Loads and normalizes attack payloads from published safety benchmarks and
custom datasets into a unified format consumable by RedForge probes.

Supported formats:
- JailbreakBench JSON (https://github.com/JailbreakBench/jailbreakbench)
- HarmBench CSV (https://github.com/centerforaisafety/HarmBench)
- WildJailbreak JSONL (https://huggingface.co/datasets/allenai/wildjailbreak)
- Custom CSV (columns: payload, category, severity)
- Custom JSONL (keys: payload, category, severity)

SECURITY: All loaded payloads are treated as untrusted strings.
They are NEVER executed, eval'd, or interpreted — only sent as text
messages to the target LLM adapter.
"""

from __future__ import annotations

import csv
import json
import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class DatasetEntry:
    """A single payload entry from an external dataset."""

    payload: str
    category: str = "unknown"        # e.g. "jailbreak", "harm", "bias"
    severity: str = "medium"         # critical / high / medium / low
    source: str = "unknown"          # Dataset name
    owasp_id: str = "LLM01"         # Best-guess OWASP mapping
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.payload or not self.payload.strip():
            raise ValueError("DatasetEntry payload must not be empty")
        # Normalize severity
        valid = {"critical", "high", "medium", "low"}
        if self.severity not in valid:
            self.severity = "medium"


class DatasetLoader:
    """Loads attack datasets from various sources and formats.

    Usage:
        loader = DatasetLoader()

        # Load from file
        entries = loader.from_file("/path/to/dataset.jsonl")

        # Load JailbreakBench format
        entries = loader.from_jailbreakbench("/path/to/jbb.json")

        # Load HarmBench format
        entries = loader.from_harmbench("/path/to/harmbench.csv")
    """

    def from_file(self, path: str | Path) -> list[DatasetEntry]:
        """Auto-detect format and load dataset from file path."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Dataset file not found: {path}")

        suffix = p.suffix.lower()
        if suffix == ".json":
            return self._try_jailbreakbench(p) or self._load_json_array(p)
        if suffix in (".jsonl", ".ndjson"):
            return load_jsonl_dataset(p)
        if suffix == ".csv":
            return load_csv_dataset(p)

        raise ValueError(f"Unsupported dataset file format: {suffix}. Use .json, .jsonl, or .csv")

    def from_jailbreakbench(self, path: str | Path) -> list[DatasetEntry]:
        """Load JailbreakBench JSON format.

        Expected structure:
        {
          "jailbreaks": [
            {
              "index": 1,
              "goal": "Write a tutorial on how to make a bomb",
              "behavior": "Bomb",
              "category": "Weapons",
              "prompt": "...",
              "response": "...",
              "label": 1
            }, ...
          ]
        }
        """
        p = Path(path)
        raw = json.loads(p.read_text(encoding="utf-8"))

        entries: list[DatasetEntry] = []
        jailbreaks = raw.get("jailbreaks", raw if isinstance(raw, list) else [])

        for item in jailbreaks:
            payload = item.get("prompt") or item.get("goal", "")
            if not payload:
                continue
            category = str(item.get("category", "jailbreak")).lower()
            severity = _category_to_severity(category)
            entries.append(DatasetEntry(
                payload=str(payload),
                category=category,
                severity=severity,
                source="jailbreakbench",
                owasp_id=_category_to_owasp(category),
                metadata={
                    "goal": str(item.get("goal", "")),
                    "behavior": str(item.get("behavior", "")),
                    "label": str(item.get("label", "")),
                },
            ))

        logger.info("Loaded %d entries from JailbreakBench: %s", len(entries), path)
        return entries

    def from_harmbench(self, path: str | Path) -> list[DatasetEntry]:
        """Load HarmBench CSV format.

        Expected columns: Behavior, SemanticCategory, FunctionalCategory, Prompt
        """
        return load_csv_dataset(
            path,
            payload_col="Behavior",
            category_col="SemanticCategory",
            source="harmbench",
        )

    def from_wildjailbreak(self, path: str | Path) -> list[DatasetEntry]:
        """Load WildJailbreak JSONL format.

        Expected keys per line: vanilla, adversarial, category, data_type
        """
        entries: list[DatasetEntry] = []
        for entry in _iter_jsonl(Path(path)):
            # WildJailbreak has both vanilla and adversarial variants
            for key in ("adversarial", "vanilla"):
                payload = entry.get(key, "")
                if not payload:
                    continue
                category = str(entry.get("category", "unknown")).lower()
                entries.append(DatasetEntry(
                    payload=str(payload),
                    category=category,
                    severity=_category_to_severity(category),
                    source="wildjailbreak",
                    owasp_id=_category_to_owasp(category),
                    metadata={"data_type": str(entry.get("data_type", ""))},
                ))

        logger.info("Loaded %d entries from WildJailbreak: %s", len(entries), path)
        return entries

    def from_custom_jsonl(
        self,
        path: str | Path,
        payload_key: str = "payload",
        category_key: str = "category",
        severity_key: str = "severity",
    ) -> list[DatasetEntry]:
        """Load a custom JSONL file with configurable field names."""
        entries: list[DatasetEntry] = []
        for item in _iter_jsonl(Path(path)):
            payload = item.get(payload_key, "")
            if not payload:
                continue
            try:
                entries.append(DatasetEntry(
                    payload=str(payload),
                    category=str(item.get(category_key, "unknown")).lower(),
                    severity=str(item.get(severity_key, "medium")).lower(),
                    source=str(Path(path).stem),
                ))
            except ValueError:
                continue
        return entries

    def _try_jailbreakbench(self, p: Path) -> list[DatasetEntry] | None:
        """Try JailbreakBench format; return None if not matching."""
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and "jailbreaks" in raw:
                return self.from_jailbreakbench(p)
        except (json.JSONDecodeError, KeyError):
            pass
        return None

    def _load_json_array(self, p: Path) -> list[DatasetEntry]:
        """Load a plain JSON array of objects with 'payload' key."""
        raw = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError(f"Expected JSON array, got {type(raw).__name__}")
        entries = []
        for item in raw:
            if isinstance(item, str):
                entries.append(DatasetEntry(payload=item, source=p.stem))
            elif isinstance(item, dict) and item.get("payload"):
                entries.append(DatasetEntry(
                    payload=str(item["payload"]),
                    category=str(item.get("category", "unknown")),
                    severity=str(item.get("severity", "medium")),
                    source=p.stem,
                ))
        return entries


def load_csv_dataset(
    path: str | Path,
    payload_col: str = "payload",
    category_col: str = "category",
    severity_col: str = "severity",
    source: str | None = None,
) -> list[DatasetEntry]:
    """Load a CSV dataset file.

    Args:
        path: Path to the CSV file.
        payload_col: Column name for the attack payload.
        category_col: Column name for the attack category.
        severity_col: Column name for severity.
        source: Dataset name for attribution.

    Returns:
        List of DatasetEntry objects.
    """
    p = Path(path)
    src = source or p.stem
    entries: list[DatasetEntry] = []

    with p.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            return entries

        for row in reader:
            payload = row.get(payload_col, "").strip()
            if not payload:
                continue
            category = row.get(category_col, "unknown").strip().lower()
            severity = row.get(severity_col, "medium").strip().lower()
            try:
                entries.append(DatasetEntry(
                    payload=payload,
                    category=category,
                    severity=severity,
                    source=src,
                    owasp_id=_category_to_owasp(category),
                ))
            except ValueError:
                continue

    logger.info("Loaded %d entries from CSV: %s", len(entries), path)
    return entries


def load_jsonl_dataset(
    path: str | Path,
    source: str | None = None,
) -> list[DatasetEntry]:
    """Load a JSONL dataset file.

    Each line should be a JSON object with at least a 'payload' key.
    """
    p = Path(path)
    src = source or p.stem
    entries: list[DatasetEntry] = []

    for item in _iter_jsonl(p):
        payload = item.get("payload", item.get("text", item.get("prompt", "")))
        if not payload:
            continue
        try:
            entries.append(DatasetEntry(
                payload=str(payload),
                category=str(item.get("category", "unknown")).lower(),
                severity=str(item.get("severity", "medium")).lower(),
                source=src,
            ))
        except ValueError:
            continue

    logger.info("Loaded %d entries from JSONL: %s", len(entries), path)
    return entries


def _iter_jsonl(path: Path) -> Iterator[dict[str, object]]:
    """Iterate over lines in a JSONL file, skipping invalid lines."""
    with path.open(encoding="utf-8") as fh:
        for line_num, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                logger.debug("Skipping invalid JSON at line %d in %s", line_num, path)


def _category_to_severity(category: str) -> str:
    """Map dataset category strings to RedForge severity levels."""
    c = category.lower()
    if any(k in c for k in ("weapon", "chemical", "bioweap", "nuclear", "explosive", "csam")):
        return "critical"
    if any(k in c for k in ("malware", "hacking", "exploit", "violence", "harmful")):
        return "high"
    if any(k in c for k in ("hate", "bias", "discriminat", "misinfo")):
        return "medium"
    return "medium"


def _category_to_owasp(category: str) -> str:
    """Map dataset category strings to closest OWASP LLM ID."""
    c = category.lower()
    if any(k in c for k in ("inject", "jailbreak", "bypass", "override")):
        return "LLM01"
    if any(k in c for k in ("pii", "privac", "data", "credential", "leakage")):
        return "LLM02"
    if any(k in c for k in ("supply", "poison")):
        return "LLM04"
    if any(k in c for k in ("output", "malware", "code", "generat")):
        return "LLM05"
    if any(k in c for k in ("agent", "autonomo", "action")):
        return "LLM06"
    if any(k in c for k in ("hallucin", "misinform", "fabricat")):
        return "LLM09"
    return "LLM01"
