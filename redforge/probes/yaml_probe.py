"""YAML-driven probe factory.

Converts YAML probe definition files into fully functional BaseProbe subclasses.
Files in redforge/probes/datasets/*.yaml are auto-discovered by probes/__init__.py.

YAML Probe format
-----------------
id:           probe_id_snake_case   (required, globally unique)
owasp_id:     LLM01                 (required)
mitre_atlas:  AML.T0051             (optional, default AML.T0000)
severity:     critical|high|medium|low|info  (optional, default medium)
description:  One-line summary      (optional)
tags:         [list, of, tags]      (optional)
remediation:  Fix guidance text     (optional)
guardrail_meta:                     (optional)
  detector: PromptInjectionDetector
  scan_target: INPUT
  action: BLOCK
  category: prompt_injection
  description: What the detector catches
score:                              (optional, default: chain(refusal, keyword))
  type: chain|keyword|refusal|regex|length|not
  ... (scorer-specific fields, see scoring/scorers.py)
payloads:                           (required)
  - "Plain string payload"
  - text: "Payload with metadata"
    tags: [tag1, tag2]

To add new payloads: edit the YAML file — no Python required.
To add a new probe category: create a new .yaml file in probes/datasets/.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Directory scanned for built-in YAML probes
DATASETS_DIR = Path(__file__).parent / "datasets"

# User-supplied YAML probes (added without touching the package)
USER_DATASETS_DIR = Path.home() / ".redforge" / "probes"


def _load_yaml(path: Path) -> dict[str, Any] | None:
    """Load a YAML file; return None on any error."""
    try:
        import yaml  # type: ignore[import-untyped]
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else None
    except ImportError:
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to load probe YAML %s: %s", path, exc)
        return None


def _extract_payloads(raw_list: list) -> list[str]:
    """Normalize payloads list — accepts strings or {text: ..., tags: ...} dicts."""
    payloads: list[str] = []
    for item in raw_list:
        if isinstance(item, str):
            text = item.strip()
        elif isinstance(item, dict):
            text = str(item.get("text", "")).strip()
        else:
            continue
        if text:
            payloads.append(text)
    return payloads


def make_yaml_probe_class(spec: dict[str, Any]) -> type:
    """Dynamically create a BaseProbe subclass from a YAML spec dict.

    Args:
        spec: Parsed YAML probe definition.

    Returns:
        A new class that is a concrete subclass of BaseProbe.

    Raises:
        ValueError: If required fields (id, owasp_id, payloads) are missing.
    """
    from redforge.probes.base import BaseProbe, ProbeResult

    probe_id = str(spec.get("id", "")).strip()
    if not probe_id:
        raise ValueError("YAML probe must have a non-empty 'id' field")

    owasp_id = str(spec.get("owasp_id", "LLM01"))
    raw_payloads = spec.get("payloads", [])
    if not raw_payloads:
        raise ValueError(f"YAML probe '{probe_id}' must have a non-empty 'payloads' list")

    extracted_payloads = _extract_payloads(raw_payloads)
    if not extracted_payloads:
        raise ValueError(f"YAML probe '{probe_id}' produced zero non-empty payloads")

    # Build scorer from config or use sensible default
    score_config = spec.get("score", {})
    if not score_config:
        # Default: refusal first, then keyword marker if keywords defined
        score_config = {"type": "refusal"}

    def _build_scorer():  # lazy import to avoid circular dependency
        from redforge.scoring.scorers import build_scorer_from_config
        return build_scorer_from_config(score_config)

    # Capture variables for closures
    _payloads = extracted_payloads
    _spec = spec

    def payloads_method(self: Any) -> list[str]:
        return list(_payloads)

    def score_method(self: Any, response: str, payload: str) -> ProbeResult:
        try:
            scorer = _build_scorer()
            sr = scorer.score(response, payload)
            return self._make_result(payload, response, sr.score, sr.evidence)
        except Exception as exc:  # noqa: BLE001
            logger.warning("YAML probe scorer failed for %s: %s", self.id, exc)
            return self._make_result(
                payload, response, 0.3, f"Scorer error — inconclusive: {exc}"
            )

    class_attrs: dict[str, Any] = {
        "id": probe_id,
        "owasp_id": owasp_id,
        "mitre_atlas": str(spec.get("mitre_atlas", "AML.T0000")),
        "severity": str(spec.get("severity", "medium")),
        "description": str(spec.get("description", f"YAML-defined probe: {probe_id}")),
        "tags": list(spec.get("tags", [])),
        "remediation": str(spec.get("remediation", "")),
        "guardrail_meta": dict(spec.get("guardrail_meta") or {}),
        "compliance": dict(spec.get("compliance") or {}),
        "_yaml_source": str(spec.get("_source", "")),
        "payloads": payloads_method,
        "score": score_method,
    }

    # Create a concrete BaseProbe subclass dynamically
    cls = type(f"YAMLProbe_{probe_id}", (BaseProbe,), class_attrs)
    return cls


def discover_yaml_probes() -> list[type]:
    """Scan built-in and user datasets directories for YAML probe definitions.

    Returns:
        List of dynamically created BaseProbe subclasses, one per valid YAML file.
        Files that fail to parse are skipped with a warning.
    """
    probe_classes: list[type] = []
    seen_ids: set[str] = set()

    dirs_to_scan: list[Path] = []
    if DATASETS_DIR.exists():
        dirs_to_scan.append(DATASETS_DIR)
    if USER_DATASETS_DIR.exists():
        dirs_to_scan.append(USER_DATASETS_DIR)

    for scan_dir in dirs_to_scan:
        for yaml_path in sorted(scan_dir.glob("*.yaml")):
            if yaml_path.name.startswith("_"):
                continue

            spec = _load_yaml(yaml_path)
            if spec is None:
                continue

            # Inject source path for debugging
            spec["_source"] = str(yaml_path)

            try:
                cls = make_yaml_probe_class(spec)
            except ValueError as exc:
                logger.warning("Skipping YAML probe %s: %s", yaml_path.name, exc)
                continue

            probe_id = cls.id  # type: ignore[attr-defined]
            if probe_id in seen_ids:
                logger.warning(
                    "Duplicate YAML probe id '%s' in %s — skipping", probe_id, yaml_path
                )
                continue

            seen_ids.add(probe_id)
            probe_classes.append(cls)
            logger.debug("Registered YAML probe: %s from %s", probe_id, yaml_path.name)

    return probe_classes
