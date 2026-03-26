"""Compliance framework loader — reads YAML framework definitions.

Frameworks are loaded from two locations (in priority order):
  1. User overrides: ~/.redforge/compliance/*.yaml
  2. Built-in:       redforge/compliance/frameworks/*.yaml

A user framework YAML with the same framework_id as a built-in one wins.
Drop a YAML file in ~/.redforge/compliance/ to add or override any framework.

To add a new compliance framework:
  1. Create ~/.redforge/compliance/my_framework.yaml  (or add it to
     redforge/compliance/frameworks/ for built-in distribution).
  2. Follow the format of existing framework YAML files.
  3. That's all — map_findings_to_compliance() picks it up automatically.

YAML format reference: see redforge/compliance/frameworks/nist_ai_rmf.yaml
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Built-in framework files live here
_BUILTIN_FRAMEWORKS_DIR = Path(__file__).parent / "frameworks"

# User overrides live here (created on demand)
_USER_FRAMEWORKS_DIR = Path.home() / ".redforge" / "compliance"


@dataclass
class FrameworkControl:
    """A single control entry within a compliance framework."""

    control_id: str
    control_name: str
    description: str
    severity: str
    remediation: str


@dataclass
class ComplianceFramework:
    """A loaded compliance framework definition.

    Attributes:
        framework_id:  Canonical identifier (e.g. "NIST_AI_RMF").
        name:          Human-readable name.
        version:       Framework version string.
        url:           Reference URL.
        description:   One-line summary.
        mappings:      dict[owasp_id → list[FrameworkControl]]
        source:        File path this was loaded from.
    """

    framework_id: str
    name: str
    version: str
    url: str
    description: str
    mappings: dict[str, list[FrameworkControl]] = field(default_factory=dict)
    source: str = ""


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def _load_yaml_file(path: Path) -> dict:
    """Load a YAML file, returning an empty dict on any error."""
    try:
        import yaml  # type: ignore[import-untyped]
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except ImportError:
        logger.warning(
            "pyyaml not installed; compliance YAML files cannot be loaded. "
            "Run: pip install pyyaml"
        )
        return {}
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to load compliance framework from %s: %s", path, exc)
        return {}


def _parse_framework(raw: dict, source: str) -> ComplianceFramework | None:
    """Parse a raw YAML dict into a ComplianceFramework."""
    framework_id = raw.get("framework_id", "")
    if not framework_id:
        logger.warning("Skipping framework file %s: missing 'framework_id'", source)
        return None

    mappings: dict[str, list[FrameworkControl]] = {}
    for owasp_id, controls in raw.get("mappings", {}).items():
        if not isinstance(controls, list):
            continue
        parsed_controls: list[FrameworkControl] = []
        for ctrl in controls:
            if not isinstance(ctrl, dict):
                continue
            parsed_controls.append(
                FrameworkControl(
                    control_id=str(ctrl.get("control_id", "")),
                    control_name=str(ctrl.get("control_name", "")),
                    description=str(ctrl.get("description", "")).strip(),
                    severity=str(ctrl.get("severity", "medium")),
                    remediation=str(ctrl.get("remediation", "")).strip(),
                )
            )
        if parsed_controls:
            mappings[str(owasp_id)] = parsed_controls

    return ComplianceFramework(
        framework_id=framework_id,
        name=str(raw.get("name", framework_id)),
        version=str(raw.get("version", "1.0")),
        url=str(raw.get("url", "")),
        description=str(raw.get("description", "")).strip(),
        mappings=mappings,
        source=source,
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_FRAMEWORK_REGISTRY: dict[str, ComplianceFramework] = {}
_REGISTRY_LOADED = False


def _load_all_frameworks() -> None:
    """Load all built-in and user compliance frameworks into the registry."""
    global _REGISTRY_LOADED
    if _REGISTRY_LOADED:
        return

    # 1. Load built-ins first
    if _BUILTIN_FRAMEWORKS_DIR.exists():
        for yaml_path in sorted(_BUILTIN_FRAMEWORKS_DIR.glob("*.yaml")):
            raw = _load_yaml_file(yaml_path)
            framework = _parse_framework(raw, str(yaml_path))
            if framework:
                _FRAMEWORK_REGISTRY[framework.framework_id] = framework
                logger.debug("Loaded built-in framework: %s", framework.framework_id)

    # 2. User overrides win — same framework_id replaces built-in
    if _USER_FRAMEWORKS_DIR.exists():
        for yaml_path in sorted(_USER_FRAMEWORKS_DIR.glob("*.yaml")):
            raw = _load_yaml_file(yaml_path)
            framework = _parse_framework(raw, str(yaml_path))
            if framework:
                _FRAMEWORK_REGISTRY[framework.framework_id] = framework
                logger.info(
                    "Loaded user framework override: %s from %s",
                    framework.framework_id, yaml_path
                )

    _REGISTRY_LOADED = True


def get_framework(framework_id: str) -> ComplianceFramework | None:
    """Return a loaded framework by ID, or None if not found."""
    _load_all_frameworks()
    return _FRAMEWORK_REGISTRY.get(framework_id)


def list_frameworks() -> list[str]:
    """Return sorted list of all registered framework IDs."""
    _load_all_frameworks()
    return sorted(_FRAMEWORK_REGISTRY.keys())


def reload_frameworks() -> None:
    """Force a reload of all framework files (for testing and hot-reload)."""
    global _REGISTRY_LOADED
    _FRAMEWORK_REGISTRY.clear()
    _REGISTRY_LOADED = False
    _load_all_frameworks()


# ---------------------------------------------------------------------------
# Compliance assessment
# ---------------------------------------------------------------------------


def map_findings_to_compliance_yaml(
    failed_owasp_ids: list[str],
    frameworks: list[str] | None = None,
) -> dict:
    """Map failed probe OWASP IDs to compliance violations using YAML frameworks.

    This is the YAML-driven version of compliance/mappings.py's
    map_findings_to_compliance().  It uses the same return structure but loads
    frameworks from YAML files instead of hardcoded Python dicts.

    Args:
        failed_owasp_ids: OWASP LLM IDs that had failing probes.
        frameworks:       Framework IDs to assess.  None = all loaded frameworks.

    Returns:
        Dict with keys: frameworks_assessed, violations, compliant_controls,
        total_controls — compatible with ComplianceResult dataclass.
    """
    _load_all_frameworks()

    if frameworks is None:
        frameworks = list(_FRAMEWORK_REGISTRY.keys())

    violations = []
    total_controls = 0

    for fw_id in frameworks:
        framework = _FRAMEWORK_REGISTRY.get(fw_id)
        if not framework:
            logger.warning("Framework '%s' not found; skipping", fw_id)
            continue

        for owasp_id, controls in framework.mappings.items():
            total_controls += len(controls)
            if owasp_id in failed_owasp_ids:
                for ctrl in controls:
                    violations.append({
                        "framework": fw_id,
                        "control_id": ctrl.control_id,
                        "control_name": ctrl.control_name,
                        "description": ctrl.description,
                        "severity": ctrl.severity,
                        "remediation": ctrl.remediation,
                    })

    return {
        "frameworks_assessed": frameworks,
        "violations": violations,
        "compliant_controls": max(0, total_controls - len(violations)),
        "total_controls": total_controls,
    }


__all__ = [
    "FrameworkControl",
    "ComplianceFramework",
    "get_framework",
    "list_frameworks",
    "reload_frameworks",
    "map_findings_to_compliance_yaml",
]
