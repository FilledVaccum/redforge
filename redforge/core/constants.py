"""RedForge constants — single source of truth for shared values.

Import from here instead of re-defining in multiple files.
Adding a value here automatically propagates everywhere that uses it.
"""

from __future__ import annotations

# Version — also in pyproject.toml; keep in sync.
VERSION = "0.1.0"

# Authorization choices — used by CLI and Python SDK.
# Add new values here; both places update automatically.
AUTHORIZATION_CHOICES: tuple[str, ...] = ("owned", "authorized", "research")

# Severity display metadata — all severity-aware code derives from this.
# Key:   severity string as used in probes (lowercase)
# value: (display_color_rich, hex_color, fallback_risk_level)
#
# To add a new severity:  add one entry here.  Reporters, scorer, and CLI
# all pick it up automatically.
SEVERITY_META: dict[str, dict[str, str]] = {
    "critical": {"rich": "red",     "hex": "#dc2626", "risk": "CRITICAL"},
    "high":     {"rich": "orange3", "hex": "#ea580c", "risk": "HIGH"},
    "medium":   {"rich": "yellow",  "hex": "#ca8a04", "risk": "MEDIUM"},
    "low":      {"rich": "green",   "hex": "#16a34a", "risk": "LOW"},
    "info":     {"rich": "dim",     "hex": "#6b7280", "risk": "MINIMAL"},
}

# Derived convenience dicts — populated once from SEVERITY_META.
# These replace per-file hardcoded dicts everywhere.
SEVERITY_HEX:   dict[str, str] = {k: v["hex"]  for k, v in SEVERITY_META.items()}
SEVERITY_RICH:  dict[str, str] = {k: v["rich"] for k, v in SEVERITY_META.items()}

# Risk-level determination order (highest → lowest).
# Score thresholds still live in scorer.py, but the ORDER is canonical here.
RISK_LEVEL_ORDER: list[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]

__all__ = [
    "VERSION",
    "AUTHORIZATION_CHOICES",
    "SEVERITY_META",
    "SEVERITY_HEX",
    "SEVERITY_RICH",
    "RISK_LEVEL_ORDER",
]
