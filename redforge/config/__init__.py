"""RedForge YAML-based test configuration (promptfoo-style).

Allows defining scan configurations in YAML/JSON files for:
- CI/CD integration
- Repeatable test suites
- Custom probe selection
- Multi-provider comparison
"""

from __future__ import annotations

from redforge.config.runner import ScanConfig, YAMLConfigRunner, load_config

__all__ = ["YAMLConfigRunner", "ScanConfig", "load_config"]
