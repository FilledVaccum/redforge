"""Named connection profile system for RedForge adapters.

Profiles let users pre-configure provider + model + credentials in YAML
files and then reference them by name (e.g. ``AdapterFactory.from_profile("my-prod-gpt4")``).

Profile search order (first found wins):
  1. ``./redforge.profiles.yaml``  (project-local)
  2. ``~/.redforge/profiles.yaml`` (user-global)
  3. Path in ``REDFORGE_PROFILES`` environment variable
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from redforge.adapters.adapter_config import AdapterConfig


@dataclass
class ConnectionProfile:
    """A named, reusable connection configuration.

    Attributes:
        name: Unique profile identifier.
        config: The fully-resolved AdapterConfig.
        description: Human-readable description shown in ``list_profiles()``.
        tags: Arbitrary labels (e.g. ``['production', 'aws']``).
    """

    name: str
    config: AdapterConfig
    description: str = ""
    tags: list[str] = field(default_factory=list)


class ProfileManager:
    """Load, save, and resolve named connection profiles.

    Example YAML (``redforge.profiles.yaml``)::

        profiles:
          my-prod-gpt4:
            description: "Production OpenAI GPT-4o"
            provider: openai
            model: gpt-4o
            api_key_env: PROD_OPENAI_KEY
            max_tokens: 1024
            tags: [production]

          local-llama:
            description: "Local Ollama Llama3"
            provider: ollama
            model: llama3:70b
            base_url: http://localhost:11434
            tags: [local, free]
    """

    DEFAULT_PROFILES_FILENAME = "redforge.profiles.yaml"
    USER_PROFILES_DIR = Path.home() / ".redforge"

    def __init__(self, extra_path: Path | None = None) -> None:
        """Initialise the manager.

        Args:
            extra_path: Additional path to search *before* the defaults.
        """
        self._extra_path = extra_path
        self._cache: dict[str, ConnectionProfile] | None = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _candidate_paths(self) -> list[Path]:
        """Return all candidate YAML paths in search order."""
        candidates: list[Path] = []
        if self._extra_path is not None:
            candidates.append(self._extra_path)
        # 1. Project-local
        candidates.append(Path.cwd() / self.DEFAULT_PROFILES_FILENAME)
        # 2. User-global
        candidates.append(self.USER_PROFILES_DIR / self.DEFAULT_PROFILES_FILENAME)
        # 3. Env var override
        env_path = os.environ.get("REDFORGE_PROFILES")
        if env_path:
            candidates.append(Path(env_path))
        return candidates

    @staticmethod
    def _parse_yaml(path: Path) -> dict[str, Any]:
        """Parse a YAML file, returning an empty dict on error."""
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError:
            # Fall back to a minimal YAML-subset parser using json for simple cases
            return {}
        try:
            with path.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            return data if isinstance(data, dict) else {}
        except Exception:  # noqa: BLE001
            return {}

    @staticmethod
    def _profile_from_dict(name: str, raw: dict[str, Any]) -> ConnectionProfile:
        """Build a ConnectionProfile from a raw YAML dict."""
        description = str(raw.pop("description", ""))
        tags: list[str] = list(raw.pop("tags", []))
        config = AdapterConfig.from_dict(raw)
        return ConnectionProfile(
            name=name,
            config=config,
            description=description,
            tags=tags,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self) -> dict[str, ConnectionProfile]:
        """Load all profiles from the first matching YAML file.

        Missing or unreadable files are silently skipped — the method
        never raises.

        Returns:
            Mapping of profile name → ConnectionProfile.  Empty dict if
            no files were found or all files were empty / unreadable.
        """
        if self._cache is not None:
            return self._cache

        for path in self._candidate_paths():
            if not path.exists():
                continue
            data = self._parse_yaml(path)
            profiles_raw = data.get("profiles", {})
            if not isinstance(profiles_raw, dict):
                continue
            profiles: dict[str, ConnectionProfile] = {}
            for pname, pdata in profiles_raw.items():
                if not isinstance(pdata, dict):
                    continue
                try:
                    profiles[pname] = self._profile_from_dict(pname, dict(pdata))
                except Exception:  # noqa: BLE001, S112
                    # Silently skip malformed entries
                    continue
            self._cache = profiles
            return profiles

        self._cache = {}
        return {}

    def get(self, name: str) -> ConnectionProfile | None:
        """Retrieve a profile by name.

        Args:
            name: Profile identifier.

        Returns:
            The ConnectionProfile, or None if not found.
        """
        return self.load().get(name)

    def save(
        self, profile: ConnectionProfile, path: Path | None = None
    ) -> Path:
        """Persist a profile to a YAML file.

        If ``path`` is not given, the user-global profiles file is used
        (``~/.redforge/profiles.yaml``), creating the directory if needed.

        Args:
            profile: The profile to save.
            path: Target YAML file path.  Existing profiles are preserved.

        Returns:
            The path the profile was written to.

        Raises:
            ImportError: If PyYAML is not installed.
        """
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "ProfileManager.save() requires 'pyyaml'. "
                "Install with: pip install pyyaml"
            ) from exc

        target = path or (self.USER_PROFILES_DIR / self.DEFAULT_PROFILES_FILENAME)
        target.parent.mkdir(parents=True, exist_ok=True)

        # Load existing data
        existing: dict[str, Any] = {}
        if target.exists():
            with target.open("r", encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh)
                if isinstance(loaded, dict):
                    existing = loaded

        if "profiles" not in existing or not isinstance(existing["profiles"], dict):
            existing["profiles"] = {}

        cfg = profile.config
        entry: dict[str, Any] = {
            "description": profile.description,
            "provider": cfg.provider,
            "model": cfg.model,
        }
        if profile.tags:
            entry["tags"] = profile.tags
        if cfg.base_url is not None:
            entry["base_url"] = cfg.base_url
        if cfg.api_key_env is not None:
            entry["api_key_env"] = cfg.api_key_env
        if cfg.region is not None:
            entry["region"] = cfg.region
        if cfg.deployment_name is not None:
            entry["deployment_name"] = cfg.deployment_name
        if cfg.timeout != 30.0:
            entry["timeout"] = cfg.timeout
        if cfg.max_retries != 3:
            entry["max_retries"] = cfg.max_retries
        if cfg.temperature != 0.7:
            entry["temperature"] = cfg.temperature
        if cfg.max_tokens != 1024:
            entry["max_tokens"] = cfg.max_tokens
        if cfg.extra_headers:
            entry["extra_headers"] = cfg.extra_headers
        if cfg.extra_params:
            entry.update(cfg.extra_params)

        existing["profiles"][profile.name] = entry

        with target.open("w", encoding="utf-8") as fh:
            yaml.safe_dump(existing, fh, default_flow_style=False, allow_unicode=True)

        # Invalidate cache
        self._cache = None
        return target

    def list_profiles(self) -> list[ConnectionProfile]:
        """Return all loaded profiles as an ordered list.

        Returns:
            Profiles sorted alphabetically by name.
        """
        return sorted(self.load().values(), key=lambda p: p.name)

    @classmethod
    def from_env(cls) -> ProfileManager:
        """Create a ProfileManager that honours the ``REDFORGE_PROFILES`` env var.

        Returns:
            A new ProfileManager instance.
        """
        env_path_str = os.environ.get("REDFORGE_PROFILES")
        extra = Path(env_path_str) if env_path_str else None
        return cls(extra_path=extra)


__all__ = ["ConnectionProfile", "ProfileManager"]
