"""Probe registry — auto-discovers all probes in this package.

Three discovery sources (in order):
  1. Python modules in redforge/probes/*.py  — concrete BaseProbe subclasses
  2. YAML files in redforge/probes/datasets/*.yaml  — declarative probes
  3. Installed packages that declare redforge.probes entry points  — plugins

To add a Python probe:  create a .py file here — no registration needed.
To add a YAML probe:    create a .yaml file in probes/datasets/ — no Python needed.
To add a plugin probe:  publish a package with [project.entry-points."redforge.probes"].
"""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
from pathlib import Path

from redforge.probes.base import BaseProbe

logger = logging.getLogger(__name__)

_PROBE_REGISTRY: dict[str, type[BaseProbe]] = {}


def _register(cls: type[BaseProbe], source: str = "") -> None:
    """Register a probe class, warning on duplicate IDs."""
    probe_id = cls.id  # type: ignore[attr-defined]
    if probe_id in _PROBE_REGISTRY:
        logger.debug("Probe '%s' already registered; skipping duplicate from %s", probe_id, source)
        return
    _PROBE_REGISTRY[probe_id] = cls


def _discover_probes() -> None:
    """Populate _PROBE_REGISTRY from all three sources."""
    # 1. Python modules in this package
    package_dir = Path(__file__).parent
    skip = {"base", "__init__", "yaml_probe"}
    for _, module_name, _ in pkgutil.iter_modules([str(package_dir)]):
        if module_name in skip:
            continue
        try:
            module = importlib.import_module(f"redforge.probes.{module_name}")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to import probe module '%s': %s", module_name, exc)
            continue
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BaseProbe)
                and obj is not BaseProbe
                and not inspect.isabstract(obj)
            ):
                _register(obj, source=module_name)

    # 2. YAML probe definitions in probes/datasets/
    try:
        from redforge.probes.yaml_probe import discover_yaml_probes
        for cls in discover_yaml_probes():
            _register(cls, source="yaml")
    except Exception as exc:  # noqa: BLE001
        logger.warning("YAML probe discovery failed: %s", exc)

    # 3. Third-party plugin probes via Python entry points
    #    Install with: [project.entry-points."redforge.probes"]
    #    Example:      my_probe = "mypackage.probes:MyProbe"
    try:
        from importlib.metadata import entry_points
        eps = entry_points(group="redforge.probes")
        for ep in eps:
            try:
                obj = ep.load()
                if inspect.isclass(obj) and issubclass(obj, BaseProbe) and not inspect.isabstract(obj):
                    _register(obj, source=f"plugin:{ep.name}")
                    logger.info("Loaded plugin probe: %s from %s", ep.name, ep.value)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to load probe entry point '%s': %s", ep.name, exc)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Entry point discovery unavailable: %s", exc)


def get_all_probes() -> list[BaseProbe]:
    """Return instantiated instances of all registered probes."""
    if not _PROBE_REGISTRY:
        _discover_probes()
    return [cls() for cls in _PROBE_REGISTRY.values()]


def get_probe(probe_id: str) -> BaseProbe:
    """Return a probe instance by ID."""
    if not _PROBE_REGISTRY:
        _discover_probes()
    if probe_id not in _PROBE_REGISTRY:
        raise ValueError(f"Unknown probe '{probe_id}'. Run 'redforge list-probes' to see all.")
    return _PROBE_REGISTRY[probe_id]()


def list_probe_ids() -> list[str]:
    if not _PROBE_REGISTRY:
        _discover_probes()
    return sorted(_PROBE_REGISTRY.keys())


__all__ = ["get_all_probes", "get_probe", "list_probe_ids"]
