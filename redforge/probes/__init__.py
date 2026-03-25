"""Probe registry — auto-discovers all probes in this package."""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from pathlib import Path

from redforge.probes.base import BaseProbe

_PROBE_REGISTRY: dict[str, type[BaseProbe]] = {}


def _discover_probes() -> None:
    """Import all probe modules and register concrete BaseProbe subclasses."""
    package_dir = Path(__file__).parent
    for _, module_name, _ in pkgutil.iter_modules([str(package_dir)]):
        if module_name in ("base", "__init__"):
            continue
        module = importlib.import_module(f"redforge.probes.{module_name}")
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BaseProbe)
                and obj is not BaseProbe
                and not inspect.isabstract(obj)
            ):
                _PROBE_REGISTRY[obj.id] = obj


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
