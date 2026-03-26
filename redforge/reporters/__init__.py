"""Reporter registry — auto-discovered.

Adding a new reporter requires ONLY creating a file in this package that
subclasses BaseReporter with a unique `fmt` class attribute.
No edits to this file or commands.py are needed.

Aliases: set `fmt_aliases = ["alias1", "alias2"]` on the reporter class.
"""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil

from redforge.reporters.base import BaseReporter

_logger = logging.getLogger(__name__)

# ── Auto-discovery ───────────────────────────────────────────────────────────
# Source 1: scan every module in this package.
# Source 2: installed packages that declare redforge.reporters entry points.
#
# Adding a built-in reporter:  create a file here — no registration needed.
# Adding a plugin reporter:    publish a package with
#   [project.entry-points."redforge.reporters"]
#   myformat = "mypackage.reporters:MyReporter"

REPORTERS: dict[str, type[BaseReporter]] = {}


def _register_reporter(cls: type[BaseReporter], source: str = "") -> None:
    fmt = getattr(cls, "fmt", "")
    if not fmt or fmt in ("base", ""):
        return
    if fmt not in REPORTERS:
        REPORTERS[fmt] = cls
    for alias in getattr(cls, "fmt_aliases", []):
        if alias not in REPORTERS:
            REPORTERS[alias] = cls


# 1. Built-in reporters in this package
for _mod_info in pkgutil.iter_modules(__path__):  # type: ignore[name-defined]
    if _mod_info.name.startswith("_"):
        continue
    try:
        _mod = importlib.import_module(f"redforge.reporters.{_mod_info.name}")
    except Exception as _exc:  # noqa: BLE001
        _logger.warning("Failed to import reporter module '%s': %s", _mod_info.name, _exc)
        continue
    for _cls_name, _cls in inspect.getmembers(_mod, inspect.isclass):
        if (
            issubclass(_cls, BaseReporter)
            and _cls is not BaseReporter
            and not inspect.isabstract(_cls)
        ):
            _register_reporter(_cls, source=_mod_info.name)

# 2. Plugin reporters via entry points
try:
    from importlib.metadata import entry_points as _eps
    for _ep in _eps(group="redforge.reporters"):
        try:
            _cls = _ep.load()
            if inspect.isclass(_cls) and issubclass(_cls, BaseReporter) and not inspect.isabstract(_cls):
                _register_reporter(_cls, source=f"plugin:{_ep.name}")
                _logger.info("Loaded plugin reporter: %s from %s", _ep.name, _ep.value)
        except Exception as _exc:  # noqa: BLE001
            _logger.warning("Failed to load reporter entry point '%s': %s", _ep.name, _exc)
except Exception as _exc:  # noqa: BLE001
    _logger.debug("Reporter entry point discovery failed: %s", _exc)


def get_reporter(fmt: str) -> BaseReporter:
    if fmt not in REPORTERS:
        raise ValueError(
            f"Unknown format '{fmt}'. "
            f"Available: {', '.join(sorted(REPORTERS.keys()))}"
        )
    return REPORTERS[fmt]()


def available_formats() -> list[str]:
    """Return sorted list of all registered format names (excluding aliases)."""
    seen: set[type[BaseReporter]] = set()
    names: list[str] = []
    for fmt, cls in sorted(REPORTERS.items()):
        if cls not in seen:
            names.append(fmt)
            seen.add(cls)
    return names


__all__ = [
    "BaseReporter",
    "REPORTERS",
    "get_reporter",
    "available_formats",
]
