"""Reporter registry — auto-discovered.

Adding a new reporter requires ONLY creating a file in this package that
subclasses BaseReporter with a unique `fmt` class attribute.
No edits to this file or commands.py are needed.

Aliases: set `fmt_aliases = ["alias1", "alias2"]` on the reporter class.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil

from redforge.reporters.base import BaseReporter

# ── Auto-discovery ───────────────────────────────────────────────────────────
# Scan every module in this package.  Any concrete BaseReporter subclass with a
# non-"base" fmt attribute is registered automatically.

REPORTERS: dict[str, type[BaseReporter]] = {}

for _mod_info in pkgutil.iter_modules(__path__):  # type: ignore[name-defined]
    if _mod_info.name.startswith("_"):
        continue
    _mod = importlib.import_module(f"redforge.reporters.{_mod_info.name}")
    for _cls_name, _cls in inspect.getmembers(_mod, inspect.isclass):
        if (
            issubclass(_cls, BaseReporter)
            and _cls is not BaseReporter
            and hasattr(_cls, "fmt")
            and _cls.fmt not in ("base", "")
            and not inspect.isabstract(_cls)
        ):
            REPORTERS[_cls.fmt] = _cls
            for _alias in getattr(_cls, "fmt_aliases", []):
                REPORTERS[_alias] = _cls


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
