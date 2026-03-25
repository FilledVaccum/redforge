"""Reporter registry."""

from redforge.reporters.base import BaseReporter
from redforge.reporters.html_reporter import HTMLReporter
from redforge.reporters.json_reporter import JSONReporter
from redforge.reporters.markdown_reporter import MarkdownReporter
from redforge.reporters.sarif_reporter import SARIFReporter

REPORTERS: dict[str, type[BaseReporter]] = {
    "json": JSONReporter,
    "sarif": SARIFReporter,
    "html": HTMLReporter,
    "markdown": MarkdownReporter,
    "md": MarkdownReporter,
}


def get_reporter(fmt: str) -> BaseReporter:
    if fmt not in REPORTERS:
        raise ValueError(f"Unknown format '{fmt}'. Available: {', '.join(REPORTERS.keys())}")
    return REPORTERS[fmt]()


__all__ = ["get_reporter", "JSONReporter", "SARIFReporter", "HTMLReporter", "MarkdownReporter"]
