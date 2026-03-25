"""Safe credential loading and key masking utilities.

API keys are NEVER logged, stored in plaintext, or included in reports.
All key material is masked as *** in any string representation.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Patterns that look like API keys — used to mask them in output
_KEY_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9\-_]{20,}"),  # OpenAI style
    re.compile(r"Bearer\s+[A-Za-z0-9\-_\.]{20,}"),  # Bearer tokens
    re.compile(r"[Aa][Pp][Ii][\-_]?[Kk][Ee][Yy]\s*[=:]\s*\S+"),  # api_key = ...
    re.compile(r"[Aa][Ww][Ss][\-_][Ss][Ee][Cc][Rr][Ee][Tt]\s*[=:]\s*\S+"),  # AWS secret
    re.compile(r"AIza[A-Za-z0-9\-_]{35}"),  # Google API keys
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key
]


def load_env(env_file: Path | None = None) -> None:
    """Load environment variables from .env file if present.

    The .env file must be outside the project root and listed in .gitignore.
    """
    if env_file and env_file.exists():
        load_dotenv(env_file)
        logger.debug("Loaded env from %s", env_file)
    else:
        load_dotenv()  # looks for .env in cwd and parents


def get_secret(env_var: str, required: bool = False) -> str | None:
    """Safely retrieve a secret from environment variables.

    Args:
        env_var: The environment variable name.
        required: If True, raises ValueError when missing.

    Returns:
        The secret value, or None if not set.
    """
    value = os.environ.get(env_var)
    if required and not value:
        raise ValueError(
            f"Required secret '{env_var}' is not set. "
            f"Set it as an environment variable or in a .env file."
        )
    return value


def mask_secrets(text: str) -> str:
    """Replace any API key patterns in text with ***REDACTED***.

    Use this before logging any string that might contain credentials.
    """
    masked = text
    for pattern in _KEY_PATTERNS:
        masked = pattern.sub("***REDACTED***", masked)
    return masked


class MaskedStr(str):
    """A string subclass that masks itself in repr/str for safe logging."""

    def __repr__(self) -> str:
        return "***REDACTED***"

    def __str__(self) -> str:
        return "***REDACTED***"


def safe_key(value: str) -> MaskedStr:
    """Wrap an API key so it never appears in logs."""
    return MaskedStr(value)
