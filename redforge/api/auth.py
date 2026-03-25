"""Bearer token authentication middleware for the RedForge REST API."""

from __future__ import annotations

import os

from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

security = HTTPBearer(auto_error=False)


def get_api_key() -> str | None:
    """Load API key from environment variable."""
    return os.environ.get("REDFORGE_API_KEY")


async def verify_token(
    credentials: HTTPAuthorizationCredentials | None = Security(security),
) -> str:
    """Verify Bearer token on every protected endpoint.

    Returns the validated token or raises 401.
    """
    expected_key = get_api_key()

    if not expected_key:
        # API key not configured — reject all requests for safety
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication not configured. Set REDFORGE_API_KEY environment variable.",
        )

    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required. Use: Authorization: Bearer <REDFORGE_API_KEY>",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if credentials.credentials != expected_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return credentials.credentials
