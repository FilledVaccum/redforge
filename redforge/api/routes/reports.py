"""GET /v1/reports/{session_id} — retrieve a saved report."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException, status

from redforge.api.auth import verify_token

router = APIRouter(prefix="/v1", tags=["Reports"])

RESULTS_DIR = Path("scan_results")


@router.get("/reports/{session_id}", dependencies=[Depends(verify_token)])
async def get_report(session_id: str) -> dict[str, Any]:
    """Retrieve a previously saved scan report by session ID prefix."""
    # Validate session_id to prevent path traversal
    if not session_id.replace("-", "").isalnum() or len(session_id) > 36:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid session ID format")

    if not RESULTS_DIR.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No scan results found")

    matches = list(RESULTS_DIR.glob(f"redforge_{session_id[:8]}*.json"))
    if not matches:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Session {session_id!r} not found")

    data: dict[str, Any] = cast(dict[str, Any], json.loads(matches[0].read_text()))
    return data
