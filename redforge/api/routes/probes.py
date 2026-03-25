"""GET /v1/probes — list available probes."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from redforge.api.auth import verify_token
from redforge.api.models import ProbeInfo

router = APIRouter(prefix="/v1", tags=["Probes"])


@router.get("/probes", response_model=list[ProbeInfo], dependencies=[Depends(verify_token)])
async def list_probes() -> list[ProbeInfo]:
    """List all available attack probes with metadata."""
    from redforge.probes import get_all_probes

    return [
        ProbeInfo(
            id=p.id,
            owasp_id=p.owasp_id,
            mitre_atlas=p.mitre_atlas,
            severity=p.severity,
            description=p.description,
            tags=p.tags,
            payload_count=len(p.payloads()),
        )
        for p in get_all_probes()
    ]
