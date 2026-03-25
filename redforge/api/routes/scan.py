"""POST /v1/scan — run a vulnerability scan."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from redforge.api.auth import verify_token
from redforge.api.models import FindingResponse, ScanRequest, ScanResponse, ScoreResponse

router = APIRouter(prefix="/v1", tags=["Scan"])


@router.post("/scan", response_model=ScanResponse, dependencies=[Depends(verify_token)])
async def run_scan(request: ScanRequest) -> ScanResponse:
    """Execute a vulnerability scan against a target model.

    Returns a ScanResponse with findings and risk score.
    Raw model responses are NOT included in the API response — stored locally only.
    """
    from redforge.adapters import get_adapter
    from redforge.core.orchestrator import Orchestrator, ScanConfig
    from redforge.core.session import ScanSession
    from redforge.probes import get_all_probes, get_probe

    try:
        adapter_config: dict[str, str] = {}
        if request.model:
            adapter_config["model"] = request.model
        adapter = get_adapter(request.provider, adapter_config)
    except (ImportError, ValueError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e

    scan_config = ScanConfig(
        probes=request.probes,
        system_prompt=request.system_prompt,
        dry_run=request.dry_run,
        store_results=True,
    )
    session = ScanSession(
        target=f"{request.provider}/{request.model or 'default'}",
        provider=request.provider,
        model=request.model or "default",
    )
    all_probes = (
        [get_probe(p) for p in request.probes] if request.probes else get_all_probes()
    )

    orchestrator = Orchestrator(adapter, scan_config)
    report = await orchestrator.run(all_probes, session)

    s = report.score
    return ScanResponse(
        session_id=report.session_id,
        target=session.target,
        provider=request.provider,
        model=request.model or "default",
        score=ScoreResponse(
            risk_score=s.risk_score,
            risk_level=s.risk_level,
            total_probes=s.total_probes,
            passed=s.passed,
            failed=s.failed,
            pass_rate=s.pass_rate,
            critical_findings=s.critical_findings,
            high_findings=s.high_findings,
            medium_findings=s.medium_findings,
            low_findings=s.low_findings,
        ),
        findings=[
            FindingResponse(
                probe_id=r.probe_id,
                owasp_id=r.owasp_id,
                mitre_atlas=r.mitre_atlas,
                severity=r.severity,
                score=r.score,
                passed=r.passed,
                evidence=r.evidence,
                tags=r.tags,
            )
            for r in report.results
        ],
        started_at=session.started_at.isoformat(),
        finished_at=session.finished_at.isoformat() if session.finished_at else None,
    )
