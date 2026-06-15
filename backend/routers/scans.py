# FILE: backend/routers/scans.py
# PURPOSE: Scan management — start scans, view results, provide missing info, export PDF
# SECURITY NOTE: All endpoints require valid JWT; scan targets isolated per user

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db, AsyncSessionLocal
from dependencies import get_current_user
from models.scan_result import ScanResult
from models.scan_session import ScanSession
from models.scan_target import ScanTarget
from services.scan_service import VULN_TYPES, run_scan
from services.elk_logger import elk

router = APIRouter(prefix="/api/scans", tags=["scans"])


class StartScanRequest(BaseModel):
    target_url: str
    target_name: str
    description: str | None = None
    auth_info: dict | None = None
    headers: list[dict] | None = None


class ProvideInfoRequest(BaseModel):
    vuln_type: str
    additional_info: str


# ── Start scan ────────────────────────────────────────────────────────────────

@router.post("/start")
async def start_scan(
    body: StartScanRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = int(current_user["sub"])

    target = ScanTarget(
        user_id=user_id,
        target_url=body.target_url,
        target_name=body.target_name,
        description=body.description,
        auth_info=body.auth_info,
        headers=body.headers,
    )
    db.add(target)
    await db.flush()

    session = ScanSession(user_id=user_id, target_id=target.id, status="pending")
    db.add(session)
    await db.flush()

    # Pre-create all scan_result rows in "scanning" state
    for vt in VULN_TYPES:
        db.add(ScanResult(session_id=session.id, vuln_type=vt, status="scanning"))

    await db.commit()
    await db.refresh(session)

    # ELK: log scan request for audit trail
    elk.log_scan_request(
        session_id=session.id,
        target_url=body.target_url,
        target_name=body.target_name,
        user=current_user.get("username", "unknown"),
        vuln_types=VULN_TYPES,
    )

    background_tasks.add_task(run_scan, session.id, body.target_url, body.auth_info)
    return {"session_id": session.id, "target_id": target.id, "status": "pending"}


# ── Sessions list ─────────────────────────────────────────────────────────────

@router.get("/sessions")
async def list_sessions(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = int(current_user["sub"])
    rows = (await db.execute(
        select(ScanSession, ScanTarget)
        .join(ScanTarget, ScanSession.target_id == ScanTarget.id)
        .where(ScanSession.user_id == user_id)
        .order_by(ScanSession.started_at.desc())
    )).all()

    out = []
    for sess, tgt in rows:
        # Count results
        results = (await db.execute(
            select(ScanResult).where(ScanResult.session_id == sess.id)
        )).scalars().all()
        sev_counts: dict[str, int] = {}
        for r in results:
            if r.status == "success" and r.severity:
                sev_counts[r.severity] = sev_counts.get(r.severity, 0) + 1
        out.append({
            "id": sess.id,
            "target_id": tgt.id,
            "target_name": tgt.target_name,
            "target_url": tgt.target_url,
            "status": sess.status,
            "started_at": sess.started_at,
            "completed_at": sess.completed_at,
            "severity_counts": sev_counts,
            "total_results": len(results),
        })
    return out


# ── Single session ────────────────────────────────────────────────────────────

@router.get("/sessions/{session_id}")
async def get_session(
    session_id: int,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = int(current_user["sub"])
    sess = await db.get(ScanSession, session_id)
    if not sess or sess.user_id != user_id:
        raise HTTPException(404, "Session not found")
    tgt = await db.get(ScanTarget, sess.target_id)
    results = (await db.execute(
        select(ScanResult).where(ScanResult.session_id == session_id)
        .order_by(ScanResult.scanned_at)
    )).scalars().all()
    return {
        "session": {
            "id": sess.id, "status": sess.status,
            "started_at": sess.started_at, "completed_at": sess.completed_at,
        },
        "target": {
            "id": tgt.id, "target_name": tgt.target_name,
            "target_url": tgt.target_url, "description": tgt.description,
        },
        "results": [_result_dict(r) for r in results],
    }


@router.get("/sessions/{session_id}/results")
async def get_results(
    session_id: int,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = int(current_user["sub"])
    sess = await db.get(ScanSession, session_id)
    if not sess or sess.user_id != user_id:
        raise HTTPException(404, "Session not found")
    results = (await db.execute(
        select(ScanResult).where(ScanResult.session_id == session_id)
        .order_by(ScanResult.scanned_at)
    )).scalars().all()
    completed = sum(1 for r in results if r.status != "scanning")
    return {
        "session_status": sess.status,
        "completed": completed,
        "total": len(results),
        "results": [_result_dict(r) for r in results],
    }


# ── Provide missing info ──────────────────────────────────────────────────────

@router.post("/sessions/{session_id}/provide-info")
async def provide_info(
    session_id: int,
    body: ProvideInfoRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = int(current_user["sub"])
    sess = await db.get(ScanSession, session_id)
    if not sess or sess.user_id != user_id:
        raise HTTPException(404, "Session not found")

    result = (await db.execute(
        select(ScanResult).where(
            ScanResult.session_id == session_id,
            ScanResult.vuln_type == body.vuln_type,
        )
    )).scalars().first()
    if not result:
        raise HTTPException(404, "Result not found")

    result.status = "scanning"
    result.missing_info = None
    await db.commit()

    tgt = await db.get(ScanTarget, sess.target_id)
    auth_info = (tgt.auth_info or {}).copy()
    auth_info["additional_info"] = body.additional_info

    # Retry just this vuln type
    from services.scan_service import probe_target, _get_or_create_result
    import httpx
    async def retry_one():
        async with AsyncSessionLocal() as retry_db:
            r = await _get_or_create_result(retry_db, session_id, body.vuln_type)
            async with httpx.AsyncClient(verify=False) as client:
                probe = await probe_target(client, tgt.target_url, body.vuln_type, auth_info)
            r.status = probe.get("status", "failed")
            r.severity = probe.get("severity", "info")
            r.missing_info = probe.get("missing_info")
            r.findings = {"summary": probe.get("summary", ""), "detail": probe.get("detail", "")}
            await retry_db.commit()

    background_tasks.add_task(retry_one)
    return {"status": "retrying", "vuln_type": body.vuln_type}


# ── Export PDF ────────────────────────────────────────────────────────────────

@router.get("/sessions/{session_id}/export-pdf")
async def export_pdf(
    session_id: int,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = int(current_user["sub"])
    sess = await db.get(ScanSession, session_id)
    if not sess or sess.user_id != user_id:
        raise HTTPException(404, "Session not found")
    tgt = await db.get(ScanTarget, sess.target_id)
    results = (await db.execute(
        select(ScanResult).where(ScanResult.session_id == session_id)
    )).scalars().all()

    from services.pdf_service import generate_pdf
    import asyncio
    pdf_bytes = await asyncio.get_event_loop().run_in_executor(
        None,
        generate_pdf,
        {"id": sess.id, "status": sess.status, "started_at": sess.started_at, "completed_at": sess.completed_at},
        {"target_name": tgt.target_name, "target_url": tgt.target_url},
        [_result_dict(r) for r in results],
        current_user.get("username", "unknown"),
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=vulnlab-scan-{session_id}.pdf"},
    )


# ── Delete session ────────────────────────────────────────────────────────────

@router.delete("/sessions/{session_id}")
async def delete_session(
    session_id: int,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user_id = int(current_user["sub"])
    sess = await db.get(ScanSession, session_id)
    if not sess or sess.user_id != user_id:
        raise HTTPException(404, "Session not found")

    results = (await db.execute(
        select(ScanResult).where(ScanResult.session_id == session_id)
    )).scalars().all()
    for r in results:
        await db.delete(r)
    tgt = await db.get(ScanTarget, sess.target_id)
    await db.delete(sess)
    if tgt:
        await db.delete(tgt)
    await db.commit()
    return {"success": True}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _result_dict(r: ScanResult) -> dict:
    return {
        "id": r.id,
        "vuln_type": r.vuln_type,
        "status": r.status,
        "severity": r.severity,
        "missing_info": r.missing_info,
        "findings": r.findings,
        "reproduce_steps": r.reproduce_steps,
        "scenario_id": r.scenario_id,
        "scanned_at": r.scanned_at,
    }
