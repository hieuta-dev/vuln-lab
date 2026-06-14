# FILE: backend/routers/csrf_demo.py
# PURPOSE: CSRF demo — GET returns/skips token, POST verifies/ignores it based on mode
# READS: request.state.secure_mode (set by SecurityModeMiddleware)

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.attack_log import AttackLog
from security.csrf_token import generate_token, verify_token

router = APIRouter(prefix="/api/csrf", tags=["csrf"])

SESSION_ID = "demo-session"  # fixed session for demo purposes


@router.get("/token")
async def get_csrf_token(req: Request):
    secure = req.state.secure_mode
    if secure:
        token = generate_token(SESSION_ID)
        return {"csrf_token": token, "protected": True}
    return {"csrf_token": None, "protected": False}


class CsrfActionRequest(BaseModel):
    action: str
    csrf_token: str | None = None


@router.post("/action")
async def csrf_action(req: Request, body: CsrfActionRequest, db: AsyncSession = Depends(get_db)):
    secure = req.state.secure_mode
    if secure:
        if not body.csrf_token or not verify_token(body.csrf_token, SESSION_ID):
            db.add(AttackLog(
                endpoint="/api/csrf/action",
                payload=body.action,
                security_mode="secure",
                result="blocked",
            ))
            await db.commit()
            return {"success": False, "message": "CSRF token invalid or missing"}
        result_str = "blocked"
    else:
        result_str = "exploited"

    db.add(AttackLog(
        endpoint="/api/csrf/action",
        payload=body.action,
        security_mode="secure" if secure else "vulnerable",
        result=result_str,
    ))
    await db.commit()
    return {"success": True, "action": body.action, "mode": "secure" if secure else "vulnerable"}
