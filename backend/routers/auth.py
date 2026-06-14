# FILE: backend/routers/auth.py
# PURPOSE: Auth endpoints — JWT login/logout/me + SQL Injection demo (vulnerable mode)
# READS: request.state.secure_mode (set by SecurityModeMiddleware)

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from dependencies import get_current_user
from models.attack_log import AttackLog
from models.user import User
from security.jwt_handler import create_access_token, decode_token, revoke_token
from security.sql_injection import safe_login, vulnerable_login

router = APIRouter(prefix="/api/auth", tags=["auth"])
_bearer = HTTPBearer(auto_error=False)


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
async def login(req: Request, body: LoginRequest, db: AsyncSession = Depends(get_db)):
    secure = req.state.secure_mode
    if secure:
        user = await safe_login(db, body.username, body.password)
    else:
        user = await vulnerable_login(db, body.username, body.password)

    result_str = "exploited" if (user and not secure) else ("blocked" if not user else "success")
    db.add(AttackLog(
        endpoint="/api/auth/login",
        payload=f"username={body.username}&password={body.password}",
        security_mode="secure" if secure else "vulnerable",
        result=result_str,
    ))
    await db.commit()

    if not user:
        return {"success": False, "message": "Invalid credentials"}

    token = create_access_token({"sub": str(user["id"]), "username": user["username"], "role": user["role"]})
    return {
        "success": True,
        "access_token": token,
        "token_type": "bearer",
        "user": user,
        "mode": "secure" if secure else "vulnerable",
    }


@router.post("/logout")
async def logout(
    current_user: dict = Depends(get_current_user),
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
):
    if creds:
        revoke_token(creds.credentials)
    return {"success": True, "message": "Logged out"}


@router.get("/me")
async def me(current_user: dict = Depends(get_current_user)):
    return {"id": current_user.get("sub"), "username": current_user.get("username"), "role": current_user.get("role")}


@router.post("/register")
async def register(req: Request, body: RegisterRequest, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(text("SELECT id FROM users WHERE username=:u"), {"u": body.username})
    if existing.fetchone():
        return {"success": False, "message": "Username already taken"}

    hashed = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    user = User(username=body.username, password_plain=body.password, password_hash=hashed, role="user")
    db.add(user)
    db.add(AttackLog(
        endpoint="/api/auth/register",
        payload=f"username={body.username}",
        security_mode="secure" if req.state.secure_mode else "vulnerable",
        result="success",
    ))
    await db.commit()
    return {"success": True, "message": "Registered successfully"}
