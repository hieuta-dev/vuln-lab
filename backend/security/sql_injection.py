# FILE: backend/security/sql_injection.py
# PURPOSE: Demonstrates vulnerable raw SQL concatenation vs. safe parameterised queries
# SECURITY NOTE: vulnerable_login() is intentionally injectable — runs in Docker only

import bcrypt
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def vulnerable_login(db: AsyncSession, username: str, password: str) -> dict | None:
    # VULNERABLE: raw string interpolation — allows ' OR '1'='1 bypass
    raw_sql = f"SELECT id, username, role, password_plain FROM users WHERE username='{username}' AND password_plain='{password}'"
    result = await db.execute(text(raw_sql))
    row = result.fetchone()
    if row:
        return {"id": row.id, "username": row.username, "role": row.role}
    return None


async def safe_login(db: AsyncSession, username: str, password: str) -> dict | None:
    # SECURE: parameterised query prevents injection; bcrypt hash comparison
    result = await db.execute(
        text("SELECT id, username, role, password_hash FROM users WHERE username=:u"),
        {"u": username},
    )
    row = result.fetchone()
    if row and row.password_hash and bcrypt.checkpw(password.encode(), row.password_hash.encode()):
        return {"id": row.id, "username": row.username, "role": row.role}
    return None
