# FILE: backend/routers/comments.py
# PURPOSE: Comment CRUD — demonstrates Stored XSS (vulnerable mode) vs. bleach sanitisation (secure)
# READS: request.state.secure_mode (set by SecurityModeMiddleware)

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.attack_log import AttackLog
from models.comment import Comment
from security.xss_filter import render_raw, render_safe

router = APIRouter(prefix="/api/comments", tags=["comments"])


class CommentCreate(BaseModel):
    content: str
    user_id: int | None = None


@router.get("/")
async def list_comments(req: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Comment).order_by(Comment.created_at.desc()))
    comments = result.scalars().all()
    secure = req.state.secure_mode
    renderer = render_safe if secure else render_raw
    return [
        {
            "id": c.id,
            "user_id": c.user_id,
            "content": renderer(c.content),
            "raw_content": c.content,
            "created_at": c.created_at,
        }
        for c in comments
    ]


@router.post("/")
async def create_comment(req: Request, body: CommentCreate, db: AsyncSession = Depends(get_db)):
    secure = req.state.secure_mode
    content_to_store = render_safe(body.content) if secure else body.content

    comment = Comment(user_id=body.user_id, content=content_to_store)
    db.add(comment)
    db.add(AttackLog(
        endpoint="/api/comments",
        payload=body.content,
        security_mode="secure" if secure else "vulnerable",
        result="blocked" if secure else "exploited",
    ))
    await db.commit()
    await db.refresh(comment)
    return {"id": comment.id, "content": comment.content, "created_at": comment.created_at}
