# FILE: backend/routers/uploads.py
# PURPOSE: File upload demo — unsafe original-filename save vs. MIME-validated UUID rename
# READS: request.state.secure_mode (set by SecurityModeMiddleware)

from fastapi import APIRouter, Depends, File, Request, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db
from models.attack_log import AttackLog
from models.upload import Upload
from security.file_validator import save_no_check, save_validated

router = APIRouter(prefix="/api/uploads", tags=["uploads"])


@router.post("/")
async def upload_file(req: Request, file: UploadFile = File(...), db: AsyncSession = Depends(get_db)):
    secure = req.state.secure_mode
    try:
        if secure:
            info = await save_validated(file, settings.upload_dir)
            result = "blocked"
        else:
            info = await save_no_check(file, settings.upload_dir)
            result = "exploited"
    except ValueError as exc:
        db.add(AttackLog(
            endpoint="/api/uploads",
            payload=file.filename,
            security_mode="secure",
            result="blocked",
        ))
        await db.commit()
        return {"success": False, "error": str(exc)}

    record = Upload(
        file_name=info["file_name"],
        file_path=info["file_path"],
        file_size=info["file_size"],
        mime_type=info["mime_type"],
    )
    db.add(record)
    db.add(AttackLog(
        endpoint="/api/uploads",
        payload=file.filename,
        security_mode="secure" if secure else "vulnerable",
        result=result,
    ))
    await db.commit()
    await db.refresh(record)
    return {"success": True, "upload": {"id": record.id, **info}}


@router.get("/")
async def list_uploads(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Upload).order_by(Upload.uploaded_at.desc()))
    return result.scalars().all()
