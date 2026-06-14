# FILE: backend/security/file_validator.py
# PURPOSE: Demonstrates unsafe file saving (original filename) vs. MIME-validated safe save
# SECURITY NOTE: save_no_check() preserves attacker-controlled filename — intentional demo

import os
import uuid
import magic
from fastapi import UploadFile

ALLOWED_MIME_TYPES = {"image/jpeg", "image/png", "image/gif", "text/plain", "application/pdf"}


async def save_no_check(file: UploadFile, upload_dir: str) -> dict:
    # VULNERABLE: saves with original filename, no MIME check
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, file.filename or "upload")
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)
    return {
        "file_name": file.filename,
        "file_path": file_path,
        "file_size": len(content),
        "mime_type": file.content_type,
    }


async def save_validated(file: UploadFile, upload_dir: str) -> dict:
    # SECURE: checks actual MIME type via libmagic, renames to UUID
    os.makedirs(upload_dir, exist_ok=True)
    content = await file.read()
    detected_mime = magic.from_buffer(content, mime=True)
    if detected_mime not in ALLOWED_MIME_TYPES:
        raise ValueError(f"Rejected MIME type: {detected_mime}")
    ext_map = {
        "image/jpeg": ".jpg", "image/png": ".png", "image/gif": ".gif",
        "text/plain": ".txt", "application/pdf": ".pdf",
    }
    safe_name = f"{uuid.uuid4().hex}{ext_map.get(detected_mime, '.bin')}"
    file_path = os.path.join(upload_dir, safe_name)
    with open(file_path, "wb") as f:
        f.write(content)
    return {
        "file_name": safe_name,
        "file_path": file_path,
        "file_size": len(content),
        "mime_type": detected_mime,
    }
