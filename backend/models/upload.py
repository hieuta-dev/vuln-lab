# FILE: backend/models/upload.py
# PURPOSE: Upload record model — tracks files uploaded via the file-upload demo
# SECURITY NOTE: file_name stores the original name in vulnerable mode (path traversal risk)

from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.sql import func
from database import Base


class Upload(Base):
    __tablename__ = "uploads"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    file_name = Column(String(255), nullable=False)
    file_path = Column(String(255), nullable=False)
    file_size = Column(Integer, nullable=True)
    mime_type = Column(String(100), nullable=True)
    uploaded_at = Column(DateTime(timezone=True), server_default=func.now())
