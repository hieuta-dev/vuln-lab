# FILE: backend/models/scan_target.py
# PURPOSE: Stores scan target configuration (URL, auth, headers)

from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func
from database import Base


class ScanTarget(Base):
    __tablename__ = "scan_targets"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    target_url = Column(String(512), nullable=False)
    target_name = Column(String(255), nullable=False)
    description = Column(String(1000), nullable=True)
    auth_info = Column(JSONB, nullable=True)   # {login_url, username, password, token, cookie}
    headers = Column(JSONB, nullable=True)     # [{key, value}, ...]
    created_at = Column(DateTime(timezone=True), server_default=func.now())
