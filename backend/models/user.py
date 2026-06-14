# FILE: backend/models/user.py
# PURPOSE: User model — stores credentials in both plain (vuln demo) and bcrypt hash (secure demo)
# SECURITY NOTE: password_plain exists ONLY for demonstrating why plain-text storage is dangerous

from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_plain = Column(String(255), nullable=True)   # vulnerable mode demo
    password_hash = Column(String(255), nullable=True)    # secure mode: bcrypt
    role = Column(String(20), default="user")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
