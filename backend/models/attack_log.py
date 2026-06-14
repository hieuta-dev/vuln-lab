# FILE: backend/models/attack_log.py
# PURPOSE: Logs every API request with payload for forensic analysis demo
# SECURITY NOTE: Demonstrates why logging attack payloads is critical for incident response

from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.sql import func
from database import Base


class AttackLog(Base):
    __tablename__ = "attack_logs"

    id = Column(Integer, primary_key=True, index=True)
    endpoint = Column(String(255), nullable=True)
    payload = Column(Text, nullable=True)
    security_mode = Column(String(20), nullable=True)
    result = Column(String(50), nullable=True)  # 'exploited' | 'blocked'
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
