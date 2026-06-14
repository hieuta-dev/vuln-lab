# FILE: backend/models/scan_result.py
# PURPOSE: Per-vulnerability result within a scan session

from sqlalchemy import Column, Integer, ForeignKey, String, Text, DateTime
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func
from database import Base


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("scan_sessions.id"), nullable=False)
    scenario_id = Column(Integer, ForeignKey("scenarios.id"), nullable=True)
    vuln_type = Column(String(60), nullable=False)
    status = Column(String(20), default="scanning")  # scanning/success/failed/needs_info
    missing_info = Column(Text, nullable=True)
    findings = Column(JSONB, nullable=True)
    severity = Column(String(20), nullable=True)  # critical/high/medium/low/info
    reproduce_steps = Column(JSONB, nullable=True)  # list[str] — numbered how-to-reproduce steps
    scanned_at = Column(DateTime(timezone=True), server_default=func.now())
