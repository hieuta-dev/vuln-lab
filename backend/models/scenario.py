# FILE: backend/models/scenario.py
# PURPOSE: Stores AI-generated attack scenarios from the scenario agent
# SECURITY NOTE: Read-only from user perspective; written only by the AI engine

from sqlalchemy import Column, Integer, String, Float, DateTime
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func
from database import Base


class Scenario(Base):
    __tablename__ = "scenarios"

    id = Column(Integer, primary_key=True, index=True)
    vuln_type = Column(String(60), nullable=False, index=True)
    title = Column(String(255), nullable=True)
    steps = Column(JSONB, nullable=True)
    payloads = Column(JSONB, nullable=True)
    cvss_score = Column(Float, nullable=True)
    generated_at = Column(DateTime(timezone=True), server_default=func.now())
