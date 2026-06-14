# FILE: backend/models/comment.py
# PURPOSE: Comment model — XSS demo target; content stored without sanitisation
# SECURITY NOTE: content field intentionally allows raw HTML for the XSS demonstration

from sqlalchemy import Column, Integer, Text, ForeignKey, DateTime
from sqlalchemy.sql import func
from database import Base


class Comment(Base):
    __tablename__ = "comments"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
