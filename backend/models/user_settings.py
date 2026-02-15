"""
User settings model for storing user preferences and credentials.
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from typing import Optional

from core.database import Base


class UserSettings(Base):
    """Store user-specific settings and encrypted credentials."""
    
    __tablename__ = "user_settings"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    
    # GitHub Integration
    github_token_encrypted = Column(Text, nullable=True)
    github_username = Column(String(255), nullable=True)  # For display purposes
    github_token_valid = Column(Boolean, default=False)
    github_token_last_validated = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    user = relationship("User", back_populates="settings")
    
    def to_dict(self) -> dict:
        """Convert to dictionary (excluding sensitive data)."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "github_configured": bool(self.github_token_encrypted),
            "github_username": self.github_username,
            "github_token_valid": self.github_token_valid,
            "github_token_last_validated": self.github_token_last_validated.isoformat() if self.github_token_last_validated else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
