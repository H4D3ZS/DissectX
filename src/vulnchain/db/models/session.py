"""Session database model"""

from sqlalchemy import Column, String, Text, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

from src.vulnchain.db.base import Base


class Session(Base):
    """Session model for HTTP session management"""
    
    __tablename__ = "sessions"
    
    # Primary key
    session_id = Column(String(64), primary_key=True, index=True)
    
    # Foreign key
    workspace_id = Column(String(64), ForeignKey("workspaces.workspace_id"), nullable=False, index=True)
    
    # Session details
    name = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    domain = Column(String(255), nullable=False, index=True)
    
    # Session data stored as JSON
    cookies = Column(JSON, default=dict, nullable=False)
    headers = Column(JSON, default=dict, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    last_used = Column(DateTime, nullable=True)
    
    # Relationships
    workspace = relationship("Workspace", back_populates="sessions")
    
    def __repr__(self):
        return f"<Session(session_id='{self.session_id}', domain='{self.domain}')>"
