"""Workspace database model"""

from sqlalchemy import Column, String, Text, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

from src.vulnchain.db.base import Base


class Workspace(Base):
    """Workspace model for organizing CTF challenges"""
    
    __tablename__ = "workspaces"
    
    # Primary key
    workspace_id = Column(String(64), primary_key=True, index=True)
    
    # Workspace details
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    target_url = Column(String(2048), nullable=True)
    
    # Metadata stored as JSON
    meta_data = Column("metadata", JSON, default=dict, nullable=False)
    
    # Foreign key
    owner_id = Column(String(64), ForeignKey("users.user_id"), nullable=False, index=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    owner = relationship("User", back_populates="workspaces")
    findings = relationship("Finding", back_populates="workspace", cascade="all, delete-orphan")
    targets = relationship("Target", back_populates="workspace", cascade="all, delete-orphan")
    sessions = relationship("Session", back_populates="workspace", cascade="all, delete-orphan")
    logs = relationship("Log", back_populates="workspace", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Workspace(workspace_id='{self.workspace_id}', name='{self.name}')>"
