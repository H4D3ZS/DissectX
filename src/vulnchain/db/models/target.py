"""Target database model"""

from sqlalchemy import Column, String, Text, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

from src.vulnchain.db.base import Base


class Target(Base):
    """Target model for attack target configuration"""
    
    __tablename__ = "targets"
    
    # Primary key
    target_id = Column(String(64), primary_key=True, index=True)
    
    # Foreign key
    workspace_id = Column(String(64), ForeignKey("workspaces.workspace_id"), nullable=False, index=True)
    
    # Target details
    name = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    url = Column(String(2048), nullable=False)
    
    # Configuration stored as JSON
    custom_headers = Column(JSON, default=dict, nullable=False)
    proxy = Column(String(2048), nullable=True)
    waf_bypass_profile = Column(String(100), nullable=True)
    
    # Metadata
    meta_data = Column("metadata", JSON, default=dict, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    workspace = relationship("Workspace", back_populates="targets")
    
    def __repr__(self):
        return f"<Target(target_id='{self.target_id}', url='{self.url}')>"
