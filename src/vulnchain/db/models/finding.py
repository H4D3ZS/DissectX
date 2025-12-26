"""Finding database model"""

from sqlalchemy import Column, String, Text, DateTime, Enum as SQLEnum, JSON, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from src.vulnchain.db.base import Base


class SeverityLevel(str, enum.Enum):
    """Severity levels for findings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(Base):
    """Finding model for security vulnerabilities"""
    
    __tablename__ = "findings"
    
    # Primary key
    finding_id = Column(String(64), primary_key=True, index=True)
    
    # Foreign key
    workspace_id = Column(String(64), ForeignKey("workspaces.workspace_id"), nullable=False, index=True)
    
    # Finding details
    vulnerability_type = Column(String(100), nullable=False, index=True)
    severity = Column(SQLEnum(SeverityLevel), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    affected_url = Column(String(2048), nullable=False)
    proof_of_concept = Column(Text, nullable=False)
    remediation = Column(Text, nullable=True)
    
    # Flags and metadata
    flags = Column(JSON, default=list, nullable=False)
    meta_data = Column("metadata", JSON, default=dict, nullable=False)
    
    # Timestamps
    discovered_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    workspace = relationship("Workspace", back_populates="findings")
    evidence = relationship("Evidence", back_populates="finding", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Finding(finding_id='{self.finding_id}', type='{self.vulnerability_type}', severity='{self.severity}')>"
