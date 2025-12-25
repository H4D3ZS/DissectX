"""Evidence database model"""

from sqlalchemy import Column, String, Text, DateTime, LargeBinary, Enum as SQLEnum, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from src.vulnchain.db.base import Base


class EvidenceType(str, enum.Enum):
    """Types of evidence"""
    REQUEST = "request"
    RESPONSE = "response"
    SCREENSHOT = "screenshot"
    CODE = "code"
    LOG = "log"
    OTHER = "other"


class Evidence(Base):
    """Evidence model for supporting finding documentation"""
    
    __tablename__ = "evidence"
    
    # Primary key
    evidence_id = Column(String(64), primary_key=True, index=True)
    
    # Foreign key
    finding_id = Column(String(64), ForeignKey("findings.finding_id"), nullable=False, index=True)
    
    # Evidence details
    evidence_type = Column(SQLEnum(EvidenceType), nullable=False)
    description = Column(Text, nullable=False)
    
    # Evidence data (can be text or binary)
    data_text = Column(Text, nullable=True)
    data_binary = Column(LargeBinary, nullable=True)
    
    # Metadata
    content_type = Column(String(100), nullable=True)
    file_name = Column(String(255), nullable=True)
    
    # Timestamps
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    finding = relationship("Finding", back_populates="evidence")
    
    def __repr__(self):
        return f"<Evidence(evidence_id='{self.evidence_id}', type='{self.evidence_type}')>"
