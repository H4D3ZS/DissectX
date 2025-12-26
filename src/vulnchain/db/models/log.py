"""Log database model"""

from sqlalchemy import Column, String, Text, DateTime, Enum as SQLEnum, JSON, Integer, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from src.vulnchain.db.base import Base


class LogLevel(str, enum.Enum):
    """Log levels"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class Log(Base):
    """Log model for HTTP requests and system events"""
    
    __tablename__ = "logs"
    
    # Primary key
    log_id = Column(String(64), primary_key=True, index=True)
    
    # Foreign key
    workspace_id = Column(String(64), ForeignKey("workspaces.workspace_id"), nullable=False, index=True)
    
    # Log details
    level = Column(SQLEnum(LogLevel), nullable=False, index=True)
    module = Column(String(100), nullable=True, index=True)
    message = Column(Text, nullable=False)
    
    # HTTP request/response data (if applicable)
    request_method = Column(String(10), nullable=True)
    request_url = Column(String(2048), nullable=True)
    request_headers = Column(JSON, nullable=True)
    request_body = Column(Text, nullable=True)
    
    response_status = Column(Integer, nullable=True)
    response_headers = Column(JSON, nullable=True)
    response_body = Column(Text, nullable=True)
    response_time = Column(Integer, nullable=True)  # milliseconds
    
    # Extracted flags
    flags = Column(JSON, default=list, nullable=False)
    
    # Additional metadata
    meta_data = Column("metadata", JSON, default=dict, nullable=False)
    
    # Timestamps
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationships
    workspace = relationship("Workspace", back_populates="logs")
    
    def __repr__(self):
        return f"<Log(log_id='{self.log_id}', level='{self.level}', module='{self.module}')>"
