"""User database model"""

from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

from src.vulnchain.db.base import Base


class User(Base):
    """User model for authentication and authorization"""
    
    __tablename__ = "users"
    
    # Primary key
    user_id = Column(String(64), primary_key=True, index=True)
    
    # User credentials
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    
    # User status
    is_active = Column(Boolean, default=True, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    workspaces = relationship("Workspace", back_populates="owner", cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User(user_id='{self.user_id}', username='{self.username}')>"


class APIKey(Base):
    """API key model for programmatic access"""
    
    __tablename__ = "api_keys"
    
    # Primary key
    key_id = Column(String(64), primary_key=True, index=True)
    
    # Key data
    key = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(100), nullable=False)
    
    # Foreign key
    user_id = Column(String(64), ForeignKey("users.user_id"), nullable=False, index=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    last_used = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="api_keys")
    
    def __repr__(self):
        return f"<APIKey(key_id='{self.key_id}', name='{self.name}')>"
