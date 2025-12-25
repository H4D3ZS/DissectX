"""User repository"""

from typing import Optional, List
from sqlalchemy.orm import Session

from src.vulnchain.db.models.user import User, APIKey
from src.vulnchain.db.repositories.base import BaseRepository


class UserRepository(BaseRepository[User]):
    """Repository for user operations"""
    
    def __init__(self, db: Session):
        super().__init__(User, db)
    
    def get_by_username(self, username: str) -> Optional[User]:
        """
        Get user by username.
        
        Args:
            username: Username
            
        Returns:
            User or None
        """
        return self.db.query(User).filter(User.username == username).first()
    
    def get_by_email(self, email: str) -> Optional[User]:
        """
        Get user by email.
        
        Args:
            email: Email address
            
        Returns:
            User or None
        """
        return self.db.query(User).filter(User.email == email).first()
    
    def get_active_users(self, skip: int = 0, limit: int = 100) -> List[User]:
        """
        Get all active users.
        
        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of active users
        """
        return self.db.query(User).filter(
            User.is_active == True
        ).offset(skip).limit(limit).all()
    
    def get_admins(self, skip: int = 0, limit: int = 100) -> List[User]:
        """
        Get all admin users.
        
        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of admin users
        """
        return self.db.query(User).filter(
            User.is_admin == True
        ).offset(skip).limit(limit).all()
    
    def deactivate(self, user_id: str) -> Optional[User]:
        """
        Deactivate a user.
        
        Args:
            user_id: User ID
            
        Returns:
            Updated user or None
        """
        user = self.get(user_id)
        if not user:
            return None
        
        user.is_active = False
        self.db.commit()
        self.db.refresh(user)
        return user
    
    def activate(self, user_id: str) -> Optional[User]:
        """
        Activate a user.
        
        Args:
            user_id: User ID
            
        Returns:
            Updated user or None
        """
        user = self.get(user_id)
        if not user:
            return None
        
        user.is_active = True
        self.db.commit()
        self.db.refresh(user)
        return user
    
    def get_with_workspaces(self, user_id: str) -> Optional[User]:
        """
        Get user with all workspaces loaded.
        
        Args:
            user_id: User ID
            
        Returns:
            User with workspaces or None
        """
        from sqlalchemy.orm import joinedload
        
        return self.db.query(User).options(
            joinedload(User.workspaces)
        ).filter(User.user_id == user_id).first()


class APIKeyRepository(BaseRepository[APIKey]):
    """Repository for API key operations"""
    
    def __init__(self, db: Session):
        super().__init__(APIKey, db)
    
    def get_by_key(self, key: str) -> Optional[APIKey]:
        """
        Get API key by key value.
        
        Args:
            key: API key string
            
        Returns:
            APIKey or None
        """
        return self.db.query(APIKey).filter(APIKey.key == key).first()
    
    def get_by_user(self, user_id: str) -> List[APIKey]:
        """
        Get all API keys for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of API keys
        """
        return self.db.query(APIKey).filter(APIKey.user_id == user_id).all()
    
    def get_active(self, user_id: str) -> List[APIKey]:
        """
        Get active (non-expired) API keys for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of active API keys
        """
        from datetime import datetime
        now = datetime.utcnow()
        
        return self.db.query(APIKey).filter(
            APIKey.user_id == user_id,
            (APIKey.expires_at.is_(None)) | (APIKey.expires_at > now)
        ).all()
