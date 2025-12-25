"""Session repository"""

from typing import List, Optional
from sqlalchemy.orm import Session as DBSession
from datetime import datetime

from src.vulnchain.db.models.session import Session
from src.vulnchain.db.repositories.base import BaseRepository


class SessionRepository(BaseRepository[Session]):
    """Repository for session operations"""
    
    def __init__(self, db: DBSession):
        super().__init__(Session, db)
    
    def get_by_workspace(
        self,
        workspace_id: str,
        skip: int = 0,
        limit: int = 100
    ) -> List[Session]:
        """
        Get all sessions for a workspace.
        
        Args:
            workspace_id: Workspace ID
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of sessions
        """
        return self.db.query(Session).filter(
            Session.workspace_id == workspace_id
        ).order_by(Session.created_at.desc()).offset(skip).limit(limit).all()
    
    def get_by_domain(
        self,
        workspace_id: str,
        domain: str
    ) -> List[Session]:
        """
        Get sessions for a specific domain.
        
        Args:
            workspace_id: Workspace ID
            domain: Domain name
            
        Returns:
            List of sessions
        """
        return self.db.query(Session).filter(
            Session.workspace_id == workspace_id,
            Session.domain == domain
        ).order_by(Session.created_at.desc()).all()
    
    def get_active(
        self,
        workspace_id: str,
        skip: int = 0,
        limit: int = 100
    ) -> List[Session]:
        """
        Get active (non-expired) sessions.
        
        Args:
            workspace_id: Workspace ID
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of active sessions
        """
        now = datetime.utcnow()
        
        return self.db.query(Session).filter(
            Session.workspace_id == workspace_id,
            (Session.expires_at.is_(None)) | (Session.expires_at > now)
        ).order_by(Session.created_at.desc()).offset(skip).limit(limit).all()
    
    def get_expired(
        self,
        workspace_id: str,
        skip: int = 0,
        limit: int = 100
    ) -> List[Session]:
        """
        Get expired sessions.
        
        Args:
            workspace_id: Workspace ID
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of expired sessions
        """
        now = datetime.utcnow()
        
        return self.db.query(Session).filter(
            Session.workspace_id == workspace_id,
            Session.expires_at.isnot(None),
            Session.expires_at <= now
        ).order_by(Session.created_at.desc()).offset(skip).limit(limit).all()
    
    def update_last_used(self, session_id: str) -> Optional[Session]:
        """
        Update the last_used timestamp for a session.
        
        Args:
            session_id: Session ID
            
        Returns:
            Updated session or None
        """
        session = self.get(session_id)
        if not session:
            return None
        
        session.last_used = datetime.utcnow()
        self.db.commit()
        self.db.refresh(session)
        return session
    
    def cleanup_expired(self, workspace_id: str) -> int:
        """
        Delete all expired sessions for a workspace.
        
        Args:
            workspace_id: Workspace ID
            
        Returns:
            Number of sessions deleted
        """
        now = datetime.utcnow()
        
        count = self.db.query(Session).filter(
            Session.workspace_id == workspace_id,
            Session.expires_at.isnot(None),
            Session.expires_at <= now
        ).delete()
        
        self.db.commit()
        return count
