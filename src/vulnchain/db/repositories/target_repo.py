"""Target repository"""

from typing import List, Optional
from sqlalchemy.orm import Session

from src.vulnchain.db.models.target import Target
from src.vulnchain.db.repositories.base import BaseRepository


class TargetRepository(BaseRepository[Target]):
    """Repository for target operations"""
    
    def __init__(self, db: Session):
        super().__init__(Target, db)
    
    def get_by_workspace(
        self,
        workspace_id: str,
        skip: int = 0,
        limit: int = 100
    ) -> List[Target]:
        """
        Get all targets for a workspace.
        
        Args:
            workspace_id: Workspace ID
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of targets
        """
        return self.db.query(Target).filter(
            Target.workspace_id == workspace_id
        ).order_by(Target.created_at.desc()).offset(skip).limit(limit).all()
    
    def get_by_url(self, workspace_id: str, url: str) -> Optional[Target]:
        """
        Get target by URL.
        
        Args:
            workspace_id: Workspace ID
            url: Target URL
            
        Returns:
            Target or None
        """
        return self.db.query(Target).filter(
            Target.workspace_id == workspace_id,
            Target.url == url
        ).first()
    
    def search(
        self,
        workspace_id: str,
        query: str,
        skip: int = 0,
        limit: int = 100
    ) -> List[Target]:
        """
        Search targets by name, description, or URL.
        
        Args:
            workspace_id: Workspace ID
            query: Search query
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of matching targets
        """
        return self.db.query(Target).filter(
            Target.workspace_id == workspace_id,
            (Target.name.ilike(f"%{query}%")) |
            (Target.description.ilike(f"%{query}%")) |
            (Target.url.ilike(f"%{query}%"))
        ).order_by(Target.created_at.desc()).offset(skip).limit(limit).all()
