"""Workspace repository"""

from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session

from src.vulnchain.db.models.workspace import Workspace
from src.vulnchain.db.repositories.base import BaseRepository


class WorkspaceRepository(BaseRepository[Workspace]):
    """Repository for workspace operations"""
    
    def __init__(self, db: Session):
        super().__init__(Workspace, db)
    
    def get_by_owner(self, owner_id: str, skip: int = 0, limit: int = 100) -> List[Workspace]:
        """
        Get all workspaces for a specific owner.
        
        Args:
            owner_id: User ID of the owner
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of workspaces
        """
        return self.db.query(Workspace).filter(
            Workspace.owner_id == owner_id
        ).offset(skip).limit(limit).all()
    
    def get_by_name(self, name: str, owner_id: str) -> Optional[Workspace]:
        """
        Get workspace by name for a specific owner.
        
        Args:
            name: Workspace name
            owner_id: User ID of the owner
            
        Returns:
            Workspace or None
        """
        return self.db.query(Workspace).filter(
            Workspace.name == name,
            Workspace.owner_id == owner_id
        ).first()
    
    def search(self, query: str, owner_id: Optional[str] = None) -> List[Workspace]:
        """
        Search workspaces by name or description.
        
        Args:
            query: Search query
            owner_id: Optional owner ID to filter by
            
        Returns:
            List of matching workspaces
        """
        q = self.db.query(Workspace).filter(
            (Workspace.name.ilike(f"%{query}%")) |
            (Workspace.description.ilike(f"%{query}%"))
        )
        
        if owner_id:
            q = q.filter(Workspace.owner_id == owner_id)
        
        return q.all()
    
    def get_with_findings(self, workspace_id: str) -> Optional[Workspace]:
        """
        Get workspace with all findings loaded.
        
        Args:
            workspace_id: Workspace ID
            
        Returns:
            Workspace with findings or None
        """
        from sqlalchemy.orm import joinedload
        
        return self.db.query(Workspace).options(
            joinedload(Workspace.findings)
        ).filter(Workspace.workspace_id == workspace_id).first()
    
    def update_metadata(self, workspace_id: str, metadata: Dict[str, Any]) -> Optional[Workspace]:
        """
        Update workspace metadata.
        
        Args:
            workspace_id: Workspace ID
            metadata: New metadata dictionary
            
        Returns:
            Updated workspace or None
        """
        workspace = self.get(workspace_id)
        if not workspace:
            return None
        
        workspace.meta_data = metadata
        self.db.commit()
        self.db.refresh(workspace)
        return workspace
