"""Finding repository"""

from typing import List, Optional
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from src.vulnchain.db.models.finding import Finding, SeverityLevel
from src.vulnchain.db.repositories.base import BaseRepository


class FindingRepository(BaseRepository[Finding]):
    """Repository for finding operations"""
    
    def __init__(self, db: Session):
        super().__init__(Finding, db)
    
    def get_by_workspace(
        self,
        workspace_id: str,
        skip: int = 0,
        limit: int = 100
    ) -> List[Finding]:
        """
        Get all findings for a workspace.
        
        Args:
            workspace_id: Workspace ID
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of findings
        """
        return self.db.query(Finding).filter(
            Finding.workspace_id == workspace_id
        ).order_by(Finding.discovered_at.desc()).offset(skip).limit(limit).all()
    
    def get_by_severity(
        self,
        workspace_id: str,
        severity: SeverityLevel,
        skip: int = 0,
        limit: int = 100
    ) -> List[Finding]:
        """
        Get findings by severity level.
        
        Args:
            workspace_id: Workspace ID
            severity: Severity level
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of findings
        """
        return self.db.query(Finding).filter(
            Finding.workspace_id == workspace_id,
            Finding.severity == severity
        ).order_by(Finding.discovered_at.desc()).offset(skip).limit(limit).all()
    
    def get_by_type(
        self,
        workspace_id: str,
        vulnerability_type: str,
        skip: int = 0,
        limit: int = 100
    ) -> List[Finding]:
        """
        Get findings by vulnerability type.
        
        Args:
            workspace_id: Workspace ID
            vulnerability_type: Type of vulnerability
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of findings
        """
        return self.db.query(Finding).filter(
            Finding.workspace_id == workspace_id,
            Finding.vulnerability_type == vulnerability_type
        ).order_by(Finding.discovered_at.desc()).offset(skip).limit(limit).all()
    
    def get_recent(
        self,
        workspace_id: str,
        hours: int = 24,
        limit: int = 100
    ) -> List[Finding]:
        """
        Get recent findings within specified hours.
        
        Args:
            workspace_id: Workspace ID
            hours: Number of hours to look back
            limit: Maximum number of records to return
            
        Returns:
            List of recent findings
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        return self.db.query(Finding).filter(
            Finding.workspace_id == workspace_id,
            Finding.discovered_at >= cutoff_time
        ).order_by(Finding.discovered_at.desc()).limit(limit).all()
    
    def get_with_evidence(self, finding_id: str) -> Optional[Finding]:
        """
        Get finding with all evidence loaded.
        
        Args:
            finding_id: Finding ID
            
        Returns:
            Finding with evidence or None
        """
        from sqlalchemy.orm import joinedload
        
        return self.db.query(Finding).options(
            joinedload(Finding.evidence)
        ).filter(Finding.finding_id == finding_id).first()
    
    def search(
        self,
        workspace_id: str,
        query: str,
        skip: int = 0,
        limit: int = 100
    ) -> List[Finding]:
        """
        Search findings by title or description.
        
        Args:
            workspace_id: Workspace ID
            query: Search query
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of matching findings
        """
        return self.db.query(Finding).filter(
            Finding.workspace_id == workspace_id,
            (Finding.title.ilike(f"%{query}%")) |
            (Finding.description.ilike(f"%{query}%"))
        ).order_by(Finding.discovered_at.desc()).offset(skip).limit(limit).all()
    
    def count_by_severity(self, workspace_id: str) -> dict:
        """
        Count findings by severity level.
        
        Args:
            workspace_id: Workspace ID
            
        Returns:
            Dictionary with severity counts
        """
        from sqlalchemy import func
        
        results = self.db.query(
            Finding.severity,
            func.count(Finding.finding_id)
        ).filter(
            Finding.workspace_id == workspace_id
        ).group_by(Finding.severity).all()
        
        return {severity.value: count for severity, count in results}
