"""Workspace Manager for multi-challenge organization"""

import json
import shutil
import tarfile
import tempfile
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

from src.vulnchain.models.target import TargetConfig, Session


def _utc_now() -> datetime:
    """Get current UTC time"""
    return datetime.now(timezone.utc)


@dataclass
class Finding:
    """Represents a security finding"""
    
    finding_id: str
    workspace_id: str
    vulnerability_type: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    affected_url: str
    proof_of_concept: str
    remediation: str
    discovered_at: datetime
    flags: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        data = asdict(self)
        data['discovered_at'] = self.discovered_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        """Create finding from dictionary"""
        if 'discovered_at' in data and isinstance(data['discovered_at'], str):
            data['discovered_at'] = datetime.fromisoformat(data['discovered_at'])
        return cls(**data)


@dataclass
class Workspace:
    """Represents a workspace for organizing CTF challenges"""
    
    workspace_id: str
    name: str
    target: Optional[TargetConfig] = None
    findings: List[Finding] = field(default_factory=list)
    session: Optional[Session] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=_utc_now)
    updated_at: datetime = field(default_factory=_utc_now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert workspace to dictionary"""
        data = {
            'workspace_id': self.workspace_id,
            'name': self.name,
            'target': self.target.to_dict() if self.target else None,
            'findings': [f.to_dict() for f in self.findings],
            'session': self.session.to_dict() if self.session else None,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Workspace':
        """Create workspace from dictionary"""
        # Convert timestamps
        if 'created_at' in data and isinstance(data['created_at'], str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if 'updated_at' in data and isinstance(data['updated_at'], str):
            data['updated_at'] = datetime.fromisoformat(data['updated_at'])
        
        # Convert target
        if data.get('target'):
            data['target'] = TargetConfig.from_dict(data['target'])
        
        # Convert findings
        if data.get('findings'):
            data['findings'] = [Finding.from_dict(f) for f in data['findings']]
        
        # Convert session
        if data.get('session'):
            data['session'] = Session.from_dict(data['session'])
        
        return cls(**data)


class WorkspaceManager:
    """
    Manages workspaces for organizing multiple CTF challenges.
    Handles workspace creation, loading, switching, and state management.
    """
    
    def __init__(self, base_path: Optional[Path] = None):
        """
        Initialize the Workspace Manager.
        
        Args:
            base_path: Base directory for storing workspaces (defaults to ./workspaces)
        """
        self.base_path = base_path or Path("./workspaces")
        self.base_path.mkdir(parents=True, exist_ok=True)
        
        self._workspaces: Dict[str, Workspace] = {}
        self._current_workspace_id: Optional[str] = None
        
        # Load existing workspaces
        self._discover_workspaces()
    
    def _discover_workspaces(self):
        """Discover and load existing workspaces from disk"""
        if not self.base_path.exists():
            return
        
        for workspace_dir in self.base_path.iterdir():
            if workspace_dir.is_dir():
                config_file = workspace_dir / "workspace.json"
                if config_file.exists():
                    try:
                        workspace = self._load_workspace_from_disk(workspace_dir)
                        self._workspaces[workspace.workspace_id] = workspace
                    except Exception:
                        # Skip invalid workspaces
                        pass
    
    def _get_workspace_path(self, workspace_id: str) -> Path:
        """Get the directory path for a workspace"""
        return self.base_path / workspace_id
    
    def _load_workspace_from_disk(self, workspace_path: Path) -> Workspace:
        """Load workspace from disk"""
        config_file = workspace_path / "workspace.json"
        with open(config_file, 'r') as f:
            data = json.load(f)
        return Workspace.from_dict(data)
    
    def _save_workspace_to_disk(self, workspace: Workspace):
        """Save workspace to disk"""
        workspace_path = self._get_workspace_path(workspace.workspace_id)
        workspace_path.mkdir(parents=True, exist_ok=True)
        
        # Save workspace configuration
        config_file = workspace_path / "workspace.json"
        with open(config_file, 'w') as f:
            json.dump(workspace.to_dict(), f, indent=2)
        
        # Create subdirectories
        (workspace_path / "findings").mkdir(exist_ok=True)
        (workspace_path / "logs").mkdir(exist_ok=True)
        (workspace_path / "evidence").mkdir(exist_ok=True)
    
    def create_workspace(
        self,
        name: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Workspace:
        """
        Create a new workspace.
        
        Args:
            name: Workspace name
            metadata: Optional metadata dictionary
        
        Returns:
            Created Workspace object
        """
        workspace_id = str(uuid.uuid4())
        
        workspace = Workspace(
            workspace_id=workspace_id,
            name=name,
            metadata=metadata or {},
        )
        
        # Save to disk
        self._save_workspace_to_disk(workspace)
        
        # Store in memory
        self._workspaces[workspace_id] = workspace
        
        # Set as current workspace if it's the first one
        if self._current_workspace_id is None:
            self._current_workspace_id = workspace_id
        
        return workspace
    
    def load_workspace(self, workspace_id: str) -> Workspace:
        """
        Load an existing workspace.
        
        Args:
            workspace_id: Workspace ID to load
        
        Returns:
            Loaded Workspace object
        
        Raises:
            ValueError: If workspace not found
        """
        # Check if already loaded in memory
        if workspace_id in self._workspaces:
            return self._workspaces[workspace_id]
        
        # Try to load from disk
        workspace_path = self._get_workspace_path(workspace_id)
        if not workspace_path.exists():
            raise ValueError(f"Workspace {workspace_id} not found")
        
        workspace = self._load_workspace_from_disk(workspace_path)
        self._workspaces[workspace_id] = workspace
        
        return workspace
    
    def get_workspace(self, workspace_id: str) -> Optional[Workspace]:
        """
        Get workspace by ID.
        
        Args:
            workspace_id: Workspace ID
        
        Returns:
            Workspace object or None if not found
        """
        try:
            return self.load_workspace(workspace_id)
        except ValueError:
            return None
    
    def list_workspaces(self) -> List[Workspace]:
        """
        List all workspaces.
        
        Returns:
            List of Workspace objects
        """
        return list(self._workspaces.values())
    
    def switch_workspace(self, workspace_id: str) -> Workspace:
        """
        Switch to a different workspace.
        
        Args:
            workspace_id: Workspace ID to switch to
        
        Returns:
            Switched Workspace object
        
        Raises:
            ValueError: If workspace not found
        """
        workspace = self.load_workspace(workspace_id)
        self._current_workspace_id = workspace_id
        return workspace
    
    def get_current_workspace(self) -> Optional[Workspace]:
        """
        Get the currently active workspace.
        
        Returns:
            Current Workspace object or None
        """
        if self._current_workspace_id:
            return self.get_workspace(self._current_workspace_id)
        return None
    
    def update_workspace(
        self,
        workspace_id: str,
        **kwargs
    ) -> Workspace:
        """
        Update workspace fields.
        
        Args:
            workspace_id: Workspace ID to update
            **kwargs: Fields to update
        
        Returns:
            Updated Workspace object
        
        Raises:
            ValueError: If workspace not found
        """
        workspace = self.load_workspace(workspace_id)
        
        # Update fields
        for key, value in kwargs.items():
            if hasattr(workspace, key):
                setattr(workspace, key, value)
        
        # Update timestamp
        workspace.updated_at = _utc_now()
        
        # Save to disk
        self._save_workspace_to_disk(workspace)
        
        return workspace
    
    def save_finding(
        self,
        workspace_id: str,
        finding: Finding
    ):
        """
        Save a finding to a workspace.
        
        Args:
            workspace_id: Workspace ID
            finding: Finding object to save
        
        Raises:
            ValueError: If workspace not found
        """
        workspace = self.load_workspace(workspace_id)
        
        # Add finding to workspace
        workspace.findings.append(finding)
        workspace.updated_at = _utc_now()
        
        # Save to disk
        self._save_workspace_to_disk(workspace)
        
        # Also save finding as separate file for easy access
        workspace_path = self._get_workspace_path(workspace_id)
        findings_dir = workspace_path / "findings"
        finding_file = findings_dir / f"{finding.finding_id}.json"
        
        with open(finding_file, 'w') as f:
            json.dump(finding.to_dict(), f, indent=2)
    
    def get_findings(
        self,
        workspace_id: str,
        severity: Optional[str] = None,
        vulnerability_type: Optional[str] = None
    ) -> List[Finding]:
        """
        Get findings from a workspace with optional filtering.
        
        Args:
            workspace_id: Workspace ID
            severity: Optional severity filter
            vulnerability_type: Optional vulnerability type filter
        
        Returns:
            List of Finding objects
        
        Raises:
            ValueError: If workspace not found
        """
        workspace = self.load_workspace(workspace_id)
        
        findings = workspace.findings
        
        # Apply filters
        if severity:
            findings = [f for f in findings if f.severity == severity]
        
        if vulnerability_type:
            findings = [f for f in findings if f.vulnerability_type == vulnerability_type]
        
        return findings
    
    def update_target(
        self,
        workspace_id: str,
        target: TargetConfig
    ):
        """
        Update the target configuration for a workspace.
        
        Args:
            workspace_id: Workspace ID
            target: Target configuration
        
        Raises:
            ValueError: If workspace not found
        """
        workspace = self.load_workspace(workspace_id)
        workspace.target = target
        workspace.updated_at = _utc_now()
        
        # Save to disk
        self._save_workspace_to_disk(workspace)
    
    def update_session(
        self,
        workspace_id: str,
        session: Session
    ):
        """
        Update the session for a workspace.
        
        Args:
            workspace_id: Workspace ID
            session: Session object
        
        Raises:
            ValueError: If workspace not found
        """
        workspace = self.load_workspace(workspace_id)
        workspace.session = session
        workspace.updated_at = _utc_now()
        
        # Save to disk
        self._save_workspace_to_disk(workspace)
    
    def delete_workspace(self, workspace_id: str):
        """
        Delete a workspace.
        
        Args:
            workspace_id: Workspace ID to delete
        
        Raises:
            ValueError: If workspace not found
        """
        workspace_path = self._get_workspace_path(workspace_id)
        
        if not workspace_path.exists():
            raise ValueError(f"Workspace {workspace_id} not found")
        
        # Remove from disk
        shutil.rmtree(workspace_path)
        
        # Remove from memory
        if workspace_id in self._workspaces:
            del self._workspaces[workspace_id]
        
        # Clear current workspace if it was deleted
        if self._current_workspace_id == workspace_id:
            self._current_workspace_id = None
    
    def get_workspace_stats(self, workspace_id: str) -> Dict[str, Any]:
        """
        Get statistics for a workspace.
        
        Args:
            workspace_id: Workspace ID
        
        Returns:
            Dictionary with workspace statistics
        
        Raises:
            ValueError: If workspace not found
        """
        workspace = self.load_workspace(workspace_id)
        
        # Count findings by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
        }
        
        for finding in workspace.findings:
            severity = finding.severity.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Count flags
        total_flags = sum(len(f.flags) for f in workspace.findings)
        
        return {
            'workspace_id': workspace_id,
            'name': workspace.name,
            'total_findings': len(workspace.findings),
            'severity_counts': severity_counts,
            'total_flags': total_flags,
            'has_target': workspace.target is not None,
            'has_session': workspace.session is not None,
            'created_at': workspace.created_at.isoformat(),
            'updated_at': workspace.updated_at.isoformat(),
        }
    
    def export_workspace(self, workspace_id: str) -> bytes:
        """
        Export workspace to a portable archive.
        
        Packages the complete workspace including configuration, findings,
        session data, and all associated files into a tar.gz archive.
        
        Args:
            workspace_id: Workspace ID to export
        
        Returns:
            Archive data as bytes
        
        Raises:
            ValueError: If workspace not found
        """
        workspace = self.load_workspace(workspace_id)
        workspace_path = self._get_workspace_path(workspace_id)
        
        if not workspace_path.exists():
            raise ValueError(f"Workspace {workspace_id} not found on disk")
        
        # Create temporary file for archive
        with tempfile.NamedTemporaryFile(delete=False, suffix='.tar.gz') as tmp_file:
            tmp_path = Path(tmp_file.name)
        
        try:
            # Create tar.gz archive
            with tarfile.open(tmp_path, 'w:gz') as tar:
                # Add workspace directory with all contents
                tar.add(
                    workspace_path,
                    arcname=workspace_id,
                    recursive=True
                )
            
            # Read archive data
            with open(tmp_path, 'rb') as f:
                archive_data = f.read()
            
            return archive_data
        
        finally:
            # Clean up temporary file
            if tmp_path.exists():
                tmp_path.unlink()
    
    def import_workspace(self, data: bytes) -> Workspace:
        """
        Import workspace from a portable archive.
        
        Restores complete workspace state from an archive including all
        configurations, findings, sessions, and associated files.
        
        Args:
            data: Archive data as bytes
        
        Returns:
            Imported Workspace object
        
        Raises:
            ValueError: If archive is invalid or workspace already exists
        """
        # Create temporary file for archive
        with tempfile.NamedTemporaryFile(delete=False, suffix='.tar.gz') as tmp_file:
            tmp_file.write(data)
            tmp_path = Path(tmp_file.name)
        
        try:
            # Extract to temporary directory first
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_extract_path = Path(tmp_dir)
                
                # Extract archive
                with tarfile.open(tmp_path, 'r:gz') as tar:
                    # Security check: ensure no path traversal
                    for member in tar.getmembers():
                        if member.name.startswith('/') or '..' in member.name:
                            raise ValueError(f"Invalid archive: unsafe path {member.name}")
                    
                    tar.extractall(tmp_extract_path)
                
                # Find workspace directory (should be the only top-level directory)
                workspace_dirs = [d for d in tmp_extract_path.iterdir() if d.is_dir()]
                
                if len(workspace_dirs) != 1:
                    raise ValueError("Invalid archive: expected exactly one workspace directory")
                
                extracted_workspace_path = workspace_dirs[0]
                workspace_id = extracted_workspace_path.name
                
                # Check if workspace already exists
                target_path = self._get_workspace_path(workspace_id)
                if target_path.exists():
                    raise ValueError(f"Workspace {workspace_id} already exists")
                
                # Load workspace configuration to validate
                config_file = extracted_workspace_path / "workspace.json"
                if not config_file.exists():
                    raise ValueError("Invalid archive: missing workspace.json")
                
                with open(config_file, 'r') as f:
                    workspace_data = json.load(f)
                
                workspace = Workspace.from_dict(workspace_data)
                
                # Move workspace to final location
                shutil.move(str(extracted_workspace_path), str(target_path))
                
                # Store in memory
                self._workspaces[workspace_id] = workspace
                
                return workspace
        
        finally:
            # Clean up temporary file
            if tmp_path.exists():
                tmp_path.unlink()
