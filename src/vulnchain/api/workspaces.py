"""Workspace management API endpoints"""

from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Dict, Optional, List, Any
from datetime import datetime
import uuid
import io

router = APIRouter(prefix="/api/workspaces", tags=["workspaces"])


class WorkspaceCreate(BaseModel):
    """Request model for creating a workspace"""
    name: str
    description: Optional[str] = None
    target_url: Optional[str] = None
    metadata: Dict[str, Any] = {}


class WorkspaceUpdate(BaseModel):
    """Request model for updating a workspace"""
    name: Optional[str] = None
    description: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class WorkspaceResponse(BaseModel):
    """Response model for workspace"""
    workspace_id: str
    name: str
    description: Optional[str]
    target_url: Optional[str]
    metadata: Dict[str, Any]
    findings_count: int
    created_at: str
    updated_at: str


# In-memory storage
workspaces_db: Dict[str, Dict[str, Any]] = {}


@router.post("/", response_model=WorkspaceResponse)
async def create_workspace(workspace: WorkspaceCreate):
    """
    Create a new workspace.
    
    Args:
        workspace: Workspace configuration data
        
    Returns:
        Created workspace with ID
    """
    workspace_id = str(uuid.uuid4())
    
    workspace_data = {
        "workspace_id": workspace_id,
        "name": workspace.name,
        "description": workspace.description,
        "target_url": workspace.target_url,
        "metadata": workspace.metadata,
        "findings": [],
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat()
    }
    
    workspaces_db[workspace_id] = workspace_data
    
    return WorkspaceResponse(
        workspace_id=workspace_id,
        name=workspace_data["name"],
        description=workspace_data["description"],
        target_url=workspace_data["target_url"],
        metadata=workspace_data["metadata"],
        findings_count=0,
        created_at=workspace_data["created_at"],
        updated_at=workspace_data["updated_at"]
    )


@router.get("/", response_model=List[WorkspaceResponse])
async def list_workspaces():
    """
    List all workspaces.
    
    Returns:
        List of all workspaces
    """
    return [
        WorkspaceResponse(
            workspace_id=ws["workspace_id"],
            name=ws["name"],
            description=ws["description"],
            target_url=ws["target_url"],
            metadata=ws["metadata"],
            findings_count=len(ws.get("findings", [])),
            created_at=ws["created_at"],
            updated_at=ws["updated_at"]
        )
        for ws in workspaces_db.values()
    ]


@router.get("/{workspace_id}", response_model=WorkspaceResponse)
async def get_workspace(workspace_id: str):
    """
    Get a specific workspace.
    
    Args:
        workspace_id: Workspace ID
        
    Returns:
        Workspace details
    """
    if workspace_id not in workspaces_db:
        raise HTTPException(status_code=404, detail="Workspace not found")
    
    ws = workspaces_db[workspace_id]
    
    return WorkspaceResponse(
        workspace_id=ws["workspace_id"],
        name=ws["name"],
        description=ws["description"],
        target_url=ws["target_url"],
        metadata=ws["metadata"],
        findings_count=len(ws.get("findings", [])),
        created_at=ws["created_at"],
        updated_at=ws["updated_at"]
    )


@router.put("/{workspace_id}", response_model=WorkspaceResponse)
async def update_workspace(workspace_id: str, workspace: WorkspaceUpdate):
    """
    Update a workspace.
    
    Args:
        workspace_id: Workspace ID
        workspace: Updated workspace data
        
    Returns:
        Updated workspace
    """
    if workspace_id not in workspaces_db:
        raise HTTPException(status_code=404, detail="Workspace not found")
    
    ws = workspaces_db[workspace_id]
    
    # Update fields
    if workspace.name is not None:
        ws["name"] = workspace.name
    if workspace.description is not None:
        ws["description"] = workspace.description
    if workspace.metadata is not None:
        ws["metadata"].update(workspace.metadata)
    
    ws["updated_at"] = datetime.now().isoformat()
    
    return WorkspaceResponse(
        workspace_id=ws["workspace_id"],
        name=ws["name"],
        description=ws["description"],
        target_url=ws["target_url"],
        metadata=ws["metadata"],
        findings_count=len(ws.get("findings", [])),
        created_at=ws["created_at"],
        updated_at=ws["updated_at"]
    )


@router.delete("/{workspace_id}")
async def delete_workspace(workspace_id: str):
    """
    Delete a workspace.
    
    Args:
        workspace_id: Workspace ID
        
    Returns:
        Success message
    """
    if workspace_id not in workspaces_db:
        raise HTTPException(status_code=404, detail="Workspace not found")
    
    del workspaces_db[workspace_id]
    
    return {"message": "Workspace deleted successfully", "workspace_id": workspace_id}


@router.post("/{workspace_id}/export")
async def export_workspace(workspace_id: str):
    """
    Export workspace as a downloadable archive.
    
    Args:
        workspace_id: Workspace ID
        
    Returns:
        Workspace archive file
    """
    if workspace_id not in workspaces_db:
        raise HTTPException(status_code=404, detail="Workspace not found")
    
    ws = workspaces_db[workspace_id]
    
    # In real implementation, this would create a tar.gz archive
    # For now, return JSON representation
    import json
    workspace_json = json.dumps(ws, indent=2)
    
    return StreamingResponse(
        io.BytesIO(workspace_json.encode()),
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=workspace-{workspace_id}.json"
        }
    )


@router.post("/import")
async def import_workspace(file: UploadFile = File(...)):
    """
    Import workspace from an archive file.
    
    Args:
        file: Workspace archive file
        
    Returns:
        Imported workspace details
    """
    try:
        import json
        content = await file.read()
        workspace_data = json.loads(content.decode())
        
        # Generate new workspace ID
        new_workspace_id = str(uuid.uuid4())
        workspace_data["workspace_id"] = new_workspace_id
        workspace_data["imported_at"] = datetime.now().isoformat()
        
        workspaces_db[new_workspace_id] = workspace_data
        
        return WorkspaceResponse(
            workspace_id=new_workspace_id,
            name=workspace_data["name"],
            description=workspace_data.get("description"),
            target_url=workspace_data.get("target_url"),
            metadata=workspace_data.get("metadata", {}),
            findings_count=len(workspace_data.get("findings", [])),
            created_at=workspace_data["created_at"],
            updated_at=workspace_data["updated_at"]
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to import workspace: {str(e)}")
