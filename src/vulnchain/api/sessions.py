"""Session management API endpoints"""

from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Dict, Optional, List
from datetime import datetime
import uuid
import json
import io

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


class SessionCreate(BaseModel):
    """Request model for creating a session"""
    domain: str
    cookies: Dict[str, str]
    headers: Dict[str, str] = {}
    name: Optional[str] = None
    description: Optional[str] = None


class SessionUpdate(BaseModel):
    """Request model for updating a session"""
    cookies: Optional[Dict[str, str]] = None
    headers: Optional[Dict[str, str]] = None
    name: Optional[str] = None
    description: Optional[str] = None


class SessionResponse(BaseModel):
    """Response model for session"""
    session_id: str
    domain: str
    cookies: Dict[str, str]
    headers: Dict[str, str]
    name: Optional[str]
    description: Optional[str]
    created_at: str
    expires_at: Optional[str]


# In-memory storage
sessions_db: Dict[str, Dict] = {}


@router.post("/", response_model=SessionResponse)
async def create_session(session: SessionCreate):
    """
    Create a new session.
    
    Args:
        session: Session data
        
    Returns:
        Created session with ID
    """
    session_id = str(uuid.uuid4())
    
    session_data = {
        "session_id": session_id,
        "domain": session.domain,
        "cookies": session.cookies,
        "headers": session.headers,
        "name": session.name,
        "description": session.description,
        "created_at": datetime.now().isoformat(),
        "expires_at": None
    }
    
    sessions_db[session_id] = session_data
    
    return SessionResponse(**session_data)


@router.get("/", response_model=List[SessionResponse])
async def list_sessions(domain: Optional[str] = None):
    """
    List all sessions.
    
    Args:
        domain: Optional filter by domain
        
    Returns:
        List of sessions
    """
    sessions = list(sessions_db.values())
    
    if domain:
        sessions = [s for s in sessions if s["domain"] == domain]
    
    return [SessionResponse(**s) for s in sessions]


@router.get("/{session_id}", response_model=SessionResponse)
async def get_session(session_id: str):
    """
    Get a specific session.
    
    Args:
        session_id: Session ID
        
    Returns:
        Session details
    """
    if session_id not in sessions_db:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return SessionResponse(**sessions_db[session_id])


@router.put("/{session_id}", response_model=SessionResponse)
async def update_session(session_id: str, session: SessionUpdate):
    """
    Update a session.
    
    Args:
        session_id: Session ID
        session: Updated session data
        
    Returns:
        Updated session
    """
    if session_id not in sessions_db:
        raise HTTPException(status_code=404, detail="Session not found")
    
    s = sessions_db[session_id]
    
    # Update fields
    if session.cookies is not None:
        s["cookies"].update(session.cookies)
    if session.headers is not None:
        s["headers"].update(session.headers)
    if session.name is not None:
        s["name"] = session.name
    if session.description is not None:
        s["description"] = session.description
    
    return SessionResponse(**s)


@router.delete("/{session_id}")
async def delete_session(session_id: str):
    """
    Delete a session.
    
    Args:
        session_id: Session ID
        
    Returns:
        Success message
    """
    if session_id not in sessions_db:
        raise HTTPException(status_code=404, detail="Session not found")
    
    del sessions_db[session_id]
    
    return {"message": "Session deleted successfully", "session_id": session_id}


@router.post("/{session_id}/export")
async def export_session(session_id: str):
    """
    Export session to a file.
    
    Args:
        session_id: Session ID
        
    Returns:
        Session file
    """
    if session_id not in sessions_db:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session_data = sessions_db[session_id]
    session_json = json.dumps(session_data, indent=2)
    
    return StreamingResponse(
        io.BytesIO(session_json.encode()),
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=session-{session_id}.json"
        }
    )


@router.post("/import")
async def import_session(file: UploadFile = File(...)):
    """
    Import session from a file.
    
    Args:
        file: Session file
        
    Returns:
        Imported session details
    """
    try:
        content = await file.read()
        session_data = json.loads(content.decode())
        
        # Generate new session ID
        new_session_id = str(uuid.uuid4())
        session_data["session_id"] = new_session_id
        session_data["imported_at"] = datetime.now().isoformat()
        
        sessions_db[new_session_id] = session_data
        
        return SessionResponse(**session_data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to import session: {str(e)}")


@router.post("/{session_id}/apply/{target_id}")
async def apply_session_to_target(session_id: str, target_id: str):
    """
    Apply a session to a target configuration.
    
    Args:
        session_id: Session ID
        target_id: Target ID
        
    Returns:
        Success message
    """
    if session_id not in sessions_db:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # In real implementation, this would update the target configuration
    # to use this session for all requests
    
    return {
        "message": "Session applied to target successfully",
        "session_id": session_id,
        "target_id": target_id
    }
