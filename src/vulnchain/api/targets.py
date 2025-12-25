"""Target configuration API endpoints"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, validator
from typing import Dict, Optional, List
from datetime import datetime

from src.vulnchain.models.target import TargetConfig, validate_url, URLValidationError

router = APIRouter(prefix="/api/targets", tags=["targets"])


class TargetCreate(BaseModel):
    """Request model for creating a target"""
    url: str
    custom_headers: Dict[str, str] = Field(default_factory=dict)
    proxy: Optional[str] = None
    waf_bypass_profile: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    
    @validator('url')
    def validate_url_field(cls, v):
        try:
            validate_url(v)
            return v
        except URLValidationError as e:
            raise ValueError(str(e))
    
    @validator('proxy')
    def validate_proxy_field(cls, v):
        if v:
            try:
                validate_url(v)
                return v
            except URLValidationError as e:
                raise ValueError(f"Invalid proxy URL: {e}")
        return v


class TargetUpdate(BaseModel):
    """Request model for updating a target"""
    url: Optional[str] = None
    custom_headers: Optional[Dict[str, str]] = None
    proxy: Optional[str] = None
    waf_bypass_profile: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None


class TargetResponse(BaseModel):
    """Response model for target"""
    target_id: str
    url: str
    custom_headers: Dict[str, str]
    proxy: Optional[str]
    waf_bypass_profile: Optional[str]
    name: Optional[str]
    description: Optional[str]
    created_at: str
    updated_at: str


# In-memory storage (will be replaced with database)
targets_db: Dict[str, TargetConfig] = {}


@router.post("/", response_model=TargetResponse)
async def create_target(target: TargetCreate):
    """
    Create a new target configuration.
    
    Args:
        target: Target configuration data
        
    Returns:
        Created target with ID
    """
    try:
        config = TargetConfig(
            url=target.url,
            custom_headers=target.custom_headers,
            proxy=target.proxy,
            waf_bypass_profile=target.waf_bypass_profile,
            name=target.name,
            description=target.description
        )
        
        target_id = f"target-{len(targets_db) + 1}"
        targets_db[target_id] = config
        
        return TargetResponse(
            target_id=target_id,
            url=config.url,
            custom_headers=config.custom_headers,
            proxy=config.proxy,
            waf_bypass_profile=config.waf_bypass_profile,
            name=config.name,
            description=config.description,
            created_at=config.created_at.isoformat(),
            updated_at=config.updated_at.isoformat()
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/", response_model=List[TargetResponse])
async def list_targets():
    """
    List all target configurations.
    
    Returns:
        List of all targets
    """
    return [
        TargetResponse(
            target_id=target_id,
            url=config.url,
            custom_headers=config.custom_headers,
            proxy=config.proxy,
            waf_bypass_profile=config.waf_bypass_profile,
            name=config.name,
            description=config.description,
            created_at=config.created_at.isoformat(),
            updated_at=config.updated_at.isoformat()
        )
        for target_id, config in targets_db.items()
    ]


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(target_id: str):
    """
    Get a specific target configuration.
    
    Args:
        target_id: Target ID
        
    Returns:
        Target configuration
    """
    if target_id not in targets_db:
        raise HTTPException(status_code=404, detail="Target not found")
    
    config = targets_db[target_id]
    
    return TargetResponse(
        target_id=target_id,
        url=config.url,
        custom_headers=config.custom_headers,
        proxy=config.proxy,
        waf_bypass_profile=config.waf_bypass_profile,
        name=config.name,
        description=config.description,
        created_at=config.created_at.isoformat(),
        updated_at=config.updated_at.isoformat()
    )


@router.put("/{target_id}", response_model=TargetResponse)
async def update_target(target_id: str, target: TargetUpdate):
    """
    Update a target configuration.
    
    Args:
        target_id: Target ID
        target: Updated target data
        
    Returns:
        Updated target configuration
    """
    if target_id not in targets_db:
        raise HTTPException(status_code=404, detail="Target not found")
    
    config = targets_db[target_id]
    
    # Update fields
    update_data = target.dict(exclude_unset=True)
    config.update(**update_data)
    
    return TargetResponse(
        target_id=target_id,
        url=config.url,
        custom_headers=config.custom_headers,
        proxy=config.proxy,
        waf_bypass_profile=config.waf_bypass_profile,
        name=config.name,
        description=config.description,
        created_at=config.created_at.isoformat(),
        updated_at=config.updated_at.isoformat()
    )


@router.delete("/{target_id}")
async def delete_target(target_id: str):
    """
    Delete a target configuration.
    
    Args:
        target_id: Target ID
        
    Returns:
        Success message
    """
    if target_id not in targets_db:
        raise HTTPException(status_code=404, detail="Target not found")
    
    del targets_db[target_id]
    
    return {"message": "Target deleted successfully", "target_id": target_id}
