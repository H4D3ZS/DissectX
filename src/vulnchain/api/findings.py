"""Security findings API endpoints"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Dict, Optional, List, Any
from datetime import datetime
import uuid

router = APIRouter(prefix="/api/findings", tags=["findings"])


class EvidenceCreate(BaseModel):
    """Evidence data"""
    evidence_type: str  # request, response, screenshot, code
    description: str
    data: str  # Base64 encoded or text


class FindingCreate(BaseModel):
    """Request model for creating a finding"""
    workspace_id: str
    vulnerability_type: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    affected_url: str
    proof_of_concept: str
    remediation: Optional[str] = None
    flags: List[str] = []
    evidence: List[EvidenceCreate] = []


class FindingUpdate(BaseModel):
    """Request model for updating a finding"""
    vulnerability_type: Optional[str] = None
    severity: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    affected_url: Optional[str] = None
    proof_of_concept: Optional[str] = None
    remediation: Optional[str] = None
    flags: Optional[List[str]] = None


class EvidenceResponse(BaseModel):
    """Evidence response model"""
    evidence_id: str
    evidence_type: str
    description: str
    timestamp: str


class FindingResponse(BaseModel):
    """Response model for finding"""
    finding_id: str
    workspace_id: str
    vulnerability_type: str
    severity: str
    title: str
    description: str
    affected_url: str
    proof_of_concept: str
    remediation: Optional[str]
    flags: List[str]
    evidence_count: int
    discovered_at: str


# In-memory storage
findings_db: Dict[str, Dict[str, Any]] = {}
evidence_db: Dict[str, Dict[str, Any]] = {}


@router.post("/", response_model=FindingResponse)
async def create_finding(finding: FindingCreate):
    """
    Create a new security finding.
    
    Args:
        finding: Finding data
        
    Returns:
        Created finding with ID
    """
    finding_id = str(uuid.uuid4())
    
    # Store evidence
    evidence_ids = []
    for ev in finding.evidence:
        evidence_id = str(uuid.uuid4())
        evidence_db[evidence_id] = {
            "evidence_id": evidence_id,
            "finding_id": finding_id,
            "evidence_type": ev.evidence_type,
            "description": ev.description,
            "data": ev.data,
            "timestamp": datetime.now().isoformat()
        }
        evidence_ids.append(evidence_id)
    
    finding_data = {
        "finding_id": finding_id,
        "workspace_id": finding.workspace_id,
        "vulnerability_type": finding.vulnerability_type,
        "severity": finding.severity,
        "title": finding.title,
        "description": finding.description,
        "affected_url": finding.affected_url,
        "proof_of_concept": finding.proof_of_concept,
        "remediation": finding.remediation,
        "flags": finding.flags,
        "evidence_ids": evidence_ids,
        "discovered_at": datetime.now().isoformat()
    }
    
    findings_db[finding_id] = finding_data
    
    return FindingResponse(
        finding_id=finding_id,
        workspace_id=finding_data["workspace_id"],
        vulnerability_type=finding_data["vulnerability_type"],
        severity=finding_data["severity"],
        title=finding_data["title"],
        description=finding_data["description"],
        affected_url=finding_data["affected_url"],
        proof_of_concept=finding_data["proof_of_concept"],
        remediation=finding_data["remediation"],
        flags=finding_data["flags"],
        evidence_count=len(evidence_ids),
        discovered_at=finding_data["discovered_at"]
    )


@router.get("/", response_model=List[FindingResponse])
async def list_findings(
    workspace_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    vulnerability_type: Optional[str] = Query(None)
):
    """
    List all findings with optional filters.
    
    Args:
        workspace_id: Filter by workspace ID
        severity: Filter by severity
        vulnerability_type: Filter by vulnerability type
        
    Returns:
        List of findings
    """
    findings = list(findings_db.values())
    
    # Apply filters
    if workspace_id:
        findings = [f for f in findings if f["workspace_id"] == workspace_id]
    if severity:
        findings = [f for f in findings if f["severity"] == severity]
    if vulnerability_type:
        findings = [f for f in findings if f["vulnerability_type"] == vulnerability_type]
    
    return [
        FindingResponse(
            finding_id=f["finding_id"],
            workspace_id=f["workspace_id"],
            vulnerability_type=f["vulnerability_type"],
            severity=f["severity"],
            title=f["title"],
            description=f["description"],
            affected_url=f["affected_url"],
            proof_of_concept=f["proof_of_concept"],
            remediation=f["remediation"],
            flags=f["flags"],
            evidence_count=len(f.get("evidence_ids", [])),
            discovered_at=f["discovered_at"]
        )
        for f in findings
    ]


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: str):
    """
    Get a specific finding.
    
    Args:
        finding_id: Finding ID
        
    Returns:
        Finding details
    """
    if finding_id not in findings_db:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    f = findings_db[finding_id]
    
    return FindingResponse(
        finding_id=f["finding_id"],
        workspace_id=f["workspace_id"],
        vulnerability_type=f["vulnerability_type"],
        severity=f["severity"],
        title=f["title"],
        description=f["description"],
        affected_url=f["affected_url"],
        proof_of_concept=f["proof_of_concept"],
        remediation=f["remediation"],
        flags=f["flags"],
        evidence_count=len(f.get("evidence_ids", [])),
        discovered_at=f["discovered_at"]
    )


@router.put("/{finding_id}", response_model=FindingResponse)
async def update_finding(finding_id: str, finding: FindingUpdate):
    """
    Update a finding.
    
    Args:
        finding_id: Finding ID
        finding: Updated finding data
        
    Returns:
        Updated finding
    """
    if finding_id not in findings_db:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    f = findings_db[finding_id]
    
    # Update fields
    update_data = finding.dict(exclude_unset=True)
    f.update(update_data)
    
    return FindingResponse(
        finding_id=f["finding_id"],
        workspace_id=f["workspace_id"],
        vulnerability_type=f["vulnerability_type"],
        severity=f["severity"],
        title=f["title"],
        description=f["description"],
        affected_url=f["affected_url"],
        proof_of_concept=f["proof_of_concept"],
        remediation=f["remediation"],
        flags=f["flags"],
        evidence_count=len(f.get("evidence_ids", [])),
        discovered_at=f["discovered_at"]
    )


@router.delete("/{finding_id}")
async def delete_finding(finding_id: str):
    """
    Delete a finding.
    
    Args:
        finding_id: Finding ID
        
    Returns:
        Success message
    """
    if finding_id not in findings_db:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    # Delete associated evidence
    f = findings_db[finding_id]
    for evidence_id in f.get("evidence_ids", []):
        if evidence_id in evidence_db:
            del evidence_db[evidence_id]
    
    del findings_db[finding_id]
    
    return {"message": "Finding deleted successfully", "finding_id": finding_id}


@router.get("/{finding_id}/evidence", response_model=List[EvidenceResponse])
async def get_finding_evidence(finding_id: str):
    """
    Get all evidence for a finding.
    
    Args:
        finding_id: Finding ID
        
    Returns:
        List of evidence
    """
    if finding_id not in findings_db:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    f = findings_db[finding_id]
    evidence_ids = f.get("evidence_ids", [])
    
    return [
        EvidenceResponse(
            evidence_id=ev["evidence_id"],
            evidence_type=ev["evidence_type"],
            description=ev["description"],
            timestamp=ev["timestamp"]
        )
        for ev_id in evidence_ids
        if (ev := evidence_db.get(ev_id))
    ]


@router.get("/{finding_id}/evidence/{evidence_id}")
async def get_evidence_data(finding_id: str, evidence_id: str):
    """
    Get specific evidence data.
    
    Args:
        finding_id: Finding ID
        evidence_id: Evidence ID
        
    Returns:
        Evidence data
    """
    if finding_id not in findings_db:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    if evidence_id not in evidence_db:
        raise HTTPException(status_code=404, detail="Evidence not found")
    
    ev = evidence_db[evidence_id]
    
    if ev["finding_id"] != finding_id:
        raise HTTPException(status_code=404, detail="Evidence not found for this finding")
    
    return ev
