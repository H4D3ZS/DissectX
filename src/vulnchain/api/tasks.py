"""API endpoints for background task management"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from typing import Dict, Any, List, Optional
from pydantic import BaseModel

from src.vulnchain.core.auth import get_current_user, User
from src.vulnchain.core.celery_app import celery_app
from src.vulnchain.tasks import scan_tasks, fuzzing_tasks, report_tasks
from celery.result import AsyncResult

router = APIRouter(prefix="/api/tasks", tags=["tasks"])


# Request models
class ReconScanRequest(BaseModel):
    """Request model for reconnaissance scan"""
    target_url: str
    workspace_id: int
    options: Optional[Dict[str, Any]] = None


class FullScanRequest(BaseModel):
    """Request model for full scan"""
    target_url: str
    workspace_id: int
    modules: Optional[List[str]] = None
    options: Optional[Dict[str, Any]] = None


class FuzzingRequest(BaseModel):
    """Request model for fuzzing"""
    target_url: str
    parameter: str
    wordlist_path: str
    workspace_id: int
    options: Optional[Dict[str, Any]] = None


class DirectoryFuzzingRequest(BaseModel):
    """Request model for directory fuzzing"""
    base_url: str
    wordlist_path: str
    workspace_id: int
    options: Optional[Dict[str, Any]] = None


class ReportRequest(BaseModel):
    """Request model for report generation"""
    workspace_id: int
    findings: List[Dict[str, Any]]
    format: str  # markdown, json, html, pdf
    options: Optional[Dict[str, Any]] = None


# Scan endpoints
@router.post("/scan/reconnaissance")
async def start_reconnaissance_scan(
    request: ReconScanRequest,
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Start reconnaissance scan as background task.
    
    Returns:
        Task ID and status
    """
    task = scan_tasks.run_reconnaissance.delay(
        target_url=request.target_url,
        workspace_id=request.workspace_id,
        user_id=current_user.id,
        options=request.options
    )
    
    return {
        "task_id": task.id,
        "status": "started",
        "message": "Reconnaissance scan started"
    }


@router.post("/scan/full")
async def start_full_scan(
    request: FullScanRequest,
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Start full vulnerability scan as background task.
    
    Returns:
        Task ID and status
    """
    task = scan_tasks.run_full_scan.delay(
        target_url=request.target_url,
        workspace_id=request.workspace_id,
        user_id=current_user.id,
        modules=request.modules,
        options=request.options
    )
    
    return {
        "task_id": task.id,
        "status": "started",
        "message": "Full scan started"
    }


@router.post("/scan/subdomains")
async def start_subdomain_enumeration(
    domain: str,
    workspace_id: int,
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Start subdomain enumeration as background task.
    
    Returns:
        Task ID and status
    """
    task = scan_tasks.run_subdomain_enumeration.delay(
        domain=domain,
        workspace_id=workspace_id,
        user_id=current_user.id
    )
    
    return {
        "task_id": task.id,
        "status": "started",
        "message": "Subdomain enumeration started"
    }


# Fuzzing endpoints
@router.post("/fuzzing/parameter")
async def start_parameter_fuzzing(
    request: FuzzingRequest,
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Start parameter fuzzing as background task.
    
    Returns:
        Task ID and status
    """
    task = fuzzing_tasks.run_fuzzing_campaign.delay(
        target_url=request.target_url,
        parameter=request.parameter,
        wordlist_path=request.wordlist_path,
        workspace_id=request.workspace_id,
        user_id=current_user.id,
        options=request.options
    )
    
    return {
        "task_id": task.id,
        "status": "started",
        "message": "Parameter fuzzing started"
    }


@router.post("/fuzzing/directory")
async def start_directory_fuzzing(
    request: DirectoryFuzzingRequest,
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Start directory fuzzing as background task.
    
    Returns:
        Task ID and status
    """
    task = fuzzing_tasks.run_directory_fuzzing.delay(
        base_url=request.base_url,
        wordlist_path=request.wordlist_path,
        workspace_id=request.workspace_id,
        user_id=current_user.id,
        options=request.options
    )
    
    return {
        "task_id": task.id,
        "status": "started",
        "message": "Directory fuzzing started"
    }


# Report generation endpoints
@router.post("/report/generate")
async def generate_report(
    request: ReportRequest,
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Generate report as background task.
    
    Returns:
        Task ID and status
    """
    # Select appropriate task based on format
    if request.format == "markdown":
        task = report_tasks.generate_markdown_report.delay(
            workspace_id=request.workspace_id,
            user_id=current_user.id,
            findings=request.findings,
            options=request.options
        )
    elif request.format == "json":
        task = report_tasks.generate_json_report.delay(
            workspace_id=request.workspace_id,
            user_id=current_user.id,
            findings=request.findings,
            options=request.options
        )
    elif request.format == "html":
        task = report_tasks.generate_html_report.delay(
            workspace_id=request.workspace_id,
            user_id=current_user.id,
            findings=request.findings,
            options=request.options
        )
    elif request.format == "pdf":
        task = report_tasks.generate_pdf_report.delay(
            workspace_id=request.workspace_id,
            user_id=current_user.id,
            findings=request.findings,
            options=request.options
        )
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {request.format}")
    
    return {
        "task_id": task.id,
        "status": "started",
        "format": request.format,
        "message": f"Report generation started ({request.format})"
    }


# Task status and result endpoints
@router.get("/status/{task_id}")
async def get_task_status(
    task_id: str,
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Get task status and progress.
    
    Args:
        task_id: Task ID
        
    Returns:
        Task status information
    """
    task_result = AsyncResult(task_id, app=celery_app)
    
    response = {
        "task_id": task_id,
        "state": task_result.state,
        "ready": task_result.ready(),
        "successful": task_result.successful() if task_result.ready() else None,
    }
    
    # Add progress info if available
    if task_result.state == "PROGRESS":
        response["progress"] = task_result.info
    
    # Add result if completed
    if task_result.ready():
        if task_result.successful():
            response["result"] = task_result.result
        else:
            response["error"] = str(task_result.info)
    
    return response


@router.get("/result/{task_id}")
async def get_task_result(
    task_id: str,
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Get task result.
    
    Args:
        task_id: Task ID
        
    Returns:
        Task result
    """
    task_result = AsyncResult(task_id, app=celery_app)
    
    if not task_result.ready():
        raise HTTPException(status_code=202, detail="Task not completed yet")
    
    if not task_result.successful():
        raise HTTPException(status_code=500, detail=f"Task failed: {task_result.info}")
    
    return {
        "task_id": task_id,
        "state": task_result.state,
        "result": task_result.result
    }


@router.delete("/cancel/{task_id}")
async def cancel_task(
    task_id: str,
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Cancel a running task.
    
    Args:
        task_id: Task ID
        
    Returns:
        Cancellation status
    """
    task_result = AsyncResult(task_id, app=celery_app)
    
    if task_result.ready():
        return {
            "task_id": task_id,
            "message": "Task already completed",
            "state": task_result.state
        }
    
    # Revoke the task
    celery_app.control.revoke(task_id, terminate=True)
    
    return {
        "task_id": task_id,
        "message": "Task cancelled",
        "state": "REVOKED"
    }


@router.get("/list")
async def list_active_tasks(
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    List all active tasks.
    
    Returns:
        List of active tasks
    """
    # Get active tasks from Celery
    inspect = celery_app.control.inspect()
    
    active_tasks = inspect.active()
    scheduled_tasks = inspect.scheduled()
    reserved_tasks = inspect.reserved()
    
    return {
        "active": active_tasks or {},
        "scheduled": scheduled_tasks or {},
        "reserved": reserved_tasks or {},
    }


@router.get("/stats")
async def get_task_stats(
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Get Celery worker statistics.
    
    Returns:
        Worker statistics
    """
    inspect = celery_app.control.inspect()
    
    stats = inspect.stats()
    active_queues = inspect.active_queues()
    
    return {
        "stats": stats or {},
        "active_queues": active_queues or {},
    }
