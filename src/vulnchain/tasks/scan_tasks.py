"""Background tasks for scanning and reconnaissance operations"""
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from celery import Task
from celery.utils.log import get_task_logger

from src.vulnchain.core.celery_app import celery_app
from src.vulnchain.modules.reconnaissance import ReconnaissanceModule
from src.vulnchain.db.session import get_db
from src.vulnchain.db.repositories.finding_repo import FindingRepository
from src.vulnchain.db.repositories.session_repo import SessionRepository
from src.vulnchain.core.redis_client import get_redis

logger = get_task_logger(__name__)


class ScanTask(Task):
    """Base task class for scan operations with progress tracking"""
    
    def __init__(self):
        super().__init__()
        self._progress = 0
        self._status = "pending"
        self._current_step = ""
    
    def update_progress(self, progress: int, status: str, current_step: str = ""):
        """Update task progress"""
        self._progress = progress
        self._status = status
        self._current_step = current_step
        
        # Update task state
        self.update_state(
            state="PROGRESS",
            meta={
                "progress": progress,
                "status": status,
                "current_step": current_step,
            }
        )


@celery_app.task(bind=True, base=ScanTask, name="app.tasks.scan_tasks.run_reconnaissance")
def run_reconnaissance(
    self,
    target_url: str,
    workspace_id: int,
    user_id: int,
    options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Run reconnaissance scan on target.
    
    Args:
        target_url: Target URL to scan
        workspace_id: Workspace ID
        user_id: User ID
        options: Optional scan options
        
    Returns:
        Scan results dictionary
    """
    logger.info(f"Starting reconnaissance scan for {target_url}")
    self.update_progress(0, "starting", "Initializing reconnaissance")
    
    try:
        # Initialize reconnaissance module
        recon = ReconnaissanceModule()
        results = {}
        
        # Run WhatWeb
        self.update_progress(10, "running", "Running WhatWeb fingerprinting")
        try:
            results["whatweb"] = recon.run_whatweb(target_url)
        except Exception as e:
            logger.error(f"WhatWeb failed: {e}")
            results["whatweb"] = {"error": str(e)}
        
        # Run Wappalyzer
        self.update_progress(30, "running", "Running Wappalyzer analysis")
        try:
            results["wappalyzer"] = recon.run_wappalyzer(target_url)
        except Exception as e:
            logger.error(f"Wappalyzer failed: {e}")
            results["wappalyzer"] = {"error": str(e)}
        
        # DNS lookup
        self.update_progress(50, "running", "Performing DNS lookup")
        try:
            from urllib.parse import urlparse
            domain = urlparse(target_url).netloc
            results["dns"] = recon.dns_lookup(domain)
        except Exception as e:
            logger.error(f"DNS lookup failed: {e}")
            results["dns"] = {"error": str(e)}
        
        # SSL info
        self.update_progress(70, "running", "Gathering SSL certificate info")
        try:
            from urllib.parse import urlparse
            hostname = urlparse(target_url).netloc
            results["ssl"] = recon.get_ssl_info(hostname)
        except Exception as e:
            logger.error(f"SSL info failed: {e}")
            results["ssl"] = {"error": str(e)}
        
        # HTTP headers
        self.update_progress(90, "running", "Analyzing HTTP headers")
        try:
            results["headers"] = recon.get_http_headers(target_url)
        except Exception as e:
            logger.error(f"Header analysis failed: {e}")
            results["headers"] = {"error": str(e)}
        
        self.update_progress(100, "completed", "Reconnaissance complete")
        
        return {
            "status": "success",
            "target_url": target_url,
            "workspace_id": workspace_id,
            "results": results,
            "timestamp": datetime.utcnow().isoformat(),
        }
        
    except Exception as e:
        logger.error(f"Reconnaissance scan failed: {e}")
        self.update_progress(0, "failed", f"Error: {str(e)}")
        return {
            "status": "error",
            "error": str(e),
            "target_url": target_url,
        }


@celery_app.task(bind=True, base=ScanTask, name="app.tasks.scan_tasks.run_full_scan")
def run_full_scan(
    self,
    target_url: str,
    workspace_id: int,
    user_id: int,
    modules: Optional[List[str]] = None,
    options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Run full vulnerability scan with multiple modules.
    
    Args:
        target_url: Target URL to scan
        workspace_id: Workspace ID
        user_id: User ID
        modules: List of module names to run (None = all)
        options: Optional scan options
        
    Returns:
        Scan results dictionary
    """
    logger.info(f"Starting full scan for {target_url}")
    self.update_progress(0, "starting", "Initializing full scan")
    
    try:
        results = {}
        total_modules = len(modules) if modules else 4
        current_module = 0
        
        # Run reconnaissance first
        self.update_progress(5, "running", "Running reconnaissance")
        recon_result = run_reconnaissance(target_url, workspace_id, user_id, options)
        results["reconnaissance"] = recon_result
        
        # Determine which modules to run
        if not modules:
            modules = []  # No additional modules by default
        
        # Run each module
        for module_name in modules:
            current_module += 1
            progress = int(10 + (current_module / total_modules) * 80)
            
            self.update_progress(
                progress,
                "running",
                f"Running {module_name} module ({current_module}/{total_modules})"
            )
            
            try:
                # Module execution would go here
                # For now, just log that we would run it
                logger.info(f"Would run module: {module_name}")
                results[module_name] = {
                    "status": "not_implemented",
                    "message": f"Module {module_name} execution not yet integrated"
                }
                    
            except Exception as e:
                logger.error(f"Module {module_name} failed: {e}")
                results[module_name] = {"error": str(e)}
        
        self.update_progress(100, "completed", "Full scan complete")
        
        return {
            "status": "success",
            "target_url": target_url,
            "workspace_id": workspace_id,
            "modules_run": modules,
            "results": results,
            "timestamp": datetime.utcnow().isoformat(),
        }
        
    except Exception as e:
        logger.error(f"Full scan failed: {e}")
        self.update_progress(0, "failed", f"Error: {str(e)}")
        return {
            "status": "error",
            "error": str(e),
            "target_url": target_url,
        }


@celery_app.task(name="app.tasks.scan_tasks.run_subdomain_enumeration")
def run_subdomain_enumeration(
    domain: str,
    workspace_id: int,
    user_id: int,
    options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Run subdomain enumeration.
    
    Args:
        domain: Domain to enumerate
        workspace_id: Workspace ID
        user_id: User ID
        options: Optional enumeration options
        
    Returns:
        Enumeration results
    """
    logger.info(f"Starting subdomain enumeration for {domain}")
    
    try:
        recon = ReconnaissanceModule()
        subdomains = recon.enumerate_subdomains(domain)
        
        return {
            "status": "success",
            "domain": domain,
            "workspace_id": workspace_id,
            "subdomains": subdomains,
            "count": len(subdomains),
            "timestamp": datetime.utcnow().isoformat(),
        }
        
    except Exception as e:
        logger.error(f"Subdomain enumeration failed: {e}")
        return {
            "status": "error",
            "error": str(e),
            "domain": domain,
        }


@celery_app.task(name="app.tasks.scan_tasks.cleanup_expired_sessions")
def cleanup_expired_sessions() -> Dict[str, Any]:
    """
    Periodic task to cleanup expired sessions.
    
    Returns:
        Cleanup results
    """
    logger.info("Starting expired session cleanup")
    
    try:
        redis = get_redis()
        
        # Get all session keys
        session_keys = redis.keys("session:*")
        expired_count = 0
        
        for key in session_keys:
            ttl = redis.ttl(key)
            if ttl == -2:  # Key doesn't exist (expired)
                expired_count += 1
            elif ttl == -1:  # Key has no expiration
                # Set expiration to 24 hours
                redis.expire(key, 86400)
        
        logger.info(f"Cleaned up {expired_count} expired sessions")
        
        return {
            "status": "success",
            "expired_count": expired_count,
            "total_keys": len(session_keys),
            "timestamp": datetime.utcnow().isoformat(),
        }
        
    except Exception as e:
        logger.error(f"Session cleanup failed: {e}")
        return {
            "status": "error",
            "error": str(e),
        }


@celery_app.task(name="app.tasks.scan_tasks.cleanup_old_findings")
def cleanup_old_findings(days: int = 30) -> Dict[str, Any]:
    """
    Periodic task to cleanup old findings.
    
    Args:
        days: Delete findings older than this many days
        
    Returns:
        Cleanup results
    """
    logger.info(f"Starting cleanup of findings older than {days} days")
    
    try:
        # This would need database access
        # For now, just return success
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        logger.info(f"Would delete findings older than {cutoff_date}")
        
        return {
            "status": "success",
            "cutoff_date": cutoff_date.isoformat(),
            "deleted_count": 0,  # Placeholder
            "timestamp": datetime.utcnow().isoformat(),
        }
        
    except Exception as e:
        logger.error(f"Finding cleanup failed: {e}")
        return {
            "status": "error",
            "error": str(e),
        }
