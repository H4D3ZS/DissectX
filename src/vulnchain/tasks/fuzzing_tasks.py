"""Background tasks for fuzzing operations"""
from typing import Dict, Any, List, Optional
from datetime import datetime
from celery import Task
from celery.utils.log import get_task_logger

from src.vulnchain.core.celery_app import celery_app
from src.vulnchain.core.payload_engine import PayloadEngine
from src.vulnchain.core.request_handler import RequestHandler

logger = get_task_logger(__name__)


class FuzzingTask(Task):
    """Base task class for fuzzing operations with progress tracking"""
    
    def __init__(self):
        super().__init__()
        self._progress = 0
        self._status = "pending"
        self._current_payload = ""
        self._results_count = 0
    
    def update_progress(
        self,
        progress: int,
        status: str,
        current_payload: str = "",
        results_count: int = 0
    ):
        """Update task progress"""
        self._progress = progress
        self._status = status
        self._current_payload = current_payload
        self._results_count = results_count
        
        # Update task state
        self.update_state(
            state="PROGRESS",
            meta={
                "progress": progress,
                "status": status,
                "current_payload": current_payload,
                "results_count": results_count,
            }
        )


@celery_app.task(
    bind=True,
    base=FuzzingTask,
    name="app.tasks.fuzzing_tasks.run_fuzzing_campaign"
)
def run_fuzzing_campaign(
    self,
    target_url: str,
    parameter: str,
    wordlist_path: str,
    workspace_id: int,
    user_id: int,
    options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Run fuzzing campaign on a parameter.
    
    Args:
        target_url: Target URL
        parameter: Parameter to fuzz
        wordlist_path: Path to wordlist file
        workspace_id: Workspace ID
        user_id: User ID
        options: Optional fuzzing options
        
    Returns:
        Fuzzing results
    """
    logger.info(f"Starting fuzzing campaign for {target_url}?{parameter}")
    self.update_progress(0, "starting", "Initializing fuzzing campaign")
    
    try:
        # Initialize components
        payload_engine = PayloadEngine()
        request_handler = RequestHandler()
        
        # Load wordlist
        self.update_progress(5, "loading", "Loading wordlist")
        payload_engine.load_wordlist(wordlist_path, category="fuzzing")
        payloads = payload_engine.get_payloads("fuzzing")
        
        total_payloads = len(payloads)
        results = []
        interesting_results = []
        
        # Baseline request
        self.update_progress(10, "baseline", "Sending baseline request")
        baseline_response = request_handler.send_request(
            "GET",
            target_url,
            params={parameter: "baseline"}
        )
        baseline_length = len(baseline_response.body)
        
        # Fuzz each payload
        for i, payload in enumerate(payloads):
            progress = int(10 + (i / total_payloads) * 85)
            self.update_progress(
                progress,
                "fuzzing",
                payload[:50],  # Truncate long payloads
                len(results)
            )
            
            try:
                # Send request with payload
                response = request_handler.send_request(
                    "GET",
                    target_url,
                    params={parameter: payload}
                )
                
                result = {
                    "payload": payload,
                    "status_code": response.status_code,
                    "length": len(response.body),
                    "time": response.elapsed_time,
                }
                
                results.append(result)
                
                # Check if response is interesting
                length_diff = abs(len(response.body) - baseline_length)
                length_diff_percent = (length_diff / baseline_length) * 100 if baseline_length > 0 else 0
                
                if (
                    response.status_code not in [404, 403] or
                    length_diff_percent > 10 or
                    response.status_code == 500
                ):
                    interesting_results.append(result)
                
            except Exception as e:
                logger.error(f"Fuzzing payload failed: {e}")
                results.append({
                    "payload": payload,
                    "error": str(e),
                })
        
        self.update_progress(100, "completed", "Fuzzing campaign complete", len(results))
        
        return {
            "status": "success",
            "target_url": target_url,
            "parameter": parameter,
            "workspace_id": workspace_id,
            "total_payloads": total_payloads,
            "results": results,
            "interesting_results": interesting_results,
            "baseline_length": baseline_length,
            "timestamp": datetime.utcnow().isoformat(),
        }
        
    except Exception as e:
        logger.error(f"Fuzzing campaign failed: {e}")
        self.update_progress(0, "failed", f"Error: {str(e)}")
        return {
            "status": "error",
            "error": str(e),
            "target_url": target_url,
        }


@celery_app.task(
    bind=True,
    base=FuzzingTask,
    name="app.tasks.fuzzing_tasks.run_directory_fuzzing"
)
def run_directory_fuzzing(
    self,
    base_url: str,
    wordlist_path: str,
    workspace_id: int,
    user_id: int,
    options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Run directory and file fuzzing.
    
    Args:
        base_url: Base URL to fuzz
        wordlist_path: Path to wordlist file
        workspace_id: Workspace ID
        user_id: User ID
        options: Optional fuzzing options
        
    Returns:
        Fuzzing results
    """
    logger.info(f"Starting directory fuzzing for {base_url}")
    self.update_progress(0, "starting", "Initializing directory fuzzing")
    
    try:
        # Initialize components
        payload_engine = PayloadEngine()
        request_handler = RequestHandler()
        
        # Load wordlist
        self.update_progress(5, "loading", "Loading wordlist")
        payload_engine.load_wordlist(wordlist_path, category="directories")
        paths = payload_engine.get_payloads("directories")
        
        total_paths = len(paths)
        results = []
        found_paths = []
        
        # Fuzz each path
        for i, path in enumerate(paths):
            progress = int(5 + (i / total_paths) * 90)
            self.update_progress(
                progress,
                "fuzzing",
                path[:50],
                len(found_paths)
            )
            
            try:
                # Construct full URL
                url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
                
                # Send request
                response = request_handler.send_request("GET", url)
                
                result = {
                    "path": path,
                    "url": url,
                    "status_code": response.status_code,
                    "length": len(response.body),
                    "time": response.elapsed_time,
                }
                
                # Check if path exists
                if response.status_code in [200, 201, 204, 301, 302, 307, 308, 401, 403]:
                    found_paths.append(result)
                    logger.info(f"Found: {url} [{response.status_code}]")
                
                results.append(result)
                
            except Exception as e:
                logger.error(f"Directory fuzzing failed for {path}: {e}")
                results.append({
                    "path": path,
                    "error": str(e),
                })
        
        self.update_progress(100, "completed", "Directory fuzzing complete", len(found_paths))
        
        return {
            "status": "success",
            "base_url": base_url,
            "workspace_id": workspace_id,
            "total_paths": total_paths,
            "found_paths": found_paths,
            "found_count": len(found_paths),
            "results": results,
            "timestamp": datetime.utcnow().isoformat(),
        }
        
    except Exception as e:
        logger.error(f"Directory fuzzing failed: {e}")
        self.update_progress(0, "failed", f"Error: {str(e)}")
        return {
            "status": "error",
            "error": str(e),
            "base_url": base_url,
        }


@celery_app.task(name="app.tasks.fuzzing_tasks.run_parameter_fuzzing")
def run_parameter_fuzzing(
    target_url: str,
    wordlist_path: str,
    workspace_id: int,
    user_id: int,
    options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Run parameter name fuzzing.
    
    Args:
        target_url: Target URL
        wordlist_path: Path to parameter wordlist
        workspace_id: Workspace ID
        user_id: User ID
        options: Optional fuzzing options
        
    Returns:
        Fuzzing results
    """
    logger.info(f"Starting parameter fuzzing for {target_url}")
    
    try:
        # Initialize components
        payload_engine = PayloadEngine()
        request_handler = RequestHandler()
        
        # Load wordlist
        payload_engine.load_wordlist(wordlist_path, category="parameters")
        parameters = payload_engine.get_payloads("parameters")
        
        # Baseline request
        baseline_response = request_handler.send_request("GET", target_url)
        baseline_length = len(baseline_response.body)
        
        found_parameters = []
        
        # Test each parameter
        for param in parameters:
            try:
                # Send request with parameter
                response = request_handler.send_request(
                    "GET",
                    target_url,
                    params={param: "test"}
                )
                
                # Check if response differs from baseline
                length_diff = abs(len(response.body) - baseline_length)
                length_diff_percent = (length_diff / baseline_length) * 100 if baseline_length > 0 else 0
                
                if length_diff_percent > 5 or response.status_code != baseline_response.status_code:
                    found_parameters.append({
                        "parameter": param,
                        "status_code": response.status_code,
                        "length": len(response.body),
                        "length_diff_percent": length_diff_percent,
                    })
                    logger.info(f"Found parameter: {param}")
                
            except Exception as e:
                logger.error(f"Parameter fuzzing failed for {param}: {e}")
        
        return {
            "status": "success",
            "target_url": target_url,
            "workspace_id": workspace_id,
            "total_parameters": len(parameters),
            "found_parameters": found_parameters,
            "found_count": len(found_parameters),
            "baseline_length": baseline_length,
            "timestamp": datetime.utcnow().isoformat(),
        }
        
    except Exception as e:
        logger.error(f"Parameter fuzzing failed: {e}")
        return {
            "status": "error",
            "error": str(e),
            "target_url": target_url,
        }
