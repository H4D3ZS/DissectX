import subprocess
import threading
import logging
import queue
import re
from typing import Callable, List, Optional

class ToolExecutor:
    """Handles execution of external security tools with real-time output streaming"""
    
    def __init__(self, log_callback: Optional[Callable[[str, str], None]] = None):
        self.log_callback = log_callback
        self.active_processes = {}

    def _emit(self, message: str, level: str = "INFO"):
        if self.log_callback:
            self.log_callback(message, level)
        else:
            logging.info(message)

    def execute(self, tool_name: str, cmd: List[str], task_id: str, capture_output: bool = False):
        """Execute a command and stream output in a background thread"""
        output_buffer = []

        def run_in_thread():
            try:
                self._emit(f"[{tool_name}] Executing: {' '.join(cmd)}", "INFO")
                
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                
                self.active_processes[task_id] = {
                    "process": process,
                    "output": output_buffer if capture_output else None
                }
                
                for line in process.stdout:
                    clean_line = line.strip()
                    if clean_line:
                        # Strip ANSI escape codes if present
                        clean_line = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', clean_line)
                        if capture_output:
                            output_buffer.append(clean_line)
                        self._emit(f"[{tool_name}] {clean_line}", "INFO")
                
                process.wait()
                
                if process.returncode == 0:
                    self._emit(f"[{tool_name}] Task completed successfully.", "SUCCESS")
                else:
                    self._emit(f"[{tool_name}] Task exited with code {process.returncode}", "WARNING")
                    
            except FileNotFoundError:
                self._emit(f"[{tool_name}] Error: Binary not found. Please ensure it is installed in your PATH.", "ERROR")
            except Exception as e:
                self._emit(f"[{tool_name}] Exception during execution: {str(e)}", "ERROR")
            finally:
                # We don't remove it immediately if we want to capture output
                if not capture_output and task_id in self.active_processes:
                    del self.active_processes[task_id]

        thread = threading.Thread(target=run_in_thread)
        thread.daemon = True
        thread.start()
        return thread, output_buffer

    def get_output(self, task_id: str) -> List[str]:
        if task_id in self.active_processes:
            return self.active_processes[task_id].get("output", [])
        return []

    def stop_task(self, task_id: str):
        if task_id in self.active_processes:
            p_data = self.active_processes[task_id]
            if isinstance(p_data, dict) and "process" in p_data:
                p_data["process"].terminate()
                self._emit(f"Task {task_id} terminated by user.", "WARNING")
                return True
        return False

    @staticmethod
    def sanitize_target(target: str) -> str:
        """Simple sanitization to prevent command injection"""
        # Remove any shells metacharacters
        return re.sub(r'[;&|`$<>^{}]', '', target)
