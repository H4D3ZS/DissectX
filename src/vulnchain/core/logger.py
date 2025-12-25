"""Structured logging system with JSON format"""

import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, AsyncIterator
from enum import Enum
import asyncio
from collections import deque

from src.vulnchain.core.http_models import Request, Response
from src.vulnchain.core.report_generator import ReportGenerator, Finding as ReportFinding, Evidence as ReportEvidence


def _utc_now() -> datetime:
    """Get current UTC time"""
    return datetime.now(timezone.utc)


class LogLevel(str, Enum):
    """Log level enumeration"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogEntryType(str, Enum):
    """Log entry type enumeration"""
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    FINDING = "finding"
    FLAG = "flag"
    ERROR = "error"
    INFO = "info"


@dataclass
class LogEntry:
    """Represents a single log entry"""
    
    entry_id: str
    timestamp: datetime
    level: LogLevel
    entry_type: LogEntryType
    message: str
    data: Dict[str, Any] = field(default_factory=dict)
    workspace_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert log entry to dictionary"""
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp.isoformat(),
            "level": self.level.value,
            "entry_type": self.entry_type.value,
            "message": self.message,
            "data": self.data,
            "workspace_id": self.workspace_id,
        }
    
    def to_json(self) -> str:
        """Convert log entry to JSON string"""
        return json.dumps(self.to_dict(), indent=2)


class Logger:
    """
    Structured logging system with JSON format.
    Logs all HTTP requests/responses, findings, and flags.
    Supports filtering, search, and real-time streaming.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the Logger.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.max_entries = self.config.get("max_entries", 10000)
        self._entries: deque = deque(maxlen=self.max_entries)
        self._entry_counter = 0
        self._subscribers: List[asyncio.Queue] = []
        
        # Flag patterns for common CTF formats
        self.flag_patterns = [
            r"CTF\{[^}]+\}",
            r"FLAG\{[^}]+\}",
            r"flag\{[^}]+\}",
            r"ctf\{[^}]+\}",
            r"[A-Za-z0-9_]+\{[A-Za-z0-9_\-!@#$%^&*()+=]+\}",
        ]
        
        # Compile regex patterns
        self._compiled_patterns = [re.compile(pattern) for pattern in self.flag_patterns]
    
    def add_flag_pattern(self, pattern: str):
        """
        Add a custom flag pattern.
        
        Args:
            pattern: Regex pattern string
        """
        if pattern not in self.flag_patterns:
            self.flag_patterns.append(pattern)
            self._compiled_patterns.append(re.compile(pattern))
    
    def _generate_entry_id(self) -> str:
        """Generate unique entry ID"""
        self._entry_counter += 1
        return f"log_{self._entry_counter:08d}"
    
    def log_request(self, request: Request, response: Optional[Response] = None):
        """
        Log HTTP request.
        
        Args:
            request: Request object
            response: Optional associated response
        """
        entry_id = self._generate_entry_id()
        
        # Prepare request data
        request_data = {
            "method": request.method,
            "url": request.url,
            "headers": request.headers,
            "cookies": request.cookies,
            "proxy": request.proxy,
            "timeout": request.timeout,
            "follow_redirects": request.follow_redirects,
            "http2": request.http2,
        }
        
        # Include body if present
        if request.data is not None:
            if isinstance(request.data, (str, dict, list)):
                request_data["body"] = request.data
            else:
                request_data["body"] = str(request.data)
        
        # Create log entry
        entry = LogEntry(
            entry_id=entry_id,
            timestamp=request.timestamp,
            level=LogLevel.INFO,
            entry_type=LogEntryType.HTTP_REQUEST,
            message=f"{request.method} {request.url}",
            data=request_data,
        )
        
        self._add_entry(entry)
    
    def log_response(self, response: Response):
        """
        Log HTTP response.
        
        Args:
            response: Response object
        """
        entry_id = self._generate_entry_id()
        
        # Prepare response data
        response_data = {
            "status_code": response.status_code,
            "headers": response.headers,
            "elapsed_time": response.elapsed_time,
            "body_length": len(response.body),
            "request": {
                "method": response.request.method,
                "url": response.request.url,
            },
        }
        
        # Include body text (truncate if too large)
        max_body_length = 10000
        if len(response.text) <= max_body_length:
            response_data["body"] = response.text
        else:
            response_data["body"] = response.text[:max_body_length] + "... [truncated]"
            response_data["body_truncated"] = True
        
        # Create log entry
        entry = LogEntry(
            entry_id=entry_id,
            timestamp=response.timestamp,
            level=LogLevel.INFO,
            entry_type=LogEntryType.HTTP_RESPONSE,
            message=f"{response.status_code} {response.request.method} {response.request.url}",
            data=response_data,
        )
        
        self._add_entry(entry)
        
        # Check for flags in response
        flags = self.extract_flags(response.text)
        if flags:
            self.log_flags(flags, response)
    
    def log_finding(self, finding: Dict[str, Any]):
        """
        Log security finding.
        
        Args:
            finding: Finding dictionary with vulnerability details
        """
        entry_id = self._generate_entry_id()
        
        # Determine log level based on severity
        severity = finding.get("severity", "info").upper()
        level_map = {
            "CRITICAL": LogLevel.CRITICAL,
            "HIGH": LogLevel.ERROR,
            "MEDIUM": LogLevel.WARNING,
            "LOW": LogLevel.INFO,
            "INFO": LogLevel.INFO,
        }
        level = level_map.get(severity, LogLevel.INFO)
        
        # Create log entry
        entry = LogEntry(
            entry_id=entry_id,
            timestamp=_utc_now(),
            level=level,
            entry_type=LogEntryType.FINDING,
            message=finding.get("title", "Security Finding"),
            data=finding,
            workspace_id=finding.get("workspace_id"),
        )
        
        self._add_entry(entry)
    
    def extract_flags(self, text: str) -> List[str]:
        """
        Extract CTF flags from text using regex patterns.
        
        Args:
            text: Text to search for flags
        
        Returns:
            List of extracted flags
        """
        flags = []
        for pattern in self._compiled_patterns:
            matches = pattern.findall(text)
            flags.extend(matches)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_flags = []
        for flag in flags:
            if flag not in seen:
                seen.add(flag)
                unique_flags.append(flag)
        
        return unique_flags
    
    def log_flags(self, flags: List[str], response: Optional[Response] = None):
        """
        Log extracted flags.
        
        Args:
            flags: List of flag strings
            response: Optional response where flags were found
        """
        for flag in flags:
            entry_id = self._generate_entry_id()
            
            flag_data = {
                "flag": flag,
            }
            
            if response:
                flag_data["source"] = {
                    "url": response.request.url,
                    "status_code": response.status_code,
                    "timestamp": response.timestamp.isoformat(),
                }
            
            # Create log entry
            entry = LogEntry(
                entry_id=entry_id,
                timestamp=_utc_now(),
                level=LogLevel.CRITICAL,  # Flags are always critical
                entry_type=LogEntryType.FLAG,
                message=f"Flag found: {flag}",
                data=flag_data,
            )
            
            self._add_entry(entry)
    
    def log_error(self, message: str, error: Optional[Exception] = None, context: Optional[Dict[str, Any]] = None):
        """
        Log error message.
        
        Args:
            message: Error message
            error: Optional exception object
            context: Optional context data
        """
        entry_id = self._generate_entry_id()
        
        error_data = context or {}
        if error:
            error_data["error_type"] = type(error).__name__
            error_data["error_message"] = str(error)
        
        # Create log entry
        entry = LogEntry(
            entry_id=entry_id,
            timestamp=_utc_now(),
            level=LogLevel.ERROR,
            entry_type=LogEntryType.ERROR,
            message=message,
            data=error_data,
        )
        
        self._add_entry(entry)
    
    def log_info(self, message: str, data: Optional[Dict[str, Any]] = None):
        """
        Log informational message.
        
        Args:
            message: Info message
            data: Optional additional data
        """
        entry_id = self._generate_entry_id()
        
        # Create log entry
        entry = LogEntry(
            entry_id=entry_id,
            timestamp=_utc_now(),
            level=LogLevel.INFO,
            entry_type=LogEntryType.INFO,
            message=message,
            data=data or {},
        )
        
        self._add_entry(entry)
    
    def _add_entry(self, entry: LogEntry):
        """
        Add entry to log and notify subscribers.
        
        Args:
            entry: LogEntry to add
        """
        self._entries.append(entry)
        
        # Notify all subscribers
        for queue in self._subscribers:
            try:
                queue.put_nowait(entry)
            except asyncio.QueueFull:
                # Skip if queue is full
                pass
    
    def get_entries(
        self,
        level: Optional[LogLevel] = None,
        entry_type: Optional[LogEntryType] = None,
        workspace_id: Optional[str] = None,
        search: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[LogEntry]:
        """
        Get log entries with optional filtering.
        
        Args:
            level: Filter by log level
            entry_type: Filter by entry type
            workspace_id: Filter by workspace ID
            search: Search in message and data
            limit: Maximum number of entries to return
        
        Returns:
            List of matching log entries
        """
        results = []
        
        for entry in reversed(self._entries):
            # Apply filters
            if level and entry.level != level:
                continue
            
            if entry_type and entry.entry_type != entry_type:
                continue
            
            if workspace_id and entry.workspace_id != workspace_id:
                continue
            
            if search:
                # Search in message and data
                search_lower = search.lower()
                if search_lower not in entry.message.lower():
                    # Also search in data
                    data_str = json.dumps(entry.data).lower()
                    if search_lower not in data_str:
                        continue
            
            results.append(entry)
            
            # Check limit
            if limit and len(results) >= limit:
                break
        
        return results
    
    def get_flags(self, workspace_id: Optional[str] = None) -> List[LogEntry]:
        """
        Get all flag entries.
        
        Args:
            workspace_id: Optional workspace filter
        
        Returns:
            List of flag log entries
        """
        return self.get_entries(entry_type=LogEntryType.FLAG, workspace_id=workspace_id)
    
    def get_findings(self, workspace_id: Optional[str] = None) -> List[LogEntry]:
        """
        Get all finding entries.
        
        Args:
            workspace_id: Optional workspace filter
        
        Returns:
            List of finding log entries
        """
        return self.get_entries(entry_type=LogEntryType.FINDING, workspace_id=workspace_id)
    
    async def stream_logs(self) -> AsyncIterator[LogEntry]:
        """
        Stream log entries in real-time.
        
        Yields:
            LogEntry objects as they are added
        """
        # Create a queue for this subscriber
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._subscribers.append(queue)
        
        try:
            while True:
                # Wait for next entry
                entry = await queue.get()
                yield entry
        finally:
            # Clean up subscriber
            if queue in self._subscribers:
                self._subscribers.remove(queue)
    
    def clear_logs(self, workspace_id: Optional[str] = None):
        """
        Clear log entries.
        
        Args:
            workspace_id: If provided, only clear logs for this workspace
        """
        if workspace_id:
            # Remove entries for specific workspace
            self._entries = deque(
                (entry for entry in self._entries if entry.workspace_id != workspace_id),
                maxlen=self.max_entries
            )
        else:
            # Clear all entries
            self._entries.clear()
    
    def export_logs(
        self,
        format: str = "json",
        level: Optional[LogLevel] = None,
        entry_type: Optional[LogEntryType] = None,
        workspace_id: Optional[str] = None,
    ) -> bytes:
        """
        Export logs to file format.
        
        Args:
            format: Export format ('json' or 'jsonl')
            level: Optional level filter
            entry_type: Optional type filter
            workspace_id: Optional workspace filter
        
        Returns:
            Serialized log data
        
        Raises:
            ValueError: If format not supported
        """
        entries = self.get_entries(
            level=level,
            entry_type=entry_type,
            workspace_id=workspace_id,
        )
        
        if format == "json":
            # Export as JSON array
            data = [entry.to_dict() for entry in entries]
            return json.dumps(data, indent=2).encode("utf-8")
        
        elif format == "jsonl":
            # Export as JSON Lines (one JSON object per line)
            lines = [json.dumps(entry.to_dict()) for entry in entries]
            return "\n".join(lines).encode("utf-8")
        
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def generate_report(
        self,
        format: str = "markdown",
        workspace_id: Optional[str] = None,
        workspace_name: Optional[str] = None,
        target_url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bytes:
        """
        Generate a security assessment report from findings.
        
        Args:
            format: Report format ('markdown', 'html', 'json', 'pdf')
            workspace_id: Optional workspace filter
            workspace_name: Optional workspace name for report
            target_url: Optional target URL for report
            metadata: Optional additional metadata
        
        Returns:
            Report data as bytes
        
        Raises:
            ValueError: If format not supported
        """
        # Get findings from logs
        finding_entries = self.get_findings(workspace_id=workspace_id)
        
        # Convert log entries to report findings
        findings = []
        for entry in finding_entries:
            finding_data = entry.data
            
            # Create evidence list
            evidence = []
            if "evidence" in finding_data:
                for ev in finding_data["evidence"]:
                    evidence.append(ReportEvidence(
                        evidence_type=ev.get("evidence_type", "unknown"),
                        data=ev.get("data", ""),
                        description=ev.get("description", ""),
                        timestamp=datetime.fromisoformat(ev["timestamp"]) if "timestamp" in ev else entry.timestamp,
                    ))
            
            # Create finding
            finding = ReportFinding(
                finding_id=finding_data.get("finding_id", entry.entry_id),
                workspace_id=entry.workspace_id or "",
                vulnerability_type=finding_data.get("vulnerability_type", "Unknown"),
                severity=finding_data.get("severity", "info"),
                title=finding_data.get("title", entry.message),
                description=finding_data.get("description", ""),
                affected_url=finding_data.get("affected_url", ""),
                proof_of_concept=finding_data.get("proof_of_concept", ""),
                remediation=finding_data.get("remediation", ""),
                discovered_at=entry.timestamp,
                flags=finding_data.get("flags", []),
                evidence=evidence,
            )
            findings.append(finding)
        
        # Generate report using ReportGenerator
        generator = ReportGenerator()
        return generator.generate_report(
            findings=findings,
            format=format,
            workspace_name=workspace_name,
            target_url=target_url,
            metadata=metadata,
        )
