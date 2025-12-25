"""HTTP request and response data models"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _utc_now() -> datetime:
    """Get current UTC time"""
    return datetime.now(timezone.utc)


@dataclass
class Request:
    """HTTP request representation"""

    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[Any] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    proxy: Optional[str] = None
    timeout: float = 30.0
    follow_redirects: bool = True
    http2: bool = False
    timestamp: datetime = field(default_factory=_utc_now)


@dataclass
class Response:
    """HTTP response representation"""

    status_code: int
    headers: Dict[str, str]
    body: bytes
    text: str
    elapsed_time: float
    request: Request
    history: List["Response"] = field(default_factory=list)
    timestamp: datetime = field(default_factory=_utc_now)

    @property
    def is_success(self) -> bool:
        """Check if response is successful (2xx status code)"""
        return 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        """Check if response is a redirect (3xx status code)"""
        return 300 <= self.status_code < 400

    @property
    def is_client_error(self) -> bool:
        """Check if response is a client error (4xx status code)"""
        return 400 <= self.status_code < 500

    @property
    def is_server_error(self) -> bool:
        """Check if response is a server error (5xx status code)"""
        return 500 <= self.status_code < 600
