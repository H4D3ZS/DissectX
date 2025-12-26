"""Target configuration models"""

import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import urlparse, ParseResult


def _utc_now() -> datetime:
    """Get current UTC time"""
    return datetime.now(timezone.utc)


class URLValidationError(Exception):
    """Raised when URL validation fails"""
    pass


def validate_url(url: str) -> bool:
    """
    Validate URL according to RFC 3986.
    
    Args:
        url: URL string to validate
        
    Returns:
        True if valid
        
    Raises:
        URLValidationError: If URL is invalid
    """
    if not url or not isinstance(url, str):
        raise URLValidationError("URL must be a non-empty string")
    
    # First check scheme before detailed parsing
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme not in ('http', 'https'):
            raise URLValidationError(f"Unsupported scheme: {scheme}. Only http and https are supported")
    except Exception as e:
        raise URLValidationError(f"URL parsing failed: {str(e)}")
    
    # Basic URL pattern according to RFC 3986
    # scheme:[//authority]path[?query][#fragment]
    url_pattern = re.compile(
        r'^(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*)'  # Scheme
        r'://'  # Authority separator
        r'(?P<authority>'
        r'(?:(?P<userinfo>[^@]+)@)?'  # Optional userinfo
        r'(?P<host>'
        r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'  # Domain labels
        r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'  # TLD
        r'|'  # OR
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'  # IPv4
        r'|'  # OR
        r'\[(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\]'  # IPv6
        r')'
        r'(?::(?P<port>\d+))?'  # Optional port
        r')'
        r'(?P<path>/[^?#]*)?'  # Path
        r'(?:\?(?P<query>[^#]*))?'  # Query
        r'(?:#(?P<fragment>.*))?$'  # Fragment
    )
    
    match = url_pattern.match(url)
    if not match:
        raise URLValidationError(f"Invalid URL format: {url}")
    
    # Validate port if present
    port = match.group('port')
    if port:
        port_num = int(port)
        if not (1 <= port_num <= 65535):
            raise URLValidationError(f"Invalid port number: {port_num}. Must be between 1 and 65535")
    
    # Validate network location
    if not parsed.netloc:
        raise URLValidationError(f"Missing network location (host) in URL: {url}")
    
    return True


@dataclass
class RateLimit:
    """Rate limiting configuration"""
    requests_per_second: float = 10.0
    burst_size: int = 20


@dataclass
class TargetConfig:
    """
    Target configuration for attack operations.
    
    Stores all configuration needed to interact with a target including
    URL, custom headers, proxy settings, WAF bypass profile, and rate limiting.
    """
    
    url: str
    custom_headers: Dict[str, str] = field(default_factory=dict)
    proxy: Optional[str] = None
    waf_bypass_profile: Optional[str] = None
    rate_limit: Optional[RateLimit] = None
    session_id: Optional[str] = None
    created_at: datetime = field(default_factory=_utc_now)
    updated_at: datetime = field(default_factory=_utc_now)
    name: Optional[str] = None
    description: Optional[str] = None
    
    def __post_init__(self):
        """Validate URL after initialization"""
        validate_url(self.url)
        
        # Validate proxy URL if provided
        if self.proxy:
            validate_url(self.proxy)
    
    def to_dict(self) -> dict:
        """
        Convert target configuration to dictionary.
        
        Returns:
            Dictionary representation
        """
        data = asdict(self)
        # Convert datetime objects to ISO format strings
        data['created_at'] = self.created_at.isoformat()
        data['updated_at'] = self.updated_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: dict) -> 'TargetConfig':
        """
        Create target configuration from dictionary.
        
        Args:
            data: Dictionary with configuration data
            
        Returns:
            TargetConfig instance
        """
        # Convert ISO format strings back to datetime
        if 'created_at' in data and isinstance(data['created_at'], str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if 'updated_at' in data and isinstance(data['updated_at'], str):
            data['updated_at'] = datetime.fromisoformat(data['updated_at'])
        
        # Handle RateLimit nested object
        if 'rate_limit' in data and data['rate_limit'] is not None:
            if isinstance(data['rate_limit'], dict):
                data['rate_limit'] = RateLimit(**data['rate_limit'])
        
        return cls(**data)
    
    def save(self, filepath: Path):
        """
        Save target configuration to file.
        
        Args:
            filepath: Path to save configuration
        """
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
    
    @classmethod
    def load(cls, filepath: Path) -> 'TargetConfig':
        """
        Load target configuration from file.
        
        Args:
            filepath: Path to configuration file
            
        Returns:
            TargetConfig instance
            
        Raises:
            FileNotFoundError: If file doesn't exist
            json.JSONDecodeError: If file is not valid JSON
        """
        with open(filepath, 'r') as f:
            data = json.load(f)
        return cls.from_dict(data)
    
    def update(self, **kwargs):
        """
        Update target configuration fields.
        
        Args:
            **kwargs: Fields to update
        """
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        
        # Update timestamp
        self.updated_at = _utc_now()
        
        # Re-validate URL if it was updated
        if 'url' in kwargs:
            validate_url(self.url)
        
        # Validate proxy if it was updated
        if 'proxy' in kwargs and self.proxy:
            validate_url(self.proxy)


@dataclass
class Session:
    """Session state for authenticated requests"""
    
    session_id: str
    domain: str
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    created_at: datetime = field(default_factory=_utc_now)
    expires_at: Optional[datetime] = None
    
    def to_dict(self) -> dict:
        """Convert session to dictionary"""
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        if self.expires_at:
            data['expires_at'] = self.expires_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Session':
        """Create session from dictionary"""
        if 'created_at' in data and isinstance(data['created_at'], str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if 'expires_at' in data and data['expires_at'] and isinstance(data['expires_at'], str):
            data['expires_at'] = datetime.fromisoformat(data['expires_at'])
        return cls(**data)
    
    def is_expired(self) -> bool:
        """Check if session is expired"""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at
