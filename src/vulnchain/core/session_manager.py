"""Session Manager for cookie handling and session state management"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, List
from http.cookies import SimpleCookie
from urllib.parse import urlparse


def _utc_now() -> datetime:
    """Get current UTC time"""
    return datetime.now(timezone.utc)


@dataclass
class Cookie:
    """Represents a single HTTP cookie"""

    name: str
    value: str
    domain: str
    path: str = "/"
    expires: Optional[datetime] = None
    max_age: Optional[int] = None
    secure: bool = False
    http_only: bool = False
    same_site: Optional[str] = None

    def is_expired(self) -> bool:
        """Check if cookie has expired"""
        if self.expires:
            return datetime.now(timezone.utc) > self.expires
        return False

    def matches_domain(self, domain: str) -> bool:
        """Check if cookie matches the given domain"""
        # Handle domain matching according to RFC 6265
        cookie_domain = self.domain.lower()
        target_domain = domain.lower()

        # Exact match
        if cookie_domain == target_domain:
            return True

        # Domain cookie (starts with .)
        if cookie_domain.startswith("."):
            return target_domain.endswith(cookie_domain) or target_domain == cookie_domain[1:]

        # Cookie domain without leading dot should match subdomains
        return target_domain.endswith("." + cookie_domain)

    def matches_path(self, path: str) -> bool:
        """Check if cookie matches the given path"""
        # Path matching according to RFC 6265
        if self.path == path:
            return True
        if path.startswith(self.path):
            if self.path.endswith("/"):
                return True
            if len(path) > len(self.path) and path[len(self.path)] == "/":
                return True
        return False


@dataclass
class Session:
    """Represents an HTTP session with cookies and metadata"""

    session_id: str
    domain: str
    cookies: Dict[str, Cookie] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    created_at: datetime = field(default_factory=_utc_now)
    expires_at: Optional[datetime] = None

    def is_expired(self) -> bool:
        """Check if session has expired"""
        if self.expires_at:
            return datetime.now(timezone.utc) > self.expires_at
        return False

    def get_cookies_for_request(self, url: str) -> Dict[str, str]:
        """
        Get cookies that should be sent with a request to the given URL.

        Args:
            url: Target URL

        Returns:
            Dictionary of cookie name-value pairs
        """
        parsed = urlparse(url)
        domain = parsed.netloc.split(":")[0]  # Remove port if present
        path = parsed.path or "/"

        result = {}
        for cookie in self.cookies.values():
            if not cookie.is_expired() and cookie.matches_domain(domain) and cookie.matches_path(path):
                result[cookie.name] = cookie.value

        return result


class SessionManager:
    """
    Manages HTTP sessions and cookies across requests.
    Handles automatic cookie extraction, storage, and application to subsequent requests.
    
    Can use Redis for persistent session storage or fall back to in-memory storage.
    """

    def __init__(self, use_redis: bool = True, redis_ttl: int = 3600):
        """
        Initialize the Session Manager.
        
        Args:
            use_redis: Whether to use Redis for session storage
            redis_ttl: Time to live for sessions in Redis (seconds)
        """
        self._sessions: Dict[str, Session] = {}
        self._domain_to_session: Dict[str, str] = {}
        self.use_redis = use_redis
        self.redis_ttl = redis_ttl
        
        # Try to initialize Redis if requested
        if self.use_redis:
            try:
                from src.vulnchain.core.redis_client import get_redis
                self.redis = get_redis()
                # Test Redis connection
                if not self.redis.ping():
                    print("Redis not available, falling back to in-memory storage")
                    self.use_redis = False
            except Exception as e:
                print(f"Failed to initialize Redis: {e}, falling back to in-memory storage")
                self.use_redis = False
    
    def _redis_key(self, session_id: str) -> str:
        """Generate Redis key for session"""
        return f"session:{session_id}"
    
    def _redis_domain_key(self, domain: str) -> str:
        """Generate Redis key for domain-to-session mapping"""
        return f"session:domain:{domain}"
    
    def _save_to_redis(self, session: Session):
        """Save session to Redis"""
        if not self.use_redis:
            return
        
        try:
            # Serialize session
            session_data = self.export_session(session.session_id, format="json")
            
            # Save to Redis with TTL
            key = self._redis_key(session.session_id)
            self.redis.set(key, session_data.decode(), ttl=self.redis_ttl, serialize="json")
            
            # Save domain mapping
            domain_key = self._redis_domain_key(session.domain)
            self.redis.set(domain_key, session.session_id, ttl=self.redis_ttl, serialize="json")
        except Exception as e:
            print(f"Failed to save session to Redis: {e}")
    
    def _load_from_redis(self, session_id: str) -> Optional[Session]:
        """Load session from Redis"""
        if not self.use_redis:
            return None
        
        try:
            key = self._redis_key(session_id)
            session_data = self.redis.get(key, serialize="json")
            
            if session_data:
                # Deserialize session
                session = self.import_session(session_data.encode(), format="json")
                return session
        except Exception as e:
            print(f"Failed to load session from Redis: {e}")
        
        return None
    
    def _delete_from_redis(self, session_id: str, domain: str):
        """Delete session from Redis"""
        if not self.use_redis:
            return
        
        try:
            key = self._redis_key(session_id)
            domain_key = self._redis_domain_key(domain)
            self.redis.delete(key)
            self.redis.delete(domain_key)
        except Exception as e:
            print(f"Failed to delete session from Redis: {e}")

    def capture_session(self, response, domain: Optional[str] = None) -> Session:
        """
        Extract and store session from HTTP response.

        Args:
            response: Response object containing Set-Cookie headers
            domain: Optional domain override (extracted from response URL if not provided)

        Returns:
            Session object containing extracted cookies
        """
        # Extract domain from response if not provided
        if domain is None:
            parsed = urlparse(response.request.url)
            domain = parsed.netloc.split(":")[0]

        # Get or create session for this domain
        session_id = self._domain_to_session.get(domain)
        if session_id and session_id in self._sessions:
            session = self._sessions[session_id]
        else:
            # Create new session
            import uuid
            session_id = str(uuid.uuid4())
            session = Session(session_id=session_id, domain=domain)
            self._sessions[session_id] = session
            self._domain_to_session[domain] = session_id

        # Extract cookies from Set-Cookie headers
        cookies = self._extract_cookies_from_response(response, domain)
        
        # Update session cookies
        for cookie in cookies:
            session.cookies[cookie.name] = cookie
        
        # Save to Redis if enabled
        self._save_to_redis(session)

        return session

    def _extract_cookies_from_response(self, response, domain: str) -> List[Cookie]:
        """
        Extract cookies from response Set-Cookie headers.

        Args:
            response: Response object
            domain: Domain for the cookies

        Returns:
            List of Cookie objects
        """
        cookies = []
        
        # Get all Set-Cookie headers (can be multiple)
        set_cookie_headers = []
        for key, value in response.headers.items():
            if key.lower() == "set-cookie":
                set_cookie_headers.append(value)

        # Parse each Set-Cookie header
        for header_value in set_cookie_headers:
            cookie = self._parse_set_cookie_header(header_value, domain)
            if cookie:
                cookies.append(cookie)

        return cookies

    def _parse_set_cookie_header(self, header_value: str, default_domain: str) -> Optional[Cookie]:
        """
        Parse a Set-Cookie header value into a Cookie object.

        Args:
            header_value: Set-Cookie header value
            default_domain: Default domain if not specified in cookie

        Returns:
            Cookie object or None if parsing fails
        """
        try:
            # Use SimpleCookie for parsing
            simple_cookie = SimpleCookie()
            simple_cookie.load(header_value)

            # Get the first (and should be only) cookie
            if not simple_cookie:
                return None

            cookie_name = list(simple_cookie.keys())[0]
            morsel = simple_cookie[cookie_name]

            # Extract cookie attributes
            name = cookie_name
            value = morsel.value
            domain = morsel.get("domain", "")
            # If no domain specified, use the default domain
            if not domain or domain == "":
                domain = default_domain
            path = morsel.get("path", "/")
            
            # Parse expires
            expires = None
            expires_str = morsel.get("expires")
            if expires_str:
                try:
                    # Parse HTTP date format
                    from email.utils import parsedate_to_datetime
                    expires = parsedate_to_datetime(expires_str)
                except Exception:
                    pass

            # Parse max-age
            max_age = None
            max_age_str = morsel.get("max-age")
            if max_age_str:
                try:
                    max_age = int(max_age_str)
                    if max_age > 0 and not expires:
                        expires = datetime.now(timezone.utc) + timedelta(seconds=max_age)
                except ValueError:
                    pass

            # Parse flags
            secure = morsel.get("secure", False) is not False
            http_only = morsel.get("httponly", False) is not False
            same_site = morsel.get("samesite", "")

            # Ensure domain starts with . for domain cookies (unless it's an exact match)
            if domain and not domain.startswith(".") and domain != default_domain:
                domain = "." + domain

            return Cookie(
                name=name,
                value=value,
                domain=domain,
                path=path,
                expires=expires,
                max_age=max_age,
                secure=secure,
                http_only=http_only,
                same_site=same_site,
            )

        except Exception:
            # If parsing fails, return None
            return None

    def get_session(self, domain: str) -> Optional[Session]:
        """
        Retrieve active session for a domain.

        Args:
            domain: Domain name

        Returns:
            Session object or None if no session exists
        """
        # Check in-memory first
        session_id = self._domain_to_session.get(domain)
        if session_id and session_id in self._sessions:
            session = self._sessions[session_id]
            if not session.is_expired():
                return session
            else:
                # Clean up expired session
                del self._sessions[session_id]
                del self._domain_to_session[domain]
                self._delete_from_redis(session_id, domain)
        
        # Check Redis if enabled
        if self.use_redis:
            try:
                domain_key = self._redis_domain_key(domain)
                session_id = self.redis.get(domain_key, serialize="json")
                
                if session_id:
                    session = self._load_from_redis(session_id)
                    if session and not session.is_expired():
                        # Cache in memory
                        self._sessions[session_id] = session
                        self._domain_to_session[domain] = session_id
                        return session
            except Exception as e:
                print(f"Failed to get session from Redis: {e}")
        
        return None

    def apply_session(self, request, session: Session) -> Dict[str, str]:
        """
        Apply session cookies to a request.

        Args:
            request: Request object to modify
            session: Session containing cookies to apply

        Returns:
            Dictionary of cookies to be used with the request
        """
        # Get cookies that match the request URL
        cookies = session.get_cookies_for_request(request.url)
        
        # Merge with existing cookies (session cookies take precedence)
        merged_cookies = {**request.cookies, **cookies}
        request.cookies = merged_cookies
        
        return request

    def export_session(self, session_id: str, format: str = "json") -> bytes:
        """
        Export session to a serialized format.

        Args:
            session_id: ID of session to export
            format: Export format (currently only 'json' supported)

        Returns:
            Serialized session data

        Raises:
            ValueError: If session not found or format not supported
        """
        if session_id not in self._sessions:
            raise ValueError(f"Session {session_id} not found")

        if format != "json":
            raise ValueError(f"Unsupported format: {format}")

        session = self._sessions[session_id]
        
        # Convert session to dictionary
        session_dict = {
            "session_id": session.session_id,
            "domain": session.domain,
            "cookies": {},
            "headers": session.headers,
            "created_at": session.created_at.isoformat(),
            "expires_at": session.expires_at.isoformat() if session.expires_at else None,
        }

        # Convert cookies to dictionaries
        for name, cookie in session.cookies.items():
            session_dict["cookies"][name] = {
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain,
                "path": cookie.path,
                "expires": cookie.expires.isoformat() if cookie.expires else None,
                "max_age": cookie.max_age,
                "secure": cookie.secure,
                "http_only": cookie.http_only,
                "same_site": cookie.same_site,
            }

        # Serialize to JSON
        json_data = json.dumps(session_dict, indent=2)
        return json_data.encode("utf-8")

    def import_session(self, data: bytes, format: str = "json") -> Session:
        """
        Import session from serialized data.

        Args:
            data: Serialized session data
            format: Import format (currently only 'json' supported)

        Returns:
            Restored Session object

        Raises:
            ValueError: If format not supported or data invalid
        """
        if format != "json":
            raise ValueError(f"Unsupported format: {format}")

        try:
            # Parse JSON
            json_data = data.decode("utf-8")
            session_dict = json.loads(json_data)

            # Restore session
            session_id = session_dict["session_id"]
            domain = session_dict["domain"]
            
            # Parse timestamps
            created_at = datetime.fromisoformat(session_dict["created_at"])
            expires_at = None
            if session_dict.get("expires_at"):
                expires_at = datetime.fromisoformat(session_dict["expires_at"])

            # Create session
            session = Session(
                session_id=session_id,
                domain=domain,
                headers=session_dict.get("headers", {}),
                created_at=created_at,
                expires_at=expires_at,
            )

            # Restore cookies
            for name, cookie_dict in session_dict.get("cookies", {}).items():
                expires = None
                if cookie_dict.get("expires"):
                    expires = datetime.fromisoformat(cookie_dict["expires"])

                cookie = Cookie(
                    name=cookie_dict["name"],
                    value=cookie_dict["value"],
                    domain=cookie_dict["domain"],
                    path=cookie_dict.get("path", "/"),
                    expires=expires,
                    max_age=cookie_dict.get("max_age"),
                    secure=cookie_dict.get("secure", False),
                    http_only=cookie_dict.get("http_only", False),
                    same_site=cookie_dict.get("same_site"),
                )
                session.cookies[name] = cookie

            # Store session
            self._sessions[session_id] = session
            self._domain_to_session[domain] = session_id

            return session

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise ValueError(f"Invalid session data: {e}")

    def get_all_sessions(self) -> List[Session]:
        """
        Get all active sessions.

        Returns:
            List of Session objects
        """
        return list(self._sessions.values())

    def clear_session(self, session_id: str):
        """
        Clear a specific session.

        Args:
            session_id: ID of session to clear
        """
        if session_id in self._sessions:
            session = self._sessions[session_id]
            domain = session.domain
            del self._sessions[session_id]
            if self._domain_to_session.get(domain) == session_id:
                del self._domain_to_session[domain]
            # Delete from Redis
            self._delete_from_redis(session_id, domain)

    def clear_all_sessions(self):
        """Clear all sessions"""
        self._sessions.clear()
        self._domain_to_session.clear()
