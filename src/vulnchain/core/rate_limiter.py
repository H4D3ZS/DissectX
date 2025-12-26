"""Rate limiting middleware and utilities"""

from fastapi import Request, HTTPException
from typing import Dict, Optional
from datetime import datetime, timedelta
import time
from collections import defaultdict


class RateLimiter:
    """
    Simple in-memory rate limiter.
    
    In production, this should use Redis for distributed rate limiting.
    """
    
    def __init__(self):
        # Store request counts: {client_id: {endpoint: [(timestamp, count)]}}
        self.requests: Dict[str, Dict[str, list]] = defaultdict(lambda: defaultdict(list))
        self.cleanup_interval = 60  # Cleanup old entries every 60 seconds
        self.last_cleanup = time.time()
    
    def _cleanup_old_entries(self):
        """Remove old entries to prevent memory growth"""
        current_time = time.time()
        
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        cutoff_time = current_time - 3600  # Keep last hour
        
        for client_id in list(self.requests.keys()):
            for endpoint in list(self.requests[client_id].keys()):
                self.requests[client_id][endpoint] = [
                    (ts, count) for ts, count in self.requests[client_id][endpoint]
                    if ts > cutoff_time
                ]
                
                if not self.requests[client_id][endpoint]:
                    del self.requests[client_id][endpoint]
            
            if not self.requests[client_id]:
                del self.requests[client_id]
        
        self.last_cleanup = current_time
    
    def _get_client_id(self, request: Request) -> str:
        """
        Get a unique identifier for the client.
        
        Args:
            request: FastAPI request
            
        Returns:
            Client identifier
        """
        # Try to get user ID from auth
        if hasattr(request.state, "user"):
            return f"user:{request.state.user.user_id}"
        
        # Fall back to IP address
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return f"ip:{forwarded.split(',')[0].strip()}"
        
        client_host = request.client.host if request.client else "unknown"
        return f"ip:{client_host}"
    
    def check_rate_limit(
        self,
        request: Request,
        max_requests: int,
        window_seconds: int,
        endpoint: Optional[str] = None
    ) -> bool:
        """
        Check if the request is within rate limits.
        
        Args:
            request: FastAPI request
            max_requests: Maximum number of requests allowed
            window_seconds: Time window in seconds
            endpoint: Optional endpoint identifier (defaults to request path)
            
        Returns:
            True if within limits, False otherwise
        """
        self._cleanup_old_entries()
        
        client_id = self._get_client_id(request)
        endpoint = endpoint or request.url.path
        current_time = time.time()
        cutoff_time = current_time - window_seconds
        
        # Get requests in the current window
        requests_in_window = [
            (ts, count) for ts, count in self.requests[client_id][endpoint]
            if ts > cutoff_time
        ]
        
        # Count total requests
        total_requests = sum(count for _, count in requests_in_window)
        
        if total_requests >= max_requests:
            return False
        
        # Add current request
        self.requests[client_id][endpoint].append((current_time, 1))
        
        return True
    
    def get_remaining_requests(
        self,
        request: Request,
        max_requests: int,
        window_seconds: int,
        endpoint: Optional[str] = None
    ) -> int:
        """
        Get the number of remaining requests in the current window.
        
        Args:
            request: FastAPI request
            max_requests: Maximum number of requests allowed
            window_seconds: Time window in seconds
            endpoint: Optional endpoint identifier
            
        Returns:
            Number of remaining requests
        """
        client_id = self._get_client_id(request)
        endpoint = endpoint or request.url.path
        current_time = time.time()
        cutoff_time = current_time - window_seconds
        
        # Get requests in the current window
        requests_in_window = [
            (ts, count) for ts, count in self.requests[client_id][endpoint]
            if ts > cutoff_time
        ]
        
        # Count total requests
        total_requests = sum(count for _, count in requests_in_window)
        
        return max(0, max_requests - total_requests)


# Global rate limiter instance
rate_limiter = RateLimiter()


# Rate limit configurations for different endpoint types
RATE_LIMITS = {
    "default": {"max_requests": 100, "window_seconds": 60},  # 100 req/min
    "auth": {"max_requests": 5, "window_seconds": 60},  # 5 req/min for auth
    "module_execution": {"max_requests": 10, "window_seconds": 60},  # 10 req/min
    "fuzzing": {"max_requests": 50, "window_seconds": 60},  # 50 req/min
    "export": {"max_requests": 5, "window_seconds": 300},  # 5 req/5min
}


def rate_limit(
    max_requests: Optional[int] = None,
    window_seconds: Optional[int] = None,
    limit_type: str = "default"
):
    """
    Decorator for rate limiting endpoints.
    
    Args:
        max_requests: Maximum requests allowed (overrides limit_type)
        window_seconds: Time window in seconds (overrides limit_type)
        limit_type: Type of rate limit to apply
        
    Returns:
        Decorator function
    """
    def decorator(func):
        async def wrapper(request: Request, *args, **kwargs):
            # Get rate limit config
            config = RATE_LIMITS.get(limit_type, RATE_LIMITS["default"])
            max_req = max_requests or config["max_requests"]
            window_sec = window_seconds or config["window_seconds"]
            
            # Check rate limit
            if not rate_limiter.check_rate_limit(request, max_req, window_sec):
                remaining = rate_limiter.get_remaining_requests(request, max_req, window_sec)
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded. Try again later.",
                    headers={
                        "X-RateLimit-Limit": str(max_req),
                        "X-RateLimit-Remaining": str(remaining),
                        "X-RateLimit-Reset": str(int(time.time() + window_sec))
                    }
                )
            
            # Add rate limit headers to response
            remaining = rate_limiter.get_remaining_requests(request, max_req, window_sec)
            
            # Call the actual endpoint
            response = await func(request, *args, **kwargs)
            
            # Add headers if response supports it
            if hasattr(response, "headers"):
                response.headers["X-RateLimit-Limit"] = str(max_req)
                response.headers["X-RateLimit-Remaining"] = str(remaining)
                response.headers["X-RateLimit-Reset"] = str(int(time.time() + window_sec))
            
            return response
        
        return wrapper
    return decorator


async def rate_limit_middleware(request: Request, call_next):
    """
    Middleware to apply rate limiting to all requests.
    
    Args:
        request: FastAPI request
        call_next: Next middleware/endpoint
        
    Returns:
        Response
    """
    # Determine rate limit type based on path
    path = request.url.path
    
    if path.startswith("/api/auth"):
        limit_type = "auth"
    elif path.startswith("/api/modules/execute"):
        limit_type = "module_execution"
    elif "export" in path:
        limit_type = "export"
    else:
        limit_type = "default"
    
    # Get rate limit config
    config = RATE_LIMITS.get(limit_type, RATE_LIMITS["default"])
    max_requests = config["max_requests"]
    window_seconds = config["window_seconds"]
    
    # Check rate limit
    if not rate_limiter.check_rate_limit(request, max_requests, window_seconds):
        remaining = rate_limiter.get_remaining_requests(request, max_requests, window_seconds)
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Try again later.",
            headers={
                "X-RateLimit-Limit": str(max_requests),
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": str(int(time.time() + window_seconds))
            }
        )
    
    # Process request
    response = await call_next(request)
    
    # Add rate limit headers
    remaining = rate_limiter.get_remaining_requests(request, max_requests, window_seconds)
    response.headers["X-RateLimit-Limit"] = str(max_requests)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    response.headers["X-RateLimit-Reset"] = str(int(time.time() + window_seconds))
    
    return response
