"""Caching utilities and decorators"""

import functools
import hashlib
import json
import asyncio
from typing import Callable, Optional, Any
from datetime import timedelta

from src.vulnchain.core.redis_client import get_redis


def cache_key(*args, **kwargs) -> str:
    """
    Generate a cache key from function arguments.
    
    Args:
        args: Positional arguments
        kwargs: Keyword arguments
        
    Returns:
        Cache key string
    """
    # Create a string representation of arguments
    key_data = {
        "args": [str(arg) for arg in args],
        "kwargs": {k: str(v) for k, v in sorted(kwargs.items())}
    }
    key_str = json.dumps(key_data, sort_keys=True)
    
    # Hash the key to keep it short
    return hashlib.md5(key_str.encode()).hexdigest()


def cached(
    ttl: Optional[int] = None,
    key_prefix: str = "",
    serialize: str = "json"
):
    """
    Decorator to cache function results in Redis.
    
    Args:
        ttl: Time to live in seconds (None for no expiration)
        key_prefix: Prefix for cache keys
        serialize: Serialization method ("json" or "pickle")
        
    Returns:
        Decorated function
        
    Example:
        @cached(ttl=3600, key_prefix="user")
        def get_user(user_id: str):
            return db.query(User).get(user_id)
    """
    def decorator(func: Callable) -> Callable:
        if asyncio.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                redis = get_redis()
                if not redis.ping():
                    return await func(*args, **kwargs)
                
                func_name = f"{func.__module__}.{func.__name__}"
                arg_key = cache_key(*args, **kwargs)
                full_key = f"{key_prefix}:{func_name}:{arg_key}" if key_prefix else f"{func_name}:{arg_key}"
                
                cached_value = redis.get(full_key, serialize=serialize)
                if cached_value is not None:
                    return cached_value
                
                result = await func(*args, **kwargs)
                redis.set(full_key, result, ttl=ttl, serialize=serialize)
                return result
            
            async_wrapper.invalidate = lambda *a, **k: _invalidate_key(func, key_prefix, *a, **k)
            return async_wrapper
        else:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                redis = get_redis()
                if not redis.ping():
                    return func(*args, **kwargs)
                
                func_name = f"{func.__module__}.{func.__name__}"
                arg_key = cache_key(*args, **kwargs)
                full_key = f"{key_prefix}:{func_name}:{arg_key}" if key_prefix else f"{func_name}:{arg_key}"
                
                cached_value = redis.get(full_key, serialize=serialize)
                if cached_value is not None:
                    return cached_value
                
                result = func(*args, **kwargs)
                redis.set(full_key, result, ttl=ttl, serialize=serialize)
                return result
            
            wrapper.invalidate = lambda *a, **k: _invalidate_key(func, key_prefix, *a, **k)
            return wrapper

    return decorator

def _invalidate_key(func, key_prefix, *args, **kwargs):
    from src.vulnchain.core.redis_client import get_redis
    redis = get_redis()
    func_name = f"{func.__module__}.{func.__name__}"
    arg_key = cache_key(*args, **kwargs)
    full_key = f"{key_prefix}:{func_name}:{arg_key}" if key_prefix else f"{func_name}:{arg_key}"
    redis.delete(full_key)


def invalidate_pattern(pattern: str):
    """
    Invalidate all cache keys matching a pattern.
    
    Args:
        pattern: Key pattern (supports wildcards)
        
    Example:
        invalidate_pattern("user:*")
    """
    redis = get_redis()
    keys = redis.keys(pattern)
    for key in keys:
        redis.delete(key)


class CacheManager:
    """
    Cache manager for manual cache operations.
    
    Provides methods for setting, getting, and invalidating cache entries.
    """
    
    def __init__(self, prefix: str = ""):
        """
        Initialize cache manager.
        
        Args:
            prefix: Prefix for all cache keys
        """
        self.prefix = prefix
        self.redis = get_redis()
    
    def _make_key(self, key: str) -> str:
        """Make full cache key with prefix"""
        return f"{self.prefix}:{key}" if self.prefix else key
    
    def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        serialize: str = "json"
    ) -> bool:
        """
        Set a cache value.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds
            serialize: Serialization method
            
        Returns:
            True if successful
        """
        full_key = self._make_key(key)
        return self.redis.set(full_key, value, ttl=ttl, serialize=serialize)
    
    def get(
        self,
        key: str,
        default: Any = None,
        serialize: str = "json"
    ) -> Any:
        """
        Get a cache value.
        
        Args:
            key: Cache key
            default: Default value if not found
            serialize: Serialization method
            
        Returns:
            Cached value or default
        """
        full_key = self._make_key(key)
        return self.redis.get(full_key, default=default, serialize=serialize)
    
    def delete(self, key: str) -> bool:
        """
        Delete a cache entry.
        
        Args:
            key: Cache key
            
        Returns:
            True if deleted
        """
        full_key = self._make_key(key)
        return self.redis.delete(full_key)
    
    def exists(self, key: str) -> bool:
        """
        Check if a cache entry exists.
        
        Args:
            key: Cache key
            
        Returns:
            True if exists
        """
        full_key = self._make_key(key)
        return self.redis.exists(full_key)
    
    def invalidate_all(self):
        """Invalidate all cache entries with this prefix"""
        pattern = f"{self.prefix}:*" if self.prefix else "*"
        invalidate_pattern(pattern)


# Pre-configured cache managers for different purposes
session_cache = CacheManager(prefix="session")
recon_cache = CacheManager(prefix="recon")
dns_cache = CacheManager(prefix="dns")
fingerprint_cache = CacheManager(prefix="fingerprint")
