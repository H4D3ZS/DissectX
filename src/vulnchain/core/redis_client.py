"""Redis client for caching and session storage"""

import json
import pickle
from typing import Optional, Any, Union
import redis
from datetime import timedelta

from src.vulnchain.core.config import settings


class RedisClient:
    """
    Redis client wrapper for caching and session storage.
    
    Provides methods for storing and retrieving data from Redis
    with automatic serialization/deserialization.
    """
    
    def __init__(self, url: Optional[str] = None):
        """
        Initialize Redis client.
        
        Args:
            url: Redis connection URL (defaults to settings.REDIS_URL)
        """
        self.url = url or settings.REDIS_URL
        self.client = redis.from_url(
            self.url,
            decode_responses=False,  # We'll handle encoding ourselves
            socket_connect_timeout=5,
            socket_timeout=5,
        )
    
    def ping(self) -> bool:
        """
        Check if Redis is available.
        
        Returns:
            True if Redis is available, False otherwise
        """
        try:
            return self.client.ping()
        except Exception:
            return False
    
    def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        serialize: str = "json"
    ) -> bool:
        """
        Set a value in Redis.
        
        Args:
            key: Cache key
            value: Value to store
            ttl: Time to live in seconds (None for no expiration)
            serialize: Serialization method ("json" or "pickle")
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Serialize value
            if serialize == "json":
                serialized = json.dumps(value).encode()
            elif serialize == "pickle":
                serialized = pickle.dumps(value)
            else:
                raise ValueError(f"Unknown serialization method: {serialize}")
            
            # Set value with optional TTL
            if ttl:
                return self.client.setex(key, ttl, serialized)
            else:
                return self.client.set(key, serialized)
        except Exception as e:
            print(f"Redis set error: {e}")
            return False
    
    def get(
        self,
        key: str,
        default: Any = None,
        serialize: str = "json"
    ) -> Any:
        """
        Get a value from Redis.
        
        Args:
            key: Cache key
            default: Default value if key not found
            serialize: Serialization method ("json" or "pickle")
            
        Returns:
            Stored value or default
        """
        try:
            value = self.client.get(key)
            if value is None:
                return default
            
            # Deserialize value
            if serialize == "json":
                return json.loads(value.decode())
            elif serialize == "pickle":
                return pickle.loads(value)
            else:
                raise ValueError(f"Unknown serialization method: {serialize}")
        except Exception as e:
            print(f"Redis get error: {e}")
            return default
    
    def delete(self, key: str) -> bool:
        """
        Delete a key from Redis.
        
        Args:
            key: Cache key
            
        Returns:
            True if deleted, False otherwise
        """
        try:
            return bool(self.client.delete(key))
        except Exception as e:
            print(f"Redis delete error: {e}")
            return False
    
    def exists(self, key: str) -> bool:
        """
        Check if a key exists in Redis.
        
        Args:
            key: Cache key
            
        Returns:
            True if exists, False otherwise
        """
        try:
            return bool(self.client.exists(key))
        except Exception as e:
            print(f"Redis exists error: {e}")
            return False
    
    def expire(self, key: str, ttl: int) -> bool:
        """
        Set expiration time for a key.
        
        Args:
            key: Cache key
            ttl: Time to live in seconds
            
        Returns:
            True if successful, False otherwise
        """
        try:
            return bool(self.client.expire(key, ttl))
        except Exception as e:
            print(f"Redis expire error: {e}")
            return False
    
    def ttl(self, key: str) -> int:
        """
        Get remaining time to live for a key.
        
        Args:
            key: Cache key
            
        Returns:
            TTL in seconds (-1 if no expiration, -2 if key doesn't exist)
        """
        try:
            return self.client.ttl(key)
        except Exception as e:
            print(f"Redis ttl error: {e}")
            return -2
    
    def keys(self, pattern: str = "*") -> list:
        """
        Get all keys matching a pattern.
        
        Args:
            pattern: Key pattern (supports wildcards)
            
        Returns:
            List of matching keys
        """
        try:
            return [key.decode() for key in self.client.keys(pattern)]
        except Exception as e:
            print(f"Redis keys error: {e}")
            return []
    
    def flush_db(self) -> bool:
        """
        Clear all keys in the current database.
        
        WARNING: This will delete all data!
        
        Returns:
            True if successful, False otherwise
        """
        try:
            return self.client.flushdb()
        except Exception as e:
            print(f"Redis flushdb error: {e}")
            return False
    
    def incr(self, key: str, amount: int = 1) -> Optional[int]:
        """
        Increment a counter.
        
        Args:
            key: Cache key
            amount: Amount to increment by
            
        Returns:
            New value or None on error
        """
        try:
            return self.client.incrby(key, amount)
        except Exception as e:
            print(f"Redis incr error: {e}")
            return None
    
    def decr(self, key: str, amount: int = 1) -> Optional[int]:
        """
        Decrement a counter.
        
        Args:
            key: Cache key
            amount: Amount to decrement by
            
        Returns:
            New value or None on error
        """
        try:
            return self.client.decrby(key, amount)
        except Exception as e:
            print(f"Redis decr error: {e}")
            return None
    
    def hset(self, name: str, key: str, value: Any, serialize: str = "json") -> bool:
        """
        Set a field in a hash.
        
        Args:
            name: Hash name
            key: Field key
            value: Field value
            serialize: Serialization method
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if serialize == "json":
                serialized = json.dumps(value).encode()
            elif serialize == "pickle":
                serialized = pickle.dumps(value)
            else:
                raise ValueError(f"Unknown serialization method: {serialize}")
            
            return bool(self.client.hset(name, key, serialized))
        except Exception as e:
            print(f"Redis hset error: {e}")
            return False
    
    def hget(
        self,
        name: str,
        key: str,
        default: Any = None,
        serialize: str = "json"
    ) -> Any:
        """
        Get a field from a hash.
        
        Args:
            name: Hash name
            key: Field key
            default: Default value if not found
            serialize: Serialization method
            
        Returns:
            Field value or default
        """
        try:
            value = self.client.hget(name, key)
            if value is None:
                return default
            
            if serialize == "json":
                return json.loads(value.decode())
            elif serialize == "pickle":
                return pickle.loads(value)
            else:
                raise ValueError(f"Unknown serialization method: {serialize}")
        except Exception as e:
            print(f"Redis hget error: {e}")
            return default
    
    def hgetall(self, name: str, serialize: str = "json") -> dict:
        """
        Get all fields from a hash.
        
        Args:
            name: Hash name
            serialize: Serialization method
            
        Returns:
            Dictionary of all fields
        """
        try:
            data = self.client.hgetall(name)
            result = {}
            
            for key, value in data.items():
                key_str = key.decode()
                if serialize == "json":
                    result[key_str] = json.loads(value.decode())
                elif serialize == "pickle":
                    result[key_str] = pickle.loads(value)
            
            return result
        except Exception as e:
            print(f"Redis hgetall error: {e}")
            return {}
    
    def hdel(self, name: str, *keys: str) -> int:
        """
        Delete fields from a hash.
        
        Args:
            name: Hash name
            keys: Field keys to delete
            
        Returns:
            Number of fields deleted
        """
        try:
            return self.client.hdel(name, *keys)
        except Exception as e:
            print(f"Redis hdel error: {e}")
            return 0


# Global Redis client instance
redis_client = RedisClient()


def get_redis() -> RedisClient:
    """
    Get Redis client instance.
    
    Returns:
        Redis client
    """
    return redis_client
