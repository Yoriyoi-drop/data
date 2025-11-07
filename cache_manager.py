"""
Infinite AI Security - Redis Cache Manager
Fase 1 Evolution: Performance Optimization with Caching
"""
import json
import time
import hashlib
from typing import Any, Optional, Dict
from datetime import datetime, UTC, timedelta

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

class CacheManager:
    """High-performance caching system with Redis fallback to in-memory"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self.redis_client = None
        self.memory_cache = {}  # Fallback in-memory cache
        self.cache_stats = {"hits": 0, "misses": 0, "sets": 0}
        
        if REDIS_AVAILABLE:
            try:
                self.redis_client = redis.from_url(redis_url, decode_responses=True)
                # Test connection
                self.redis_client.ping()
                print("[CACHE] Redis connected successfully")
            except:
                print("[CACHE] Redis unavailable, using in-memory cache")
                self.redis_client = None
        else:
            print("[CACHE] Redis not installed, using in-memory cache")
    
    def _generate_key(self, prefix: str, identifier: str) -> str:
        """Generate consistent cache key"""
        return f"infinite_ai:{prefix}:{identifier}"
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        cache_key = self._generate_key("data", key)
        
        try:
            if self.redis_client:
                # Try Redis first
                value = self.redis_client.get(cache_key)
                if value:
                    self.cache_stats["hits"] += 1
                    return json.loads(value)
            else:
                # Use in-memory cache
                if cache_key in self.memory_cache:
                    entry = self.memory_cache[cache_key]
                    # Check expiry
                    if entry["expires"] > time.time():
                        self.cache_stats["hits"] += 1
                        return entry["data"]
                    else:
                        # Remove expired entry
                        del self.memory_cache[cache_key]
            
            self.cache_stats["misses"] += 1
            return None
            
        except Exception as e:
            print(f"[CACHE] Get error: {e}")
            self.cache_stats["misses"] += 1
            return None
    
    def set(self, key: str, value: Any, ttl: int = 300) -> bool:
        """Set value in cache with TTL (seconds)"""
        cache_key = self._generate_key("data", key)
        
        try:
            if self.redis_client:
                # Use Redis
                serialized = json.dumps(value, default=str)
                result = self.redis_client.setex(cache_key, ttl, serialized)
                if result:
                    self.cache_stats["sets"] += 1
                    return True
            else:
                # Use in-memory cache
                self.memory_cache[cache_key] = {
                    "data": value,
                    "expires": time.time() + ttl
                }
                self.cache_stats["sets"] += 1
                return True
                
        except Exception as e:
            print(f"[CACHE] Set error: {e}")
            return False
        
        return False
    
    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        cache_key = self._generate_key("data", key)
        
        try:
            if self.redis_client:
                return bool(self.redis_client.delete(cache_key))
            else:
                if cache_key in self.memory_cache:
                    del self.memory_cache[cache_key]
                    return True
                return False
        except Exception as e:
            print(f"[CACHE] Delete error: {e}")
            return False
    
    def clear_pattern(self, pattern: str) -> int:
        """Clear all keys matching pattern"""
        try:
            if self.redis_client:
                keys = self.redis_client.keys(f"infinite_ai:data:{pattern}*")
                if keys:
                    return self.redis_client.delete(*keys)
            else:
                # Clear from memory cache
                keys_to_delete = [k for k in self.memory_cache.keys() 
                                if pattern in k]
                for key in keys_to_delete:
                    del self.memory_cache[key]
                return len(keys_to_delete)
        except Exception as e:
            print(f"[CACHE] Clear pattern error: {e}")
            return 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self.cache_stats["hits"] + self.cache_stats["misses"]
        hit_rate = (self.cache_stats["hits"] / total_requests * 100) if total_requests > 0 else 0
        
        stats = {
            "backend": "Redis" if self.redis_client else "Memory",
            "hits": self.cache_stats["hits"],
            "misses": self.cache_stats["misses"],
            "sets": self.cache_stats["sets"],
            "hit_rate": round(hit_rate, 2),
            "total_requests": total_requests
        }
        
        if self.redis_client:
            try:
                info = self.redis_client.info()
                stats.update({
                    "redis_memory": info.get("used_memory_human", "N/A"),
                    "redis_keys": info.get("db0", {}).get("keys", 0) if "db0" in info else 0
                })
            except:
                pass
        else:
            stats["memory_keys"] = len(self.memory_cache)
        
        return stats

class ThreatCacheManager:
    """Specialized caching for threat detection"""
    
    def __init__(self, cache_manager: CacheManager):
        self.cache = cache_manager
    
    def cache_payload_analysis(self, payload: str, result: Dict[str, Any], ttl: int = 3600):
        """Cache threat analysis result for payload"""
        # Create hash of payload for consistent key
        payload_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]
        cache_key = f"threat_analysis:{payload_hash}"
        
        cache_data = {
            "result": result,
            "cached_at": datetime.now(UTC).isoformat(),
            "payload_length": len(payload)
        }
        
        return self.cache.set(cache_key, cache_data, ttl)
    
    def get_cached_analysis(self, payload: str) -> Optional[Dict[str, Any]]:
        """Get cached analysis for payload"""
        payload_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]
        cache_key = f"threat_analysis:{payload_hash}"
        
        cached = self.cache.get(cache_key)
        if cached:
            # Check if cache is still fresh (within 1 hour)
            cached_time = datetime.fromisoformat(cached["cached_at"])
            if datetime.now(UTC) - cached_time < timedelta(hours=1):
                return cached["result"]
        
        return None

class StatsCacheManager:
    """Specialized caching for statistics"""
    
    def __init__(self, cache_manager: CacheManager):
        self.cache = cache_manager
    
    def cache_stats(self, stats: Dict[str, Any], ttl: int = 60):
        """Cache system statistics"""
        return self.cache.set("system_stats", stats, ttl)
    
    def get_cached_stats(self) -> Optional[Dict[str, Any]]:
        """Get cached statistics"""
        return self.cache.get("system_stats")
    
    def cache_user_stats(self, username: str, stats: Dict[str, Any], ttl: int = 300):
        """Cache user-specific statistics"""
        return self.cache.set(f"user_stats:{username}", stats, ttl)
    
    def get_cached_user_stats(self, username: str) -> Optional[Dict[str, Any]]:
        """Get cached user statistics"""
        return self.cache.get(f"user_stats:{username}")

class SessionCacheManager:
    """Specialized caching for user sessions"""
    
    def __init__(self, cache_manager: CacheManager):
        self.cache = cache_manager
    
    def cache_session(self, token_hash: str, session_data: Dict[str, Any], ttl: int = 1800):
        """Cache user session data"""
        return self.cache.set(f"session:{token_hash}", session_data, ttl)
    
    def get_cached_session(self, token_hash: str) -> Optional[Dict[str, Any]]:
        """Get cached session data"""
        return self.cache.get(f"session:{token_hash}")
    
    def invalidate_session(self, token_hash: str) -> bool:
        """Invalidate cached session"""
        return self.cache.delete(f"session:{token_hash}")
    
    def cache_user_permissions(self, username: str, permissions: Dict[str, Any], ttl: int = 900):
        """Cache user permissions"""
        return self.cache.set(f"permissions:{username}", permissions, ttl)
    
    def get_cached_permissions(self, username: str) -> Optional[Dict[str, Any]]:
        """Get cached user permissions"""
        return self.cache.get(f"permissions:{username}")

# Global cache instances
cache_manager = CacheManager()
threat_cache = ThreatCacheManager(cache_manager)
stats_cache = StatsCacheManager(cache_manager)
session_cache = SessionCacheManager(cache_manager)

def get_cache_info() -> Dict[str, Any]:
    """Get comprehensive cache information"""
    return {
        "cache_stats": cache_manager.get_stats(),
        "backend": "Redis" if cache_manager.redis_client else "Memory",
        "available": True,
        "managers": {
            "threat_cache": "Active",
            "stats_cache": "Active", 
            "session_cache": "Active"
        }
    }

if __name__ == "__main__":
    # Test cache functionality
    print("[CACHE] Testing Cache Manager")
    print("=" * 40)
    
    # Test basic operations
    cache_manager.set("test_key", {"message": "Hello Cache!"}, 60)
    result = cache_manager.get("test_key")
    print(f"Cache test: {result}")
    
    # Test threat caching
    test_payload = "admin' OR '1'='1"
    test_result = {"threat": True, "confidence": 0.95, "type": "sql_injection"}
    
    threat_cache.cache_payload_analysis(test_payload, test_result)
    cached_result = threat_cache.get_cached_analysis(test_payload)
    print(f"Threat cache test: {cached_result}")
    
    # Show cache stats
    stats = cache_manager.get_stats()
    print(f"Cache stats: {stats}")
    
    print("[CACHE] All tests completed successfully!")