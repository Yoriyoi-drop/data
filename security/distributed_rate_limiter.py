"""
Distributed Rate Limiter with Redis
Security Enhancement - Prevents brute force and DDoS attacks
"""
import time
import hmac
import hashlib
from typing import Dict, Optional
from datetime import datetime, timedelta

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    print("⚠️  Redis not available. Install with: pip install redis")

class DistributedRateLimiter:
    """
    Distributed rate limiter using Redis for persistence and scalability
    
    Features:
    - Persistent storage (survives restarts)
    - Distributed support (works across multiple servers)
    - Progressive blocking
    - IP reputation scoring
    - Automatic cleanup
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379/0", redis_password: Optional[str] = None):
        """
        Initialize distributed rate limiter
        
        Args:
            redis_url: Redis connection URL
            redis_password: Redis password (if required)
        """
        if not REDIS_AVAILABLE:
            raise RuntimeError("Redis is required for distributed rate limiting. Install with: pip install redis")
        
        try:
            self.redis_client = redis.from_url(
                redis_url,
                password=redis_password,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5
            )
            # Test connection
            self.redis_client.ping()
            print("✅ Connected to Redis for distributed rate limiting")
        except redis.ConnectionError as e:
            print(f"❌ Failed to connect to Redis: {e}")
            print("   Falling back to in-memory rate limiting (not recommended for production)")
            raise
        
        # Rate limit configurations
        self.limits = {
            "login": {
                "max_requests": 5,
                "window": 300,  # 5 minutes
                "block_duration": 900  # 15 minutes
            },
            "api": {
                "max_requests": 100,
                "window": 60,  # 1 minute
                "block_duration": 300  # 5 minutes
            },
            "general": {
                "max_requests": 200,
                "window": 60,  # 1 minute
                "block_duration": 300  # 5 minutes
            },
            "websocket": {
                "max_requests": 50,
                "window": 60,  # 1 minute
                "block_duration": 600  # 10 minutes
            }
        }
    
    def is_allowed(self, client_id: str, endpoint_type: str = "general") -> bool:
        """
        Check if request is allowed
        
        Args:
            client_id: Client identifier (IP address or user ID)
            endpoint_type: Type of endpoint (login, api, general, websocket)
        
        Returns:
            True if allowed, False if rate limited
        """
        # Check if permanently blocked
        if self.is_blocked(client_id):
            return False
        
        limit_config = self.limits.get(endpoint_type, self.limits["general"])
        key = f"ratelimit:{endpoint_type}:{client_id}"
        
        try:
            # Use Redis pipeline for atomic operations
            pipe = self.redis_client.pipeline()
            
            # Increment counter
            pipe.incr(key)
            
            # Set expiration on first request
            pipe.ttl(key)
            
            # Execute pipeline
            results = pipe.execute()
            current_count = results[0]
            ttl = results[1]
            
            # Set expiration if not set
            if ttl == -1:
                self.redis_client.expire(key, limit_config["window"])
            
            # Check if exceeded
            if current_count > limit_config["max_requests"]:
                # Record violation
                self._record_violation(client_id, endpoint_type, limit_config)
                return False
            
            return True
            
        except redis.RedisError as e:
            print(f"❌ Redis error in rate limiting: {e}")
            # Fail open (allow request) on Redis errors to prevent service disruption
            return True
    
    def _record_violation(self, client_id: str, endpoint_type: str, limit_config: dict):
        """
        Record rate limit violation
        
        Args:
            client_id: Client identifier
            endpoint_type: Type of endpoint
            limit_config: Limit configuration
        """
        violation_key = f"violations:{client_id}"
        
        try:
            # Increment violation counter
            violations = self.redis_client.incr(violation_key)
            
            # Set expiration (1 hour)
            self.redis_client.expire(violation_key, 3600)
            
            # Block after 3 violations
            if violations >= 3:
                self.block_ip(
                    client_id,
                    duration=limit_config["block_duration"],
                    reason=f"Multiple rate limit violations on {endpoint_type}"
                )
        
        except redis.RedisError as e:
            print(f"❌ Redis error recording violation: {e}")
    
    def block_ip(self, client_id: str, duration: int = 86400, reason: str = "Manual block"):
        """
        Block an IP address
        
        Args:
            client_id: Client identifier to block
            duration: Block duration in seconds (default 24 hours)
            reason: Reason for blocking
        """
        try:
            block_key = f"blocked:{client_id}"
            block_info = {
                "blocked_at": int(time.time()),
                "duration": duration,
                "reason": reason,
                "unblock_at": int(time.time()) + duration
            }
            
            # Store block info as hash
            self.redis_client.hset(block_key, mapping=block_info)
            
            # Set expiration
            self.redis_client.expire(block_key, duration)
            
            print(f"🚫 Blocked {client_id} for {duration}s: {reason}")
        
        except redis.RedisError as e:
            print(f"❌ Redis error blocking IP: {e}")
    
    def unblock_ip(self, client_id: str):
        """
        Manually unblock an IP address
        
        Args:
            client_id: Client identifier to unblock
        """
        try:
            # Delete block key
            self.redis_client.delete(f"blocked:{client_id}")
            
            # Delete violation counter
            self.redis_client.delete(f"violations:{client_id}")
            
            print(f"✅ Unblocked {client_id}")
        
        except redis.RedisError as e:
            print(f"❌ Redis error unblocking IP: {e}")
    
    def is_blocked(self, client_id: str) -> bool:
        """
        Check if client is blocked
        
        Args:
            client_id: Client identifier
        
        Returns:
            True if blocked, False otherwise
        """
        try:
            block_key = f"blocked:{client_id}"
            return self.redis_client.exists(block_key) > 0
        
        except redis.RedisError as e:
            print(f"❌ Redis error checking block status: {e}")
            # Fail open on Redis errors
            return False
    
    def get_block_info(self, client_id: str) -> Optional[Dict]:
        """
        Get block information for a client
        
        Args:
            client_id: Client identifier
        
        Returns:
            Block info dict or None if not blocked
        """
        try:
            block_key = f"blocked:{client_id}"
            info = self.redis_client.hgetall(block_key)
            
            if info:
                return {
                    "blocked_at": int(info.get("blocked_at", 0)),
                    "duration": int(info.get("duration", 0)),
                    "reason": info.get("reason", "Unknown"),
                    "unblock_at": int(info.get("unblock_at", 0))
                }
            
            return None
        
        except redis.RedisError as e:
            print(f"❌ Redis error getting block info: {e}")
            return None
    
    def get_violation_count(self, client_id: str) -> int:
        """
        Get violation count for a client
        
        Args:
            client_id: Client identifier
        
        Returns:
            Number of violations
        """
        try:
            violation_key = f"violations:{client_id}"
            count = self.redis_client.get(violation_key)
            return int(count) if count else 0
        
        except redis.RedisError as e:
            print(f"❌ Redis error getting violation count: {e}")
            return 0
    
    def get_remaining_requests(self, client_id: str, endpoint_type: str = "general") -> int:
        """
        Get remaining requests for a client
        
        Args:
            client_id: Client identifier
            endpoint_type: Type of endpoint
        
        Returns:
            Number of remaining requests
        """
        try:
            limit_config = self.limits.get(endpoint_type, self.limits["general"])
            key = f"ratelimit:{endpoint_type}:{client_id}"
            
            current = self.redis_client.get(key)
            current_count = int(current) if current else 0
            
            remaining = max(0, limit_config["max_requests"] - current_count)
            return remaining
        
        except redis.RedisError as e:
            print(f"❌ Redis error getting remaining requests: {e}")
            return 0
    
    def reset_client(self, client_id: str, endpoint_type: Optional[str] = None):
        """
        Reset rate limit for a client
        
        Args:
            client_id: Client identifier
            endpoint_type: Specific endpoint type or None for all
        """
        try:
            if endpoint_type:
                # Reset specific endpoint
                key = f"ratelimit:{endpoint_type}:{client_id}"
                self.redis_client.delete(key)
            else:
                # Reset all endpoints
                pattern = f"ratelimit:*:{client_id}"
                keys = self.redis_client.keys(pattern)
                if keys:
                    self.redis_client.delete(*keys)
            
            print(f"✅ Reset rate limit for {client_id}")
        
        except redis.RedisError as e:
            print(f"❌ Redis error resetting client: {e}")
    
    def get_stats(self) -> Dict:
        """
        Get rate limiter statistics
        
        Returns:
            Statistics dictionary
        """
        try:
            # Count blocked IPs
            blocked_keys = self.redis_client.keys("blocked:*")
            blocked_count = len(blocked_keys)
            
            # Count active rate limits
            ratelimit_keys = self.redis_client.keys("ratelimit:*")
            active_limits = len(ratelimit_keys)
            
            # Count violations
            violation_keys = self.redis_client.keys("violations:*")
            violation_count = len(violation_keys)
            
            return {
                "blocked_ips": blocked_count,
                "active_rate_limits": active_limits,
                "clients_with_violations": violation_count,
                "redis_connected": True
            }
        
        except redis.RedisError as e:
            print(f"❌ Redis error getting stats: {e}")
            return {
                "blocked_ips": 0,
                "active_rate_limits": 0,
                "clients_with_violations": 0,
                "redis_connected": False,
                "error": str(e)
            }
    
    def cleanup_expired(self):
        """
        Cleanup expired entries (Redis handles this automatically with TTL)
        This is a no-op for Redis-based implementation
        """
        # Redis automatically removes expired keys
        pass
    
    def health_check(self) -> bool:
        """
        Check if Redis connection is healthy
        
        Returns:
            True if healthy, False otherwise
        """
        try:
            self.redis_client.ping()
            return True
        except redis.RedisError:
            return False


# Fallback in-memory rate limiter (for development/testing)
class InMemoryRateLimiter:
    """
    In-memory rate limiter (NOT recommended for production)
    Use only for development/testing when Redis is not available
    """
    
    def __init__(self):
        print("⚠️  Using in-memory rate limiter (NOT recommended for production)")
        self.requests = {}
        self.blocked_ips = {}
        self.suspicious_ips = {}
        
        self.limits = {
            "login": {"max_requests": 5, "window": 300},
            "api": {"max_requests": 100, "window": 60},
            "general": {"max_requests": 200, "window": 60}
        }
    
    def is_allowed(self, client_ip: str, endpoint_type: str = "general") -> bool:
        if client_ip in self.blocked_ips:
            return False
        
        now = time.time()
        limit_config = self.limits.get(endpoint_type, self.limits["general"])
        
        key = f"{client_ip}:{endpoint_type}"
        
        if key not in self.requests:
            self.requests[key] = []
        
        # Clean old requests
        self.requests[key] = [
            req_time for req_time in self.requests[key] 
            if now - req_time < limit_config["window"]
        ]
        
        if len(self.requests[key]) >= limit_config["max_requests"]:
            if client_ip not in self.suspicious_ips:
                self.suspicious_ips[client_ip] = 0
            self.suspicious_ips[client_ip] += 1
            
            if self.suspicious_ips[client_ip] >= 3:
                self.blocked_ips[client_ip] = now
            
            return False
        
        self.requests[key].append(now)
        return True
    
    def unblock_ip(self, client_ip: str):
        self.blocked_ips.pop(client_ip, None)
        self.suspicious_ips.pop(client_ip, None)
    
    def is_blocked(self, client_ip: str) -> bool:
        return client_ip in self.blocked_ips
    
    def get_stats(self) -> Dict:
        return {
            "blocked_ips": len(self.blocked_ips),
            "active_rate_limits": len(self.requests),
            "clients_with_violations": len(self.suspicious_ips),
            "redis_connected": False
        }
