"""
Per-User Rate Limiter
Security Enhancement - Rate limiting per user ID in addition to IP
"""
import time
from typing import Dict, Optional
from collections import defaultdict
import threading


class PerUserRateLimiter:
    """
    Per-user rate limiter to prevent abuse by authenticated users
    
    Features:
    - Rate limiting by user ID
    - Separate limits for different actions
    - Automatic cleanup of old entries
    - Thread-safe operations
    """
    
    def __init__(self):
        """Initialize per-user rate limiter"""
        self.user_requests: Dict[str, Dict[str, list]] = defaultdict(lambda: defaultdict(list))
        self.lock = threading.Lock()
        
        # Rate limits per action type
        self.limits = {
            "api_call": {"max_requests": 1000, "window": 3600},  # 1000/hour
            "login": {"max_requests": 10, "window": 3600},  # 10/hour
            "password_change": {"max_requests": 3, "window": 3600},  # 3/hour
            "file_upload": {"max_requests": 50, "window": 3600},  # 50/hour
            "threat_analysis": {"max_requests": 500, "window": 3600},  # 500/hour
            "general": {"max_requests": 2000, "window": 3600}  # 2000/hour
        }
    
    def is_allowed(self, user_id: str, action_type: str = "general") -> bool:
        """
        Check if user is allowed to perform action
        
        Args:
            user_id: User identifier
            action_type: Type of action
        
        Returns:
            True if allowed, False if rate limited
        """
        if not user_id:
            return True  # Skip for unauthenticated requests
        
        limit_config = self.limits.get(action_type, self.limits["general"])
        now = time.time()
        
        with self.lock:
            # Get user's request history for this action
            requests = self.user_requests[user_id][action_type]
            
            # Clean old requests
            requests[:] = [req_time for req_time in requests 
                          if now - req_time < limit_config["window"]]
            
            # Check if limit exceeded
            if len(requests) >= limit_config["max_requests"]:
                return False
            
            # Add current request
            requests.append(now)
            return True
    
    def get_remaining(self, user_id: str, action_type: str = "general") -> int:
        """
        Get remaining requests for user
        
        Args:
            user_id: User identifier
            action_type: Type of action
        
        Returns:
            Number of remaining requests
        """
        if not user_id:
            return 999999
        
        limit_config = self.limits.get(action_type, self.limits["general"])
        now = time.time()
        
        with self.lock:
            requests = self.user_requests[user_id][action_type]
            
            # Clean old requests
            requests[:] = [req_time for req_time in requests 
                          if now - req_time < limit_config["window"]]
            
            return max(0, limit_config["max_requests"] - len(requests))
    
    def reset_user(self, user_id: str, action_type: Optional[str] = None):
        """
        Reset rate limit for user
        
        Args:
            user_id: User identifier
            action_type: Specific action or None for all
        """
        with self.lock:
            if action_type:
                if user_id in self.user_requests:
                    self.user_requests[user_id][action_type].clear()
            else:
                if user_id in self.user_requests:
                    del self.user_requests[user_id]
    
    def cleanup_old_entries(self):
        """Remove old entries to prevent memory bloat"""
        now = time.time()
        max_window = max(config["window"] for config in self.limits.values())
        
        with self.lock:
            users_to_remove = []
            
            for user_id, actions in self.user_requests.items():
                for action_type, requests in list(actions.items()):
                    # Clean old requests
                    requests[:] = [req_time for req_time in requests 
                                  if now - req_time < max_window]
                    
                    # Remove empty action types
                    if not requests:
                        del actions[action_type]
                
                # Mark user for removal if no actions left
                if not actions:
                    users_to_remove.append(user_id)
            
            # Remove users with no actions
            for user_id in users_to_remove:
                del self.user_requests[user_id]
    
    def get_stats(self) -> Dict:
        """Get rate limiter statistics"""
        with self.lock:
            total_users = len(self.user_requests)
            total_requests = sum(
                len(requests)
                for actions in self.user_requests.values()
                for requests in actions.values()
            )
            
            return {
                "total_users": total_users,
                "total_tracked_requests": total_requests,
                "limits": self.limits
            }


# Global instance
per_user_rate_limiter = PerUserRateLimiter()
