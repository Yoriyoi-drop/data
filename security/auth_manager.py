"""
Enterprise Authentication & Authorization Manager
"""
import jwt
import time
import hashlib
from typing import Dict, Optional, List
from datetime import datetime, timedelta
from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import asyncio
from collections import defaultdict, deque

class RateLimiter:
    def __init__(self):
        self.requests = defaultdict(deque)
        self.limits = {
            'default': {'requests': 100, 'window': 3600},  # 100 req/hour
            'premium': {'requests': 1000, 'window': 3600}, # 1000 req/hour
            'enterprise': {'requests': 10000, 'window': 3600} # 10k req/hour
        }
    
    async def check_rate_limit(self, client_id: str, tier: str = 'default') -> bool:
        """Check if client is within rate limits"""
        now = time.time()
        limit_config = self.limits.get(tier, self.limits['default'])
        
        # Clean old requests
        client_requests = self.requests[client_id]
        while client_requests and client_requests[0] < now - limit_config['window']:
            client_requests.popleft()
        
        # Check limit
        if len(client_requests) >= limit_config['requests']:
            return False
        
        # Add current request
        client_requests.append(now)
        return True
    
    async def get_rate_limit_info(self, client_id: str, tier: str = 'default') -> Dict:
        """Get rate limit information for client"""
        now = time.time()
        limit_config = self.limits.get(tier, self.limits['default'])
        
        client_requests = self.requests[client_id]
        # Count requests in current window
        current_requests = sum(1 for req_time in client_requests 
                             if req_time > now - limit_config['window'])
        
        return {
            'requests_made': current_requests,
            'requests_limit': limit_config['requests'],
            'window_seconds': limit_config['window'],
            'reset_time': now + limit_config['window']
        }

class AuthManager:
    def __init__(self):
        import os
        self.secret_key = os.getenv("JWT_SECRET_KEY", "dev-secret-change-in-production")
        self.algorithm = "HS256"
        self.access_token_expire = 3600  # 1 hour
        self.refresh_token_expire = 86400 * 7  # 7 days
        
        # User database (in production, use real database)
        self.users = {
            "admin": {
                "password_hash": self._hash_password("admin123"),
                "role": "admin",
                "tier": "enterprise",
                "permissions": ["read", "write", "admin", "emergency"]
            },
            "analyst": {
                "password_hash": self._hash_password("analyst123"),
                "role": "analyst", 
                "tier": "premium",
                "permissions": ["read", "write"]
            },
            "viewer": {
                "password_hash": self._hash_password("viewer123"),
                "role": "viewer",
                "tier": "default", 
                "permissions": ["read"]
            }
        }
        
        self.rate_limiter = RateLimiter()
        self.security = HTTPBearer()
        
        # API Keys for service-to-service communication
        self.api_keys = {
            "sk-infinite-ai-prod-2024": {
                "name": "Production API Key",
                "tier": "enterprise",
                "permissions": ["read", "write", "admin"],
                "created_at": time.time()
            },
            "sk-infinite-ai-demo-2024": {
                "name": "Demo API Key", 
                "tier": "premium",
                "permissions": ["read", "write"],
                "created_at": time.time()
            }
        }
    
    def _hash_password(self, password: str) -> str:
        """Hash password dengan salt"""
        salt = "infinite-ai-salt"
        return hashlib.sha256((password + salt).encode()).hexdigest()
    
    async def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        """Authenticate user dengan username/password"""
        
        if username not in self.users:
            return None
        
        user = self.users[username]
        password_hash = self._hash_password(password)
        
        if password_hash != user["password_hash"]:
            return None
        
        return {
            "username": username,
            "role": user["role"],
            "tier": user["tier"],
            "permissions": user["permissions"]
        }
    
    async def create_access_token(self, user_data: Dict) -> str:
        """Create JWT access token"""
        
        payload = {
            "sub": user_data["username"],
            "role": user_data["role"],
            "tier": user_data["tier"],
            "permissions": user_data["permissions"],
            "exp": datetime.utcnow() + timedelta(seconds=self.access_token_expire),
            "iat": datetime.utcnow(),
            "type": "access"
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    async def create_refresh_token(self, user_data: Dict) -> str:
        """Create JWT refresh token"""
        
        payload = {
            "sub": user_data["username"],
            "exp": datetime.utcnow() + timedelta(seconds=self.refresh_token_expire),
            "iat": datetime.utcnow(),
            "type": "refresh"
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    async def verify_token(self, token: str) -> Optional[Dict]:
        """Verify JWT token"""
        
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Check if token is expired
            if payload.get("exp", 0) < time.time():
                return None
            
            return payload
            
        except jwt.InvalidTokenError:
            return None
    
    async def verify_api_key(self, api_key: str) -> Optional[Dict]:
        """Verify API key"""
        
        if api_key not in self.api_keys:
            return None
        
        key_info = self.api_keys[api_key]
        
        return {
            "api_key": api_key,
            "name": key_info["name"],
            "tier": key_info["tier"],
            "permissions": key_info["permissions"],
            "type": "api_key"
        }
    
    async def check_permission(self, user_data: Dict, required_permission: str) -> bool:
        """Check if user has required permission"""
        
        user_permissions = user_data.get("permissions", [])
        
        # Admin has all permissions
        if "admin" in user_permissions:
            return True
        
        return required_permission in user_permissions
    
    async def get_current_user(self, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())) -> Dict:
        """FastAPI dependency untuk get current user"""
        
        token = credentials.credentials
        
        # Try JWT token first
        user_data = await self.verify_token(token)
        if user_data and user_data.get("type") == "access":
            return user_data
        
        # Try API key
        api_data = await self.verify_api_key(token)
        if api_data:
            return api_data
        
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
    async def require_permission(self, permission: str):
        """FastAPI dependency untuk require specific permission"""
        
        async def permission_checker(user_data: Dict = Depends(self.get_current_user)) -> Dict:
            if not await self.check_permission(user_data, permission):
                raise HTTPException(
                    status_code=403, 
                    detail=f"Permission '{permission}' required"
                )
            return user_data
        
        return permission_checker
    
    async def rate_limit_middleware(self, request: Request, user_data: Dict = Depends(get_current_user)):
        """Rate limiting middleware"""
        
        client_id = user_data.get("sub") or user_data.get("api_key", "anonymous")
        tier = user_data.get("tier", "default")
        
        if not await self.rate_limiter.check_rate_limit(client_id, tier):
            rate_info = await self.rate_limiter.get_rate_limit_info(client_id, tier)
            
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded",
                headers={
                    "X-RateLimit-Limit": str(rate_info["requests_limit"]),
                    "X-RateLimit-Remaining": str(max(0, rate_info["requests_limit"] - rate_info["requests_made"])),
                    "X-RateLimit-Reset": str(int(rate_info["reset_time"]))
                }
            )
        
        return user_data
    
    async def get_security_metrics(self) -> Dict:
        """Get security metrics"""
        
        total_users = len(self.users)
        total_api_keys = len(self.api_keys)
        
        # Count active sessions (simplified)
        active_sessions = sum(len(requests) for requests in self.rate_limiter.requests.values())
        
        return {
            "total_users": total_users,
            "total_api_keys": total_api_keys,
            "active_sessions": active_sessions,
            "rate_limits_configured": len(self.rate_limiter.limits),
            "security_features": [
                "JWT Authentication",
                "API Key Authentication", 
                "Role-based Access Control",
                "Rate Limiting",
                "Permission System"
            ]
        }

# Global auth manager instance
auth_manager = AuthManager()