"""
Request Size Limit Middleware
Security Enhancement - Prevents DoS attacks via large payloads
"""
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Dict


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware to limit request body size
    
    Prevents DoS attacks via large payloads
    """
    
    def __init__(self, app, default_max_size: int = 1024 * 1024):  # 1MB default
        """
        Initialize middleware
        
        Args:
            app: FastAPI application
            default_max_size: Default maximum size in bytes
        """
        super().__init__(app)
        self.default_max_size = default_max_size
        
        # Endpoint-specific limits
        self.endpoint_limits: Dict[str, int] = {
            "/api/analyze": 10 * 1024,  # 10KB
            "/api/upload": 10 * 1024 * 1024,  # 10MB
            "/auth/login": 1024,  # 1KB
            "/auth/change-password": 1024,  # 1KB
            "/auth/csrf-token": 512,  # 512B
            "/api/test-attack": 1024,  # 1KB
        }
    
    async def dispatch(self, request: Request, call_next):
        """
        Process request and check size
        
        Args:
            request: Incoming request
            call_next: Next middleware/handler
        
        Returns:
            Response
        """
        # Only check for methods that have body
        if request.method in ["POST", "PUT", "PATCH"]:
            content_length = request.headers.get("content-length")
            
            if content_length:
                content_length = int(content_length)
                
                # Get limit for this endpoint
                max_size = self._get_max_size_for_endpoint(request.url.path)
                
                # Check if exceeds limit
                if content_length > max_size:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "error": "Request too large",
                            "detail": f"Request size {content_length} bytes exceeds limit of {max_size} bytes",
                            "max_size": max_size,
                            "received_size": content_length
                        }
                    )
        
        response = await call_next(request)
        return response
    
    def _get_max_size_for_endpoint(self, path: str) -> int:
        """
        Get maximum size for specific endpoint
        
        Args:
            path: Request path
        
        Returns:
            Maximum size in bytes
        """
        # Check exact match first
        if path in self.endpoint_limits:
            return self.endpoint_limits[path]
        
        # Check prefix match
        for endpoint_path, limit in self.endpoint_limits.items():
            if path.startswith(endpoint_path):
                return limit
        
        # Return default
        return self.default_max_size
    
    def set_endpoint_limit(self, path: str, max_size: int):
        """
        Set custom limit for endpoint
        
        Args:
            path: Endpoint path
            max_size: Maximum size in bytes
        """
        self.endpoint_limits[path] = max_size
