"""
Per‑User Rate Limiter Middleware

Implements a simple token‑bucket rate limiter per user (identified by an API key or JWT subject).
Uses Redis to store counters with a TTL of 1 minute.
"""

import time
import os
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
import redis

# Redis connection – reads from env or defaults
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
redis_client = redis.from_url(REDIS_URL)

# Default limits – can be overridden via env variables
REQUESTS_PER_MINUTE = int(os.getenv("RATE_LIMIT_RPM", "60"))

class PerUserRateLimiter(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Identify the user – for now we look for an Authorization header (JWT) or X‑API‑Key
        user_id = request.headers.get("Authorization") or request.headers.get("X-API-Key")
        if not user_id:
            # If we cannot identify the user, treat as anonymous
            user_id = "anonymous"
        # Redis key format
        key = f"rl:{user_id}"
        # Increment the counter atomically
        try:
            current = redis_client.incr(key)
            # Set TTL on first hit
            if current == 1:
                redis_client.expire(key, 60)
        except redis.RedisError as exc:
            # If Redis is unavailable, allow the request (fail‑open)
            return await call_next(request)
        if current > REQUESTS_PER_MINUTE:
            return JSONResponse({"detail": "Rate limit exceeded"}, status_code=429)
        response = await call_next(request)
        return response
