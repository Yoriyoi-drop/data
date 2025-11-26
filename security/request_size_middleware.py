"""
Request Size Middleware

Limits the size of incoming request bodies. If the request exceeds the configured
`MAX_REQUEST_SIZE` (in bytes) a 413 Payload Too Large response is returned.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

MAX_REQUEST_SIZE = 5 * 1024 * 1024  # 5 MB default limit

class RequestSizeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Read the request body size without consuming the stream
        body = await request.body()
        if len(body) > MAX_REQUEST_SIZE:
            return JSONResponse(
                {"detail": "Request payload too large"},
                status_code=413,
            )
        # Re‑inject the body for downstream handlers
        request._receive = lambda: {"type": "http.request", "body": body, "more_body": False}
        response = await call_next(request)
        return response
