"""
Admin routes for API Gateway
Provides simple health/status endpoints for internal use.
"""
from fastapi import APIRouter

router = APIRouter()

@router.get("/ping", tags=["admin"])
async def ping():
    """Simple liveness check used by orchestration tools."""
    return {"status": "ok", "timestamp": "${{ now() }}"}

@router.get("/metrics", tags=["admin"])
async def metrics():
    """Placeholder for future metrics endpoint (e.g., Prometheus)."""
    return {"message": "Metrics endpoint not implemented yet"}
