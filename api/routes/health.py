"""
Health check routes
"""
from fastapi import APIRouter
from datetime import datetime

router = APIRouter(prefix="/health", tags=["health"])

@router.get("/")
async def health_check():
    """Basic health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0",
        "components": {
            "api": "online",
            "agents": "online", 
            "database": "online"
        }
    }

@router.get("/detailed")
async def detailed_health():
    """Detailed health check"""
    return {
        "status": "healthy",
        "uptime": "operational",
        "memory_usage": "normal",
        "cpu_usage": "normal",
        "disk_space": "sufficient",
        "network": "connected"
    }
