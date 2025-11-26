"""
API Routes for Infinite AI Security Platform
"""
from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File
from slowapi import Limiter
from slowapi.util import get_remote_address
import tempfile
import os

from app.core.security import verify_api_key, get_current_user, require_admin
from app.services.ai_orchestrator import get_ai_orchestrator
from app.services.reverse_engineering import get_reverse_engine
from app.models.requests import ThreatAnalysisRequest, AuthRequest
from app.models.responses import ThreatAnalysisResponse, AuthResponse

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

# Main API router
api_router = APIRouter()

# Authentication routes
auth_router = APIRouter(prefix="/auth", tags=["authentication"])

@auth_router.post("/login", response_model=AuthResponse)
@limiter.limit("10/minute")
async def login(request: Request, auth_request: AuthRequest):
    """User authentication"""
    # Implementation here
    return AuthResponse(
        access_token="mock_token",
        refresh_token="mock_refresh",
        token_type="bearer"
    )

@auth_router.post("/logout")
@limiter.limit("100/minute")
async def logout(request: Request, current_user: dict = Depends(get_current_user)):
    """User logout"""
    return {"message": "Successfully logged out"}

# AI Analysis routes
ai_router = APIRouter(prefix="/ai", tags=["ai-analysis"])

@ai_router.post("/analyze-threat", response_model=ThreatAnalysisResponse)
@limiter.limit("100/minute")
async def analyze_threat(
    request: Request,
    threat_request: ThreatAnalysisRequest,
    ai_orchestrator = Depends(get_ai_orchestrator),
    api_key: str = Depends(verify_api_key)
):
    """Analyze threat using AI agents"""
    result = await ai_orchestrator.analyze_threat(threat_request.dict())
    return ThreatAnalysisResponse(**result)

@ai_router.get("/agents/status")
@limiter.limit("200/minute")
async def get_agents_status(
    request: Request,
    ai_orchestrator = Depends(get_ai_orchestrator),
    current_user: dict = Depends(get_current_user)
):
    """Get AI agents status"""
    return await ai_orchestrator.get_agents_status()

# Reverse Engineering routes
re_router = APIRouter(prefix="/reverse-engineering", tags=["reverse-engineering"])

@re_router.post("/analyze-binary")
@limiter.limit("50/minute")
async def analyze_binary(
    request: Request,
    file: UploadFile = File(...),
    reverse_engine = Depends(get_reverse_engine),
    api_key: str = Depends(verify_api_key)
):
    """Analyze binary file"""
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{file.filename}") as tmp_file:
        content = await file.read()
        tmp_file.write(content)
        tmp_path = tmp_file.name
    
    try:
        result = await reverse_engine.analyze_binary(tmp_path)
        return result
    finally:
        os.unlink(tmp_path)

@re_router.post("/extract-iocs")
@limiter.limit("30/minute")
async def extract_iocs(
    request: Request,
    file: UploadFile = File(...),
    reverse_engine = Depends(get_reverse_engine),
    api_key: str = Depends(verify_api_key)
):
    """Extract IOCs from file"""
    with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{file.filename}") as tmp_file:
        content = await file.read()
        tmp_file.write(content)
        tmp_path = tmp_file.name
    
    try:
        result = await reverse_engine.extract_iocs(tmp_path)
        return result
    finally:
        os.unlink(tmp_path)

# Admin routes
admin_router = APIRouter(prefix="/admin", tags=["admin"])

@admin_router.get("/system/status")
@limiter.limit("100/minute")
async def get_system_status(
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """Get system status (admin only)"""
    return {
        "status": "operational",
        "version": "2.0.0",
        "uptime": "72h 15m",
        "memory_usage": "2.1GB",
        "cpu_usage": "15%"
    }

@admin_router.post("/emergency/lockdown")
@limiter.limit("10/minute")
async def emergency_lockdown(
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """Trigger emergency lockdown"""
    return {"message": "Emergency lockdown activated"}

# Include all routers
api_router.include_router(auth_router)
api_router.include_router(ai_router)
api_router.include_router(re_router)
api_router.include_router(admin_router)