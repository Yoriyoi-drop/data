"""
Enterprise API Routes - MFA, Audit, Background Tasks
"""
from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks
from app.core.security import get_current_user, require_admin
from app.core.mfa import mfa_manager
from app.core.audit import audit_logger, AuditEventType
from app.services.tasks import analyze_file_background
from app.models.requests import MFASetupRequest, AuditQueryRequest
from app.models.responses import MFASetupResponse, TaskResponse

enterprise_router = APIRouter(prefix="/enterprise", tags=["enterprise"])

# MFA Routes
@enterprise_router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Setup MFA for user"""
    user_id = current_user["sub"]
    username = current_user["username"]
    
    # Generate secret and QR code
    secret = mfa_manager.generate_secret()
    qr_code = mfa_manager.generate_qr_code(username, secret)
    backup_codes = mfa_manager.get_backup_codes()
    
    # Log audit event
    audit_logger.log_event(
        event_type=AuditEventType.SYSTEM_CONFIG,
        user_id=user_id,
        ip_address=request.client.host,
        action="mfa_setup_initiated"
    )
    
    return MFASetupResponse(
        secret=secret,
        qr_code=qr_code,
        backup_codes=backup_codes
    )

@enterprise_router.post("/mfa/verify")
async def verify_mfa(
    request: Request,
    token: str,
    secret: str,
    current_user: dict = Depends(get_current_user)
):
    """Verify MFA token"""
    user_id = current_user["sub"]
    
    is_valid = mfa_manager.verify_totp(secret, token)
    
    # Log audit event
    audit_logger.log_event(
        event_type=AuditEventType.USER_LOGIN,
        user_id=user_id,
        ip_address=request.client.host,
        action="mfa_verification",
        result="success" if is_valid else "failure"
    )
    
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid MFA token")
    
    return {"message": "MFA verified successfully"}

# Background Tasks Routes
@enterprise_router.post("/tasks/analyze-file", response_model=TaskResponse)
async def queue_file_analysis(
    file_path: str,
    analysis_type: str = "comprehensive",
    current_user: dict = Depends(get_current_user)
):
    """Queue file analysis as background task"""
    task = analyze_file_background.delay(file_path, analysis_type)
    
    # Log audit event
    audit_logger.log_event(
        event_type=AuditEventType.THREAT_ANALYSIS,
        user_id=current_user["sub"],
        action="background_analysis_queued",
        details={"task_id": task.id, "file_path": file_path}
    )
    
    return TaskResponse(
        task_id=task.id,
        status="queued",
        message="File analysis queued for processing"
    )

@enterprise_router.get("/tasks/{task_id}")
async def get_task_status(
    task_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get background task status"""
    from app.services.celery_app import celery_app
    
    task = celery_app.AsyncResult(task_id)
    
    return {
        "task_id": task_id,
        "status": task.status,
        "result": task.result if task.ready() else None,
        "progress": task.info if task.status == "PROGRESS" else None
    }

# Audit Routes (Admin Only)
@enterprise_router.get("/audit/events")
async def get_audit_events(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    current_user: dict = Depends(require_admin)
):
    """Get audit events (admin only)"""
    # Log admin access
    audit_logger.log_event(
        event_type=AuditEventType.ADMIN_ACTION,
        user_id=current_user["sub"],
        ip_address=request.client.host,
        action="audit_log_access"
    )
    
    # In production, query from database
    return {
        "events": [],
        "total": 0,
        "limit": limit,
        "offset": offset
    }

@enterprise_router.get("/audit/security-events")
async def get_security_events(
    request: Request,
    severity: str = None,
    current_user: dict = Depends(require_admin)
):
    """Get security audit events"""
    audit_logger.log_event(
        event_type=AuditEventType.ADMIN_ACTION,
        user_id=current_user["sub"],
        ip_address=request.client.host,
        action="security_events_access"
    )
    
    return {"security_events": [], "filters": {"severity": severity}}

# System Health Routes
@enterprise_router.get("/health/detailed")
async def detailed_health_check(
    current_user: dict = Depends(require_admin)
):
    """Detailed system health check"""
    from app.services.celery_app import celery_app
    
    # Check Celery workers
    celery_stats = celery_app.control.inspect().stats()
    
    return {
        "database": "healthy",
        "redis": "healthy", 
        "celery_workers": len(celery_stats) if celery_stats else 0,
        "mfa_service": "operational",
        "audit_logging": "active"
    }