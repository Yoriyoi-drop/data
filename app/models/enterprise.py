"""
Enterprise Models for MFA, Audit, and Background Tasks
"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

# MFA Models
class MFASetupRequest(BaseModel):
    """MFA setup request"""
    enable_mfa: bool = Field(default=True)

class MFASetupResponse(BaseModel):
    """MFA setup response"""
    secret: str = Field(..., description="TOTP secret key")
    qr_code: str = Field(..., description="Base64 encoded QR code")
    backup_codes: List[str] = Field(..., description="Backup recovery codes")
    setup_complete: bool = Field(default=False)

class MFAVerifyRequest(BaseModel):
    """MFA verification request"""
    token: str = Field(..., min_length=6, max_length=6, description="6-digit TOTP token")
    secret: str = Field(..., description="User's TOTP secret")

# Audit Models
class AuditQueryRequest(BaseModel):
    """Audit log query request"""
    event_type: Optional[str] = None
    user_id: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    limit: int = Field(default=100, le=1000)
    offset: int = Field(default=0, ge=0)

class AuditEvent(BaseModel):
    """Audit event model"""
    id: str
    timestamp: datetime
    event_type: str
    user_id: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    resource: Optional[str]
    action: Optional[str]
    result: str
    details: Dict[str, Any]

class AuditResponse(BaseModel):
    """Audit query response"""
    events: List[AuditEvent]
    total: int
    limit: int
    offset: int

# Background Task Models
class TaskResponse(BaseModel):
    """Background task response"""
    task_id: str = Field(..., description="Unique task identifier")
    status: str = Field(..., description="Task status")
    message: str = Field(..., description="Status message")
    created_at: datetime = Field(default_factory=datetime.utcnow)

class TaskStatusResponse(BaseModel):
    """Task status response"""
    task_id: str
    status: str  # PENDING, PROGRESS, SUCCESS, FAILURE
    result: Optional[Dict[str, Any]] = None
    progress: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

# System Health Models
class SystemHealthResponse(BaseModel):
    """Detailed system health response"""
    overall_status: str = Field(..., description="Overall system status")
    components: Dict[str, str] = Field(..., description="Component health status")
    metrics: Dict[str, Any] = Field(default_factory=dict, description="System metrics")
    last_check: datetime = Field(default_factory=datetime.utcnow)

class SecurityEventResponse(BaseModel):
    """Security event response"""
    event_id: str
    timestamp: datetime
    event_type: str
    severity: str  # low, medium, high, critical
    description: str
    source_ip: Optional[str]
    user_id: Optional[str]
    affected_resources: List[str]
    mitigation_status: str
    details: Dict[str, Any]