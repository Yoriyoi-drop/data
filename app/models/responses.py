"""
Response Models for Infinite AI Security Platform
"""
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime

class BaseResponse(BaseModel):
    """Base response model"""
    success: bool = Field(default=True)
    message: str = Field(default="Operation completed successfully")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class ThreatAnalysisResponse(BaseResponse):
    """Response model for threat analysis"""
    threat_id: str = Field(..., description="Unique threat identifier")
    threat_score: int = Field(..., ge=0, le=100, description="Threat score (0-100)")
    threat_level: str = Field(..., description="Threat level classification")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Analysis confidence")
    
    # AI Agent Results
    agent_results: Dict[str, Any] = Field(default_factory=dict)
    
    # Analysis Details
    indicators: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    mitigation_steps: List[str] = Field(default_factory=list)
    
    # Metadata
    analysis_duration: float = Field(..., description="Analysis duration in seconds")
    agents_used: List[str] = Field(default_factory=list)

class AuthResponse(BaseResponse):
    """Authentication response model"""
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer")
    expires_in: int = Field(default=1800, description="Token expiration in seconds")
    
    # User Info
    user_id: Optional[str] = None
    username: Optional[str] = None
    role: Optional[str] = None
    permissions: List[str] = Field(default_factory=list)

class BinaryAnalysisResponse(BaseResponse):
    """Binary analysis response model"""
    file_info: Dict[str, Any] = Field(default_factory=dict)
    
    # Analysis Results
    file_type: str = Field(..., description="Detected file type")
    architecture: str = Field(..., description="Target architecture")
    threat_score: int = Field(..., ge=0, le=100)
    
    # Detailed Analysis
    sections: List[Dict[str, Any]] = Field(default_factory=list)
    imports: List[str] = Field(default_factory=list)
    exports: List[str] = Field(default_factory=list)
    strings: List[str] = Field(default_factory=list)
    
    # Security Assessment
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)
    malware_indicators: List[Dict[str, Any]] = Field(default_factory=list)
    packer_detected: bool = Field(default=False)
    
    # AI Analysis
    ai_analysis: Dict[str, Any] = Field(default_factory=dict)

class IOCExtractionResponse(BaseResponse):
    """IOC extraction response model"""
    ioc_count: int = Field(..., ge=0, description="Total IOCs extracted")
    
    # IOC Categories
    file_hashes: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    ip_addresses: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    registry_keys: List[str] = Field(default_factory=list)
    file_paths: List[str] = Field(default_factory=list)
    
    # Generated Rules
    yara_rule: Optional[str] = None
    snort_rules: List[str] = Field(default_factory=list)
    
    # Metadata
    extraction_method: str = Field(default="automated")
    confidence_scores: Dict[str, float] = Field(default_factory=dict)

class AgentStatusResponse(BaseResponse):
    """AI agent status response model"""
    agents: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    
    # System Stats
    total_agents: int = Field(..., ge=0)
    active_agents: int = Field(..., ge=0)
    total_tasks_completed: int = Field(..., ge=0)
    average_response_time: float = Field(..., ge=0.0)
    
    # Performance Metrics
    system_load: float = Field(..., ge=0.0, le=100.0)
    memory_usage: float = Field(..., ge=0.0, le=100.0)
    cpu_usage: float = Field(..., ge=0.0, le=100.0)

class SystemStatusResponse(BaseResponse):
    """System status response model"""
    status: str = Field(..., description="Overall system status")
    version: str = Field(..., description="Platform version")
    uptime: str = Field(..., description="System uptime")
    
    # Resource Usage
    memory_usage: str = Field(..., description="Memory usage")
    cpu_usage: str = Field(..., description="CPU usage")
    disk_usage: str = Field(..., description="Disk usage")
    
    # Component Status
    database_status: str = Field(default="healthy")
    redis_status: str = Field(default="healthy")
    ai_agents_status: str = Field(default="operational")
    
    # Statistics
    threats_processed_today: int = Field(default=0)
    files_analyzed_today: int = Field(default=0)
    active_sessions: int = Field(default=0)

class ErrorResponse(BaseModel):
    """Error response model"""
    success: bool = Field(default=False)
    error_code: str = Field(..., description="Error code")
    error_message: str = Field(..., description="Human-readable error message")
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Debug Info (only in development)
    stack_trace: Optional[str] = None
    request_id: Optional[str] = None

class UserResponse(BaseResponse):
    """User information response model"""
    user_id: str = Field(..., description="Unique user identifier")
    username: str = Field(..., description="Username")
    email: str = Field(..., description="User email")
    role: str = Field(..., description="User role")
    is_active: bool = Field(..., description="User active status")
    created_at: datetime = Field(..., description="Account creation date")
    last_login: Optional[datetime] = None
    
    # Permissions
    permissions: List[str] = Field(default_factory=list)
    
    # Statistics
    total_analyses: int = Field(default=0)
    total_uploads: int = Field(default=0)

class EmergencyResponse(BaseResponse):
    """Emergency response model"""
    emergency_id: str = Field(..., description="Emergency incident ID")
    status: str = Field(..., description="Emergency status")
    response_time: float = Field(..., description="Response time in seconds")
    
    # Actions Taken
    actions_triggered: List[str] = Field(default_factory=list)
    systems_affected: List[str] = Field(default_factory=list)
    
    # Response Details
    incident_commander: Optional[str] = None
    estimated_resolution: Optional[datetime] = None
    
    # Notifications
    notifications_sent: int = Field(default=0)
    stakeholders_notified: List[str] = Field(default_factory=list)

class AnalyticsResponse(BaseResponse):
    """Analytics and metrics response model"""
    time_range: str = Field(..., description="Analytics time range")
    
    # Threat Analytics
    total_threats: int = Field(default=0)
    threats_by_type: Dict[str, int] = Field(default_factory=dict)
    threats_by_severity: Dict[str, int] = Field(default_factory=dict)
    
    # Performance Analytics
    average_response_time: float = Field(default=0.0)
    peak_response_time: float = Field(default=0.0)
    system_uptime: float = Field(default=99.99)
    
    # Usage Analytics
    total_api_calls: int = Field(default=0)
    unique_users: int = Field(default=0)
    files_processed: int = Field(default=0)
    
    # Trends
    threat_trend: str = Field(default="stable")  # increasing, decreasing, stable
    performance_trend: str = Field(default="stable")
    usage_trend: str = Field(default="stable")