"""
Pydantic V2 Models - Modern validation dengan field_validator
"""
from pydantic import BaseModel, field_validator, ConfigDict
from typing import Dict, Any, Optional, List
from datetime import datetime
from enum import Enum

class TaskPriorityEnum(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AgentStatusEnum(str, Enum):
    IDLE = "idle"
    BUSY = "busy"
    ERROR = "error"
    MAINTENANCE = "maintenance"

class TaskRequest(BaseModel):
    """Task request model dengan Pydantic V2"""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        use_enum_values=True
    )
    
    agent: Optional[str] = None
    task_type: str
    data: Dict[str, Any] = {}
    priority: TaskPriorityEnum = TaskPriorityEnum.MEDIUM
    
    @field_validator("task_type")
    @classmethod
    def validate_task_type(cls, v: str) -> str:
        allowed_types = [
            "threat_analysis", "strategic_planning", "code_review",
            "pattern_recognition", "log_analysis", "quick_analysis"
        ]
        if v not in allowed_types:
            raise ValueError(f"Task type must be one of: {allowed_types}")
        return v
    
    @field_validator("agent")
    @classmethod
    def validate_agent(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            allowed_agents = ["gpt5", "claude", "grok", "mistral"]
            if v not in allowed_agents:
                raise ValueError(f"Agent must be one of: {allowed_agents}")
        return v

class ThreatAnalysisRequest(BaseModel):
    """Threat analysis request model"""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    source: str
    threat_type: str
    payload: Optional[str] = None
    severity: str = "medium"
    target: Optional[str] = None
    
    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed_severities = ["low", "medium", "high", "critical"]
        if v.lower() not in allowed_severities:
            raise ValueError(f"Severity must be one of: {allowed_severities}")
        return v.lower()
    
    @field_validator("source")
    @classmethod
    def validate_source(cls, v: str) -> str:
        if not v or len(v.strip()) == 0:
            raise ValueError("Source cannot be empty")
        return v

class AgentResponse(BaseModel):
    """Agent response model"""
    model_config = ConfigDict(use_enum_values=True)
    
    agent: str
    task_type: str
    result: Dict[str, Any]
    confidence: Optional[float] = None
    processing_time: Optional[float] = None
    status: str = "success"
    timestamp: datetime = datetime.now()

class MaintenanceRequest(BaseModel):
    """Maintenance request model"""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    agent: str
    maintenance: bool = True
    reason: Optional[str] = None
    
    @field_validator("agent")
    @classmethod
    def validate_agent(cls, v: str) -> str:
        allowed_agents = ["gpt5", "claude", "grok", "mistral"]
        if v not in allowed_agents:
            raise ValueError(f"Agent must be one of: {allowed_agents}")
        return v

class AuthRequest(BaseModel):
    """Authentication request model"""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    username: str
    password: str
    
    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if len(v) < 3:
            raise ValueError("Username must be at least 3 characters")
        return v
    
    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 6:
            raise ValueError("Password must be at least 6 characters")
        return v

class TokenResponse(BaseModel):
    """Token response model"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user_info: Dict[str, Any]

class ErrorResponse(BaseModel):
    """Error response model"""
    error: str
    detail: Optional[str] = None
    timestamp: datetime = datetime.now()
    request_id: Optional[str] = None

class HealthResponse(BaseModel):
    """Health check response model"""
    status: str
    version: str
    agents_online: int
    uptime: str
    timestamp: datetime = datetime.now()

class MetricsResponse(BaseModel):
    """Metrics response model"""
    total_agents: int
    active_agents: int
    total_tasks_completed: int
    average_success_rate: float
    agent_details: Dict[str, Any]
    load_balancer: Optional[Dict[str, Any]] = None
    smart_dispatcher: Optional[Dict[str, Any]] = None
    labyrinth_defense: Optional[Dict[str, Any]] = None