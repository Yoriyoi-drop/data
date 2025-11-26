"""
Request Models for Infinite AI Security Platform
"""
from pydantic import BaseModel, Field, validator
from typing import Optional, Dict, Any, List
from datetime import datetime

class ThreatAnalysisRequest(BaseModel):
    """Request model for threat analysis"""
    threat_type: str = Field(..., description="Type of threat to analyze")
    severity: str = Field(..., description="Threat severity level")
    source: str = Field(..., description="Source of the threat")
    data: Dict[str, Any] = Field(default_factory=dict, description="Additional threat data")
    timestamp: Optional[datetime] = Field(default_factory=datetime.utcnow)
    
    @validator("threat_type")
    def validate_threat_type(cls, v):
        allowed_types = [
            "malware", "phishing", "ddos", "sql_injection", 
            "xss", "brute_force", "insider_threat", "apt"
        ]
        if v.lower() not in allowed_types:
            raise ValueError(f"Invalid threat type. Allowed: {allowed_types}")
        return v.lower()
    
    @validator("severity")
    def validate_severity(cls, v):
        allowed_severities = ["low", "medium", "high", "critical"]
        if v.lower() not in allowed_severities:
            raise ValueError(f"Invalid severity. Allowed: {allowed_severities}")
        return v.lower()

class AuthRequest(BaseModel):
    """Authentication request model"""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    remember_me: bool = Field(default=False)

class BinaryAnalysisRequest(BaseModel):
    """Binary analysis request model"""
    analysis_type: str = Field(default="comprehensive", description="Type of analysis")
    include_strings: bool = Field(default=True)
    include_imports: bool = Field(default=True)
    include_entropy: bool = Field(default=True)
    
    @validator("analysis_type")
    def validate_analysis_type(cls, v):
        allowed_types = ["quick", "comprehensive", "deep"]
        if v not in allowed_types:
            raise ValueError(f"Invalid analysis type. Allowed: {allowed_types}")
        return v

class IOCExtractionRequest(BaseModel):
    """IOC extraction request model"""
    extract_domains: bool = Field(default=True)
    extract_ips: bool = Field(default=True)
    extract_hashes: bool = Field(default=True)
    extract_urls: bool = Field(default=True)
    generate_yara: bool = Field(default=True)

class AgentTaskRequest(BaseModel):
    """AI agent task request model"""
    agent_name: str = Field(..., description="Name of the AI agent")
    task_type: str = Field(..., description="Type of task")
    task_data: Dict[str, Any] = Field(..., description="Task data")
    priority: str = Field(default="medium", description="Task priority")
    
    @validator("agent_name")
    def validate_agent_name(cls, v):
        allowed_agents = ["gpt5", "claude", "grok", "mistral", "auto"]
        if v.lower() not in allowed_agents:
            raise ValueError(f"Invalid agent name. Allowed: {allowed_agents}")
        return v.lower()
    
    @validator("priority")
    def validate_priority(cls, v):
        allowed_priorities = ["low", "medium", "high", "critical"]
        if v.lower() not in allowed_priorities:
            raise ValueError(f"Invalid priority. Allowed: {allowed_priorities}")
        return v.lower()

class SystemConfigRequest(BaseModel):
    """System configuration request model"""
    rate_limit_per_minute: Optional[int] = Field(None, ge=1, le=10000)
    max_file_size: Optional[int] = Field(None, ge=1024, le=1073741824)  # 1KB to 1GB
    log_level: Optional[str] = Field(None)
    
    @validator("log_level")
    def validate_log_level(cls, v):
        if v is not None:
            allowed_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
            if v.upper() not in allowed_levels:
                raise ValueError(f"Invalid log level. Allowed: {allowed_levels}")
            return v.upper()
        return v

class UserCreateRequest(BaseModel):
    """User creation request model"""
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., regex=r'^[^@]+@[^@]+\.[^@]+$')
    password: str = Field(..., min_length=8)
    role: str = Field(default="user")
    is_active: bool = Field(default=True)
    
    @validator("role")
    def validate_role(cls, v):
        allowed_roles = ["user", "analyst", "admin"]
        if v.lower() not in allowed_roles:
            raise ValueError(f"Invalid role. Allowed: {allowed_roles}")
        return v.lower()

class EmergencyRequest(BaseModel):
    """Emergency response request model"""
    emergency_type: str = Field(..., description="Type of emergency")
    severity: str = Field(..., description="Emergency severity")
    description: str = Field(..., min_length=10, max_length=1000)
    affected_systems: List[str] = Field(default_factory=list)
    
    @validator("emergency_type")
    def validate_emergency_type(cls, v):
        allowed_types = [
            "security_breach", "system_compromise", "data_leak",
            "ddos_attack", "malware_outbreak", "insider_threat"
        ]
        if v.lower() not in allowed_types:
            raise ValueError(f"Invalid emergency type. Allowed: {allowed_types}")
        return v.lower()
    
    @validator("severity")
    def validate_severity(cls, v):
        allowed_severities = ["medium", "high", "critical"]
        if v.lower() not in allowed_severities:
            raise ValueError(f"Invalid severity. Allowed: {allowed_severities}")
        return v.lower()