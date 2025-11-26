"""
Enterprise Audit Logging System
"""
import structlog
from datetime import datetime
from typing import Dict, Any, Optional
from enum import Enum
import json

class AuditEventType(Enum):
    """Audit event types"""
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    API_ACCESS = "api_access"
    FILE_UPLOAD = "file_upload"
    THREAT_ANALYSIS = "threat_analysis"
    ADMIN_ACTION = "admin_action"
    SECURITY_ALERT = "security_alert"
    DATA_ACCESS = "data_access"
    SYSTEM_CONFIG = "system_config"

class AuditLogger:
    """Enterprise audit logging"""
    
    def __init__(self):
        self.logger = structlog.get_logger("audit")
    
    def log_event(
        self,
        event_type: AuditEventType,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        resource: Optional[str] = None,
        action: Optional[str] = None,
        result: str = "success",
        details: Optional[Dict[str, Any]] = None
    ):
        """Log audit event"""
        audit_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type.value,
            "user_id": user_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "resource": resource,
            "action": action,
            "result": result,
            "details": details or {}
        }
        
        self.logger.info("audit_event", **audit_data)
    
    def log_security_event(
        self,
        event_type: str,
        severity: str,
        description: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        additional_data: Optional[Dict] = None
    ):
        """Log security-specific events"""
        self.log_event(
            event_type=AuditEventType.SECURITY_ALERT,
            user_id=user_id,
            ip_address=ip_address,
            action=event_type,
            details={
                "severity": severity,
                "description": description,
                "additional_data": additional_data or {}
            }
        )
    
    def log_data_access(
        self,
        user_id: str,
        resource: str,
        action: str,
        ip_address: Optional[str] = None,
        success: bool = True
    ):
        """Log data access events for compliance"""
        self.log_event(
            event_type=AuditEventType.DATA_ACCESS,
            user_id=user_id,
            ip_address=ip_address,
            resource=resource,
            action=action,
            result="success" if success else "failure"
        )

# Global audit logger
audit_logger = AuditLogger()