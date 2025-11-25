"""
Enhanced Security Logger
Security Enhancement - Structured logging with sanitization
"""
import logging
import json
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime, UTC
from typing import Dict, Any, Optional
from pathlib import Path


class SecurityLogger:
    """
    Enhanced security logger with structured logging
    
    Features:
    - Structured JSON logging
    - Log rotation
    - Sensitive data sanitization
    - Real-time alerting capability
    - Multiple log levels
    """
    
    def __init__(self, log_dir: str = "logs", log_file: str = "security.log",
                 max_bytes: int = 10*1024*1024, backup_count: int = 10):
        """
        Initialize security logger
        
        Args:
            log_dir: Directory for log files
            log_file: Log file name
            max_bytes: Maximum log file size (default 10MB)
            backup_count: Number of backup files to keep
        """
        # Create log directory
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        
        # Setup logger
        self.logger = logging.getLogger("security")
        self.logger.setLevel(logging.INFO)
        
        # Rotating file handler
        log_path = os.path.join(log_dir, log_file)
        handler = RotatingFileHandler(
            log_path,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        
        # JSON formatter
        formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
            '"message": "%(message)s", "extra": %(extra)s}'
        )
        handler.setFormatter(formatter)
        
        # Add handler
        self.logger.addHandler(handler)
        
        # Also log to console in development
        if os.getenv("ENVIRONMENT", "development") == "development":
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
        
        # Sensitive fields to sanitize
        self.sensitive_fields = {
            "password", "token", "secret", "api_key", "private_key",
            "access_token", "refresh_token", "session_id", "csrf_token",
            "credit_card", "ssn", "pin"
        }
        
        print(f"✅ Security logger initialized: {log_path}")
    
    def _sanitize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize sensitive data from logs
        
        Args:
            data: Data dictionary to sanitize
        
        Returns:
            Sanitized data dictionary
        """
        sanitized = {}
        
        for key, value in data.items():
            key_lower = key.lower()
            
            # Check if field is sensitive
            if any(sensitive in key_lower for sensitive in self.sensitive_fields):
                # Redact sensitive data
                if isinstance(value, str) and len(value) > 8:
                    sanitized[key] = f"{value[:4]}***{value[-4:]}"
                else:
                    sanitized[key] = "***REDACTED***"
            elif isinstance(value, dict):
                # Recursively sanitize nested dicts
                sanitized[key] = self._sanitize_data(value)
            elif isinstance(value, list):
                # Sanitize lists
                sanitized[key] = [
                    self._sanitize_data(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        
        return sanitized
    
    def log_security_event(self, event_type: str, user_id: Optional[str], 
                          ip_address: Optional[str], details: Dict[str, Any],
                          risk_level: str = "low"):
        """
        Log security event
        
        Args:
            event_type: Type of security event
            user_id: User ID (if applicable)
            ip_address: IP address
            details: Event details
            risk_level: Risk level (low, medium, high, critical)
        """
        # Sanitize details
        sanitized_details = self._sanitize_data(details)
        
        extra_data = {
            "event_type": event_type,
            "user_id": user_id or "anonymous",
            "ip_address": ip_address or "unknown",
            "risk_level": risk_level,
            "details": sanitized_details,
            "timestamp_utc": datetime.now(UTC).isoformat()
        }
        
        # Log based on risk level
        if risk_level == "critical":
            self.logger.critical(
                f"Security event: {event_type}",
                extra={"extra": json.dumps(extra_data)}
            )
            # Send alert for critical events
            self._send_alert(extra_data)
        elif risk_level == "high":
            self.logger.error(
                f"Security event: {event_type}",
                extra={"extra": json.dumps(extra_data)}
            )
        elif risk_level == "medium":
            self.logger.warning(
                f"Security event: {event_type}",
                extra={"extra": json.dumps(extra_data)}
            )
        else:
            self.logger.info(
                f"Security event: {event_type}",
                extra={"extra": json.dumps(extra_data)}
            )
    
    def log_authentication(self, event: str, user_id: str, ip_address: str,
                          success: bool, details: Optional[Dict] = None):
        """
        Log authentication event
        
        Args:
            event: Event type (login, logout, etc.)
            user_id: User ID
            ip_address: IP address
            success: Whether authentication succeeded
            details: Additional details
        """
        risk_level = "low" if success else "medium"
        
        event_details = {
            "event": event,
            "success": success,
            **(details or {})
        }
        
        self.log_security_event(
            f"auth_{event}",
            user_id,
            ip_address,
            event_details,
            risk_level
        )
    
    def log_access(self, endpoint: str, method: str, user_id: Optional[str],
                   ip_address: str, status_code: int, response_time: float):
        """
        Log API access
        
        Args:
            endpoint: API endpoint
            method: HTTP method
            user_id: User ID (if authenticated)
            ip_address: IP address
            status_code: HTTP status code
            response_time: Response time in seconds
        """
        details = {
            "endpoint": endpoint,
            "method": method,
            "status_code": status_code,
            "response_time_ms": round(response_time * 1000, 2)
        }
        
        # Determine risk level based on status code
        if status_code >= 500:
            risk_level = "high"
        elif status_code >= 400:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        self.log_security_event(
            "api_access",
            user_id,
            ip_address,
            details,
            risk_level
        )
    
    def log_threat_detection(self, threat_type: str, payload: str,
                            user_id: Optional[str], ip_address: str,
                            confidence: float, blocked: bool):
        """
        Log threat detection
        
        Args:
            threat_type: Type of threat detected
            payload: Malicious payload (will be sanitized)
            user_id: User ID
            ip_address: IP address
            confidence: Detection confidence (0-1)
            blocked: Whether threat was blocked
        """
        details = {
            "threat_type": threat_type,
            "payload_preview": payload[:100] if payload else "",
            "confidence": confidence,
            "blocked": blocked
        }
        
        risk_level = "critical" if confidence > 0.9 else "high" if confidence > 0.7 else "medium"
        
        self.log_security_event(
            "threat_detected",
            user_id,
            ip_address,
            details,
            risk_level
        )
    
    def _send_alert(self, event_data: Dict[str, Any]):
        """
        Send alert for critical events
        
        Args:
            event_data: Event data to include in alert
        """
        # TODO: Implement alerting (email, Slack, PagerDuty, etc.)
        # For now, just print to console
        print(f"\n🚨 CRITICAL SECURITY ALERT: {event_data['event_type']}")
        print(f"   User: {event_data['user_id']}")
        print(f"   IP: {event_data['ip_address']}")
        print(f"   Details: {event_data['details']}\n")
    
    def get_recent_events(self, count: int = 100, risk_level: Optional[str] = None) -> list:
        """
        Get recent security events from log file
        
        Args:
            count: Number of events to retrieve
            risk_level: Filter by risk level (optional)
        
        Returns:
            List of recent events
        """
        # TODO: Implement log parsing
        # For now, return empty list
        return []


# Global logger instance
security_logger = SecurityLogger()
