"""
Pydantic Validation Models for API Endpoints
Security Enhancement - Input Validation
"""
from pydantic import BaseModel, Field, validator, EmailStr
from typing import Optional, Dict, Any
import re

class LoginRequest(BaseModel):
    """Login request validation"""
    username: str = Field(..., min_length=3, max_length=50, description="Username")
    password: str = Field(..., min_length=1, max_length=128, description="Password")
    csrf_token: str = Field(..., min_length=32, max_length=128, description="CSRF token")
    
    @validator('username')
    def validate_username(cls, v):
        """Validate username format"""
        if not re.match(r'^[a-zA-Z0-9_.-]+$', v):
            raise ValueError('Username can only contain alphanumeric characters, dots, hyphens, and underscores')
        return v.strip()
    
    @validator('password')
    def validate_password_not_empty(cls, v):
        """Ensure password is not empty or whitespace"""
        if not v or not v.strip():
            raise ValueError('Password cannot be empty')
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "username": "admin",
                "password": "SecurePassword123!",
                "csrf_token": "abc123..."
            }
        }

class ChangePasswordRequest(BaseModel):
    """Change password request validation"""
    old_password: str = Field(..., min_length=1, max_length=128, description="Current password")
    new_password: str = Field(..., min_length=12, max_length=128, description="New password")
    
    @validator('new_password')
    def validate_password_strength(cls, v):
        """Validate password meets complexity requirements"""
        if len(v) < 12:
            raise ValueError('Password must be at least 12 characters long')
        
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        
        # Check for common weak passwords
        common_weak = [
            'password123!', 'admin123456!', 'qwerty123456!', 
            '123456789012!', 'welcome123!', 'changeme123!'
        ]
        if v.lower() in common_weak:
            raise ValueError('Password is too common. Please choose a more unique password')
        
        return v
    
    @validator('new_password')
    def passwords_must_differ(cls, v, values):
        """Ensure new password is different from old password"""
        if 'old_password' in values and v == values['old_password']:
            raise ValueError('New password must be different from current password')
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "old_password": "OldPassword123!",
                "new_password": "NewSecurePassword456!"
            }
        }

class ThreatAnalysisRequest(BaseModel):
    """Threat analysis request validation"""
    input: str = Field(..., min_length=1, max_length=10000, description="Input to analyze")
    context: str = Field(default="general", max_length=50, description="Analysis context")
    
    @validator('context')
    def validate_context(cls, v):
        """Validate context is one of allowed values"""
        allowed_contexts = [
            'general', 'sql', 'html', 'filename', 'url', 
            'email', 'username', 'json', 'xml'
        ]
        if v not in allowed_contexts:
            raise ValueError(f'Context must be one of: {", ".join(allowed_contexts)}')
        return v
    
    @validator('input')
    def validate_input_not_empty(cls, v):
        """Ensure input is not empty or only whitespace"""
        if not v or not v.strip():
            raise ValueError('Input cannot be empty')
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "input": "SELECT * FROM users WHERE id=1",
                "context": "sql"
            }
        }

class UserCreateRequest(BaseModel):
    """User creation request validation"""
    username: str = Field(..., min_length=3, max_length=50, description="Username")
    password: str = Field(..., min_length=12, max_length=128, description="Password")
    email: Optional[EmailStr] = Field(None, description="Email address")
    role: str = Field(default="user", max_length=20, description="User role")
    
    @validator('username')
    def validate_username(cls, v):
        """Validate username format"""
        if not re.match(r'^[a-zA-Z0-9_.-]+$', v):
            raise ValueError('Username can only contain alphanumeric characters, dots, hyphens, and underscores')
        
        # Reserved usernames
        reserved = ['admin', 'root', 'system', 'administrator', 'superuser']
        if v.lower() in reserved:
            raise ValueError(f'Username "{v}" is reserved')
        
        return v.strip()
    
    @validator('role')
    def validate_role(cls, v):
        """Validate role is one of allowed values"""
        allowed_roles = ['user', 'admin', 'moderator', 'viewer']
        if v not in allowed_roles:
            raise ValueError(f'Role must be one of: {", ".join(allowed_roles)}')
        return v
    
    @validator('password')
    def validate_password_strength(cls, v):
        """Validate password meets complexity requirements"""
        if len(v) < 12:
            raise ValueError('Password must be at least 12 characters long')
        
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')
        
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "username": "johndoe",
                "password": "SecurePassword123!",
                "email": "john@example.com",
                "role": "user"
            }
        }

class FileUploadMetadata(BaseModel):
    """File upload metadata validation"""
    filename: str = Field(..., min_length=1, max_length=255, description="Filename")
    content_type: str = Field(..., max_length=100, description="Content type")
    size: int = Field(..., gt=0, le=10*1024*1024, description="File size in bytes (max 10MB)")
    
    @validator('filename')
    def validate_filename(cls, v):
        """Validate filename is safe"""
        # Remove path traversal attempts
        v = v.replace('..', '').replace('/', '').replace('\\', '')
        
        # Check for allowed extensions
        allowed_extensions = [
            '.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx',
            '.jpg', '.jpeg', '.png', '.gif', '.csv', '.json'
        ]
        
        if not any(v.lower().endswith(ext) for ext in allowed_extensions):
            raise ValueError(f'File extension not allowed. Allowed: {", ".join(allowed_extensions)}')
        
        # Check for dangerous patterns
        dangerous_patterns = [
            r'\.exe$', r'\.bat$', r'\.cmd$', r'\.sh$', r'\.ps1$',
            r'\.php$', r'\.jsp$', r'\.asp$', r'\.aspx$'
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError('Dangerous file type detected')
        
        return v
    
    @validator('content_type')
    def validate_content_type(cls, v):
        """Validate content type"""
        allowed_types = [
            'text/plain', 'application/pdf', 'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'image/jpeg', 'image/png', 'image/gif',
            'text/csv', 'application/json'
        ]
        
        if v not in allowed_types:
            raise ValueError(f'Content type not allowed: {v}')
        
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "filename": "document.pdf",
                "content_type": "application/pdf",
                "size": 1024000
            }
        }

class SearchRequest(BaseModel):
    """Search request validation"""
    query: str = Field(..., min_length=1, max_length=500, description="Search query")
    limit: int = Field(default=10, ge=1, le=100, description="Results limit")
    offset: int = Field(default=0, ge=0, description="Results offset")
    
    @validator('query')
    def validate_query(cls, v):
        """Validate search query"""
        # Remove excessive whitespace
        v = ' '.join(v.split())
        
        if not v:
            raise ValueError('Search query cannot be empty')
        
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "query": "security threats",
                "limit": 20,
                "offset": 0
            }
        }

class IPAddressRequest(BaseModel):
    """IP address validation"""
    ip_address: str = Field(..., max_length=45, description="IP address (IPv4 or IPv6)")
    
    @validator('ip_address')
    def validate_ip_address(cls, v):
        """Validate IP address format"""
        import ipaddress
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError('Invalid IP address format')
    
    class Config:
        schema_extra = {
            "example": {
                "ip_address": "192.168.1.1"
            }
        }

class UpdateStatsRequest(BaseModel):
    """Update stats request validation"""
    requests: Optional[int] = Field(None, ge=0, le=1000000, description="Requests increment")
    threats: Optional[int] = Field(None, ge=0, le=1000000, description="Threats increment")
    blocked: Optional[int] = Field(None, ge=0, le=1000000, description="Blocked increment")
    users: Optional[int] = Field(None, ge=0, le=1000000, description="Users increment")
    sessions: Optional[int] = Field(None, ge=0, le=1000000, description="Sessions increment")
    
    @validator('*', pre=True)
    def validate_numeric(cls, v):
        """Ensure all values are numeric"""
        if v is not None and not isinstance(v, (int, float)):
            raise ValueError('Value must be numeric')
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "requests": 1,
                "threats": 1,
                "blocked": 1
            }
        }

# Request size limit middleware helper
class RequestSizeValidator:
    """Validate request size"""
    
    @staticmethod
    def validate_size(content_length: int, max_size: int = 1024 * 1024) -> bool:
        """
        Validate request size
        
        Args:
            content_length: Content length in bytes
            max_size: Maximum allowed size (default 1MB)
        
        Returns:
            True if valid, raises ValueError if too large
        """
        if content_length > max_size:
            raise ValueError(f'Request too large: {content_length} bytes (max: {max_size} bytes)')
        return True
    
    @staticmethod
    def get_max_size_for_endpoint(endpoint: str) -> int:
        """
        Get maximum size for specific endpoint
        
        Args:
            endpoint: Endpoint path
        
        Returns:
            Maximum size in bytes
        """
        size_limits = {
            '/api/analyze': 10 * 1024,  # 10KB
            '/api/upload': 10 * 1024 * 1024,  # 10MB
            '/auth/login': 1024,  # 1KB
            '/auth/change-password': 1024,  # 1KB
            'default': 1024 * 1024  # 1MB
        }
        
        return size_limits.get(endpoint, size_limits['default'])
