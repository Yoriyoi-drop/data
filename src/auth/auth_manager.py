"""
Authentication Manager - Enterprise Grade Security
"""
import hashlib
import secrets
import time
import json
import base64
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

class AuthManager:
    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or "infinite-ai-security-2024"
        self.token_expiry = 3600  # 1 hour
        self.failed_attempts = {}
        self.locked_accounts = {}
        self.max_attempts = 5
        self.lockout_duration = 900  # 15 minutes
    
    def hash_password(self, password: str) -> str:
        """Hash password with salt"""
        salt = secrets.token_hex(16)
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}:{hashed.hex()}"
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        try:
            salt, hash_hex = hashed.split(':')
            expected = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return expected.hex() == hash_hex
        except:
            return False
    
    def create_token(self, username: str, role: str = "user") -> str:
        """Create JWT-like token"""
        payload = {
            "username": username,
            "role": role,
            "exp": int(time.time()) + self.token_expiry,
            "iat": int(time.time())
        }
        
        header = {"alg": "HS256", "typ": "JWT"}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        
        import hmac
        message = f"{header_b64}.{payload_b64}"
        signature = hmac.new(
            self.secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return f"{header_b64}.{payload_b64}.{signature}"
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode token"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            header_b64, payload_b64, signature = parts
            
            import hmac
            message = f"{header_b64}.{payload_b64}"
            expected_sig = hmac.new(
                self.secret_key.encode(),
                message.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if signature != expected_sig:
                return None
            
            payload_json = base64.urlsafe_b64decode(payload_b64 + '==').decode()
            payload = json.loads(payload_json)
            
            if payload.get('exp', 0) < time.time():
                return None
            
            return payload
        except:
            return None
    
    def is_account_locked(self, username: str) -> bool:
        """Check if account is locked"""
        if username in self.locked_accounts:
            lock_time = self.locked_accounts[username]
            if time.time() - lock_time < self.lockout_duration:
                return True
            else:
                del self.locked_accounts[username]
                self.failed_attempts[username] = 0
        return False
    
    def record_failed_attempt(self, username: str):
        """Record failed login attempt"""
        self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1
        
        if self.failed_attempts[username] >= self.max_attempts:
            self.locked_accounts[username] = time.time()
    
    def authenticate(self, username: str, password: str, password_hash: str) -> Dict[str, Any]:
        """Authenticate user with security checks"""
        if self.is_account_locked(username):
            return {
                "success": False,
                "error": "Account locked due to too many failed attempts",
                "locked_until": time.time() + self.lockout_duration
            }
        
        if self.verify_password(password, password_hash):
            # Reset failed attempts on successful login
            self.failed_attempts[username] = 0
            if username in self.locked_accounts:
                del self.locked_accounts[username]
            
            token = self.create_token(username, "admin" if username == "admin" else "user")
            
            return {
                "success": True,
                "token": token,
                "user": {"username": username, "role": "admin" if username == "admin" else "user"}
            }
        else:
            self.record_failed_attempt(username)
            return {
                "success": False,
                "error": "Invalid credentials",
                "attempts_remaining": max(0, self.max_attempts - self.failed_attempts.get(username, 0))
            }
    
    def get_security_info(self) -> Dict[str, Any]:
        """Get security statistics"""
        return {
            "failed_attempts": len(self.failed_attempts),
            "locked_accounts": len(self.locked_accounts),
            "max_attempts": self.max_attempts,
            "lockout_duration": self.lockout_duration
        }