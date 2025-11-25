"""
Enhanced Authentication System - V1.0 Security Hardening
Implements JWT rotation, MFA support, and advanced security features
"""
import os
import time
import json
import secrets
import hashlib
import base64
import re
from datetime import datetime, UTC, timedelta
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

try:
    import jwt as pyjwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

try:
    import pyotp
    MFA_AVAILABLE = True
except ImportError:
    MFA_AVAILABLE = False

@dataclass
class SecurityEvent:
    event_type: str
    user_id: str
    ip_address: str
    timestamp: datetime
    details: Dict[str, Any]
    risk_level: str = "low"

class EnhancedAuth:
    def __init__(self):
        # CRITICAL: JWT secrets must be set in environment variables for production
        self.secret_key = os.getenv("JWT_SECRET_KEY")
        self.refresh_secret = os.getenv("JWT_REFRESH_SECRET")
        
        if not self.secret_key:
            self.secret_key = self._generate_secure_key()
            print("\n" + "="*70)
            print("⚠️  SECURITY WARNING: JWT_SECRET_KEY not set!")
            print(f"Generated temporary key: {self.secret_key[:20]}...")
            print("Set JWT_SECRET_KEY environment variable for production!")
            print("="*70 + "\n")
        
        if not self.refresh_secret:
            self.refresh_secret = self._generate_secure_key()
            print("⚠️  SECURITY WARNING: JWT_REFRESH_SECRET not set!")
            print("Set JWT_REFRESH_SECRET environment variable for production!\n")
        
        self.algorithm = "HS256"
        self.access_token_expire_minutes = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
        self.refresh_token_expire_days = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
        
        # Security tracking
        self.failed_attempts = {}
        self.security_events = []
        self.blocked_ips = {}
        self.active_sessions = {}  # SECURITY FIX: Missing initialization
        
        # Rate limiting
        self.max_attempts = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
        self.lockout_duration = int(os.getenv("LOCKOUT_DURATION_MINUTES", "15"))
        
    def _generate_secure_key(self) -> str:
        """Generate cryptographically secure key"""
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    
    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """Validate password meets complexity requirements
        
        Requirements:
        - Minimum 12 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if len(password) < 12:
            return False, "Password must be at least 12 characters long"
        
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r'[0-9]', password):
            return False, "Password must contain at least one digit"
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'"\\|,.<>/?]', password):
            return False, "Password must contain at least one special character (!@#$%^&* etc.)"
        
        # Check for common weak passwords
        common_weak = ['password123', 'admin123456', 'qwerty123456', '123456789012']
        if password.lower() in common_weak:
            return False, "Password is too common. Please choose a more unique password"
        
        return True, "Password meets complexity requirements"
    
    def hash_password(self, password: str) -> str:
        """Enhanced password hashing with salt"""
        if BCRYPT_AVAILABLE:
            # Use bcrypt with higher cost factor for production
            salt = bcrypt.gensalt(rounds=12)
            return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
        else:
            # Fallback with PBKDF2
            salt = secrets.token_hex(32)
            hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 200000)
            return f"pbkdf2:{salt}:{hashed.hex()}"
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password with timing attack protection"""
        if not password or not hashed:
            # Perform dummy operation to prevent timing attacks
            self._dummy_hash_operation()
            return False
            
        try:
            if hashed.startswith("pbkdf2:"):
                _, salt, hash_hex = hashed.split(":", 2)
                expected = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 200000)
                return secrets.compare_digest(expected.hex(), hash_hex)
            elif BCRYPT_AVAILABLE:
                return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
            else:
                self._dummy_hash_operation()
                return False
        except Exception:
            self._dummy_hash_operation()
            return False
    
    def _dummy_hash_operation(self):
        """Perform dummy hash to prevent timing attacks"""
        dummy_password = "dummy_password_for_timing_protection"
        dummy_salt = "dummy_salt"
        hashlib.pbkdf2_hmac('sha256', dummy_password.encode(), dummy_salt.encode(), 200000)
    
    def create_tokens(self, user_id: str, role: str = "user", ip_address: str = None) -> Dict[str, str]:
        """Create access and refresh tokens"""
        now = datetime.now(UTC)
        session_id = secrets.token_urlsafe(32)
        
        # Access token (short-lived)
        access_payload = {
            "sub": user_id,
            "role": role,
            "session_id": session_id,
            "type": "access",
            "iat": now,
            "exp": now + timedelta(minutes=self.access_token_expire_minutes),
            "ip": ip_address
        }
        
        # Refresh token (long-lived)
        refresh_payload = {
            "sub": user_id,
            "session_id": session_id,
            "type": "refresh",
            "iat": now,
            "exp": now + timedelta(days=self.refresh_token_expire_days)
        }
        
        if JWT_AVAILABLE:
            access_token = pyjwt.encode(access_payload, self.secret_key, algorithm=self.algorithm)
            refresh_token = pyjwt.encode(refresh_payload, self.refresh_secret, algorithm=self.algorithm)
        else:
            access_token = self._create_simple_jwt(access_payload, self.secret_key)
            refresh_token = self._create_simple_jwt(refresh_payload, self.refresh_secret)
        
        # Store active session
        self.active_sessions[session_id] = {
            "user_id": user_id,
            "role": role,
            "ip_address": ip_address,
            "created_at": now,
            "last_activity": now
        }
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": self.access_token_expire_minutes * 60
        }
    
    def verify_token(self, token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
        """Verify and decode token with enhanced security"""
        try:
            secret = self.secret_key if token_type == "access" else self.refresh_secret
            
            if JWT_AVAILABLE:
                payload = pyjwt.decode(token, secret, algorithms=[self.algorithm])
            else:
                payload = self._verify_simple_jwt(token, secret)
                if not payload:
                    return None
            
            # Verify token type
            if payload.get("type") != token_type:
                return None
            
            # Check if session is still active
            session_id = payload.get("session_id")
            if session_id and session_id not in self.active_sessions:
                return None
            
            # Update last activity
            if session_id and session_id in self.active_sessions:
                self.active_sessions[session_id]["last_activity"] = datetime.now(UTC)
            
            return {
                "user_id": payload.get("sub"),
                "role": payload.get("role", "user"),
                "session_id": session_id,
                "ip_address": payload.get("ip")
            }
            
        except Exception:
            return None
    
    def refresh_access_token(self, refresh_token: str) -> Optional[Dict[str, str]]:
        """Create new access token from refresh token"""
        payload = self.verify_token(refresh_token, "refresh")
        if not payload:
            return None
        
        session_id = payload["session_id"]
        if session_id not in self.active_sessions:
            return None
        
        session = self.active_sessions[session_id]
        
        # Create new access token
        now = datetime.now(UTC)
        access_payload = {
            "sub": payload["user_id"],
            "role": session["role"],
            "session_id": session_id,
            "type": "access",
            "iat": now,
            "exp": now + timedelta(minutes=self.access_token_expire_minutes),
            "ip": session["ip_address"]
        }
        
        if JWT_AVAILABLE:
            access_token = pyjwt.encode(access_payload, self.secret_key, algorithm=self.algorithm)
        else:
            access_token = self._create_simple_jwt(access_payload, self.secret_key)
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": self.access_token_expire_minutes * 60
        }
    
    def revoke_session(self, session_id: str) -> bool:
        """Revoke a specific session"""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
            return True
        return False
    
    def revoke_all_sessions(self, user_id: str) -> int:
        """Revoke all sessions for a user"""
        revoked = 0
        sessions_to_remove = []
        
        for session_id, session in self.active_sessions.items():
            if session["user_id"] == user_id:
                sessions_to_remove.append(session_id)
                revoked += 1
        
        for session_id in sessions_to_remove:
            del self.active_sessions[session_id]
        
        return revoked
    
    def check_rate_limit(self, user_id: str, ip_address: str) -> bool:
        """Check if user/IP is rate limited"""
        # Check if IP is blocked and clean expired blocks
        if ip_address in self.blocked_ips:
            block_time = self.blocked_ips[ip_address]
            # Auto-unblock after 24 hours
            if time.time() - block_time > 86400:  # 24 hours
                del self.blocked_ips[ip_address]
                self.log_security_event("ip_auto_unblocked", user_id, ip_address, 
                                      {"reason": "24h_expiry"}, "low")
            else:
                return False
        
        key = f"{user_id}:{ip_address}"
        now = time.time()
        
        if key not in self.failed_attempts:
            return True
        
        attempts = self.failed_attempts[key]
        
        # Clean old attempts
        attempts["times"] = [t for t in attempts["times"] if now - t < self.lockout_duration * 60]
        
        if len(attempts["times"]) >= self.max_attempts:
            # Check if lockout period has passed
            if now - attempts["times"][0] < self.lockout_duration * 60:
                return False
            else:
                # Reset attempts after lockout
                del self.failed_attempts[key]
        
        return True
    
    def record_failed_attempt(self, user_id: str, ip_address: str):
        """Record failed login attempt"""
        key = f"{user_id}:{ip_address}"
        now = time.time()
        
        if key not in self.failed_attempts:
            self.failed_attempts[key] = {"times": [], "count": 0}
        
        self.failed_attempts[key]["times"].append(now)
        self.failed_attempts[key]["count"] += 1
        
        # Block IP after too many attempts (store with timestamp)
        if len(self.failed_attempts[key]["times"]) >= self.max_attempts:
            self.blocked_ips[ip_address] = time.time()  # Store block timestamp
            self.log_security_event("ip_blocked", user_id, ip_address, {
                "reason": "too_many_failed_attempts",
                "attempts": len(self.failed_attempts[key]["times"]),
                "unblock_at": time.time() + 86400  # 24 hours from now
            }, "high")
    
    def log_security_event(self, event_type: str, user_id: str, ip_address: str, 
                          details: Dict[str, Any], risk_level: str = "low"):
        """Log security event"""
        event = SecurityEvent(
            event_type=event_type,
            user_id=user_id,
            ip_address=ip_address,
            timestamp=datetime.now(UTC),
            details=details,
            risk_level=risk_level
        )
        
        self.security_events.append(event)
        
        # Keep only last 1000 events
        if len(self.security_events) > 1000:
            self.security_events = self.security_events[-1000:]
    
    def get_security_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent security events"""
        events = self.security_events[-limit:]
        return [
            {
                "event_type": event.event_type,
                "user_id": event.user_id,
                "ip_address": event.ip_address,
                "timestamp": event.timestamp.isoformat(),
                "details": event.details,
                "risk_level": event.risk_level
            }
            for event in events
        ]
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        now = datetime.now(UTC)
        expired_sessions = []
        
        for session_id, session in self.active_sessions.items():
            # Remove sessions inactive for more than 24 hours
            if (now - session["last_activity"]).total_seconds() > 86400:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.active_sessions[session_id]
        
        return len(expired_sessions)
    
    def _create_simple_jwt(self, payload: Dict[str, Any], secret: str) -> str:
        """Create simple JWT without library"""
        import hmac
        
        header = {"alg": "HS256", "typ": "JWT"}
        
        # Convert datetime objects to timestamps
        for key, value in payload.items():
            if isinstance(value, datetime):
                payload[key] = int(value.timestamp())
        
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        
        message = f"{header_b64}.{payload_b64}"
        signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
        
        return f"{header_b64}.{payload_b64}.{signature}"
    
    def _verify_simple_jwt(self, token: str, secret: str) -> Optional[Dict[str, Any]]:
        """Verify simple JWT without library"""
        try:
            import hmac
            
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            header_b64, payload_b64, signature = parts
            
            # Verify signature
            message = f"{header_b64}.{payload_b64}"
            expected_sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
            
            if not secrets.compare_digest(signature, expected_sig):
                return None
            
            # Decode payload
            payload_json = base64.urlsafe_b64decode(payload_b64 + '==').decode()
            payload = json.loads(payload_json)
            
            # Check expiration
            if payload.get('exp', 0) < time.time():
                return None
            
            return payload
            
        except Exception:
            return None

# MFA Support
class MFAManager:
    def __init__(self):
        self.user_secrets = {}
    
    def generate_secret(self, user_id: str) -> str:
        """Generate TOTP secret for user"""
        if not MFA_AVAILABLE:
            raise RuntimeError("MFA not available - install pyotp")
        
        secret = pyotp.random_base32()
        self.user_secrets[user_id] = secret
        return secret
    
    def get_qr_code_url(self, user_id: str, issuer: str = "Infinite AI Security") -> str:
        """Get QR code URL for TOTP setup"""
        if user_id not in self.user_secrets:
            raise ValueError("No secret found for user")
        
        secret = self.user_secrets[user_id]
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=user_id,
            issuer_name=issuer
        )
    
    def verify_totp(self, user_id: str, token: str) -> bool:
        """Verify TOTP token"""
        if user_id not in self.user_secrets:
            return False
        
        secret = self.user_secrets[user_id]
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
    
    def is_mfa_enabled(self, user_id: str) -> bool:
        """Check if MFA is enabled for user"""
        return user_id in self.user_secrets

# Global instances
enhanced_auth = EnhancedAuth()
mfa_manager = MFAManager()