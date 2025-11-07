"""
Infinite AI Security - Secure Authentication System
Fixed implementation with bcrypt + PyJWT as recommended by AI consultant team
"""
import os
import time
import secrets
from datetime import datetime, timedelta, UTC
from typing import Optional

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    import hashlib

try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    import base64
    import json

class SecureAuth:
    def __init__(self):
        self.secret_key = os.getenv("JWT_SECRET_KEY", "infinite-ai-security-secret-key-2024-production")
        self.algorithm = "HS256"
        self.access_token_expire_minutes = 30
    
    def hash_password(self, password: str) -> str:
        """Secure password hashing with bcrypt (recommended) or PBKDF2 fallback"""
        if BCRYPT_AVAILABLE:
            # Preferred: bcrypt with automatic salt generation
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
            return hashed_password.decode('utf-8')
        else:
            # Fallback: PBKDF2 with SHA256 (better than plain SHA256)
            salt = secrets.token_hex(16)
            hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return f"{salt}:{hashed.hex()}"
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        if BCRYPT_AVAILABLE and not ':' in hashed_password:
            # bcrypt format
            try:
                return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
            except:
                return False
        else:
            # PBKDF2 format (salt:hash)
            try:
                salt, hash_hex = hashed_password.split(':')
                expected = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
                return expected.hex() == hash_hex
            except:
                return False
    
    def create_token(self, username: str, role: str = "user") -> str:
        """Create secure JWT token"""
        if JWT_AVAILABLE:
            # Preferred: PyJWT with proper signature
            expire = datetime.now(UTC) + timedelta(minutes=self.access_token_expire_minutes)
            to_encode = {
                "sub": username,
                "role": role,
                "exp": expire,
                "iat": datetime.now(UTC),
                "iss": "infinite-ai-security"
            }
            encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
            return encoded_jwt
        else:
            # Fallback: Custom JWT-like token with HMAC signature
            payload = {
                "username": username,
                "role": role,
                "exp": int(time.time()) + (self.access_token_expire_minutes * 60),
                "iat": int(time.time())
            }
            
            header = {"alg": "HS256", "typ": "JWT"}
            header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
            
            # Create HMAC signature
            import hmac
            message = f"{header_b64}.{payload_b64}"
            signature = hmac.new(
                self.secret_key.encode(),
                message.encode(),
                hashlib.sha256
            ).hexdigest()
            
            return f"{header_b64}.{payload_b64}.{signature}"
    
    def verify_token(self, token: str) -> Optional[dict]:
        """Verify JWT token and return payload"""
        if JWT_AVAILABLE:
            # Preferred: PyJWT verification
            try:
                payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
                return {
                    "username": payload.get("sub"),
                    "role": payload.get("role", "user"),
                    "exp": payload.get("exp"),
                    "iat": payload.get("iat")
                }
            except jwt.ExpiredSignatureError:
                return None
            except jwt.InvalidTokenError:
                return None
        else:
            # Fallback: Custom verification
            try:
                parts = token.split('.')
                if len(parts) != 3:
                    return None
                
                header_b64, payload_b64, signature = parts
                
                # Verify signature
                import hmac
                message = f"{header_b64}.{payload_b64}"
                expected_sig = hmac.new(
                    self.secret_key.encode(),
                    message.encode(),
                    hashlib.sha256
                ).hexdigest()
                
                if signature != expected_sig:
                    return None
                
                # Decode payload
                payload_json = base64.urlsafe_b64decode(payload_b64 + '==').decode()
                payload = json.loads(payload_json)
                
                # Check expiry
                if payload.get('exp', 0) < time.time():
                    return None
                
                return payload
            except:
                return None
    
    def get_security_info(self) -> dict:
        """Get current security configuration info"""
        return {
            "password_hashing": "bcrypt" if BCRYPT_AVAILABLE else "PBKDF2-SHA256",
            "token_system": "PyJWT" if JWT_AVAILABLE else "Custom-HMAC",
            "token_expiry_minutes": self.access_token_expire_minutes,
            "algorithm": self.algorithm,
            "security_level": "Production" if (BCRYPT_AVAILABLE and JWT_AVAILABLE) else "Enhanced"
        }

# Input normalization for threat detection (as recommended)
def normalize_input(payload: str) -> str:
    """Normalize input to prevent bypass attempts"""
    import urllib.parse
    
    # Decode URL encoding multiple times
    for _ in range(3):
        try:
            payload = urllib.parse.unquote(payload)
        except:
            break
    
    # Convert to lowercase for case-insensitive matching
    return payload.lower()

# Rate limiter implementation (no longer future enhancement)
class RateLimiter:
    def __init__(self, max_requests: int = 100, window: int = 60):
        self.max_requests = max_requests
        self.window = window
        self.requests = {}  # {user_id: [timestamp1, timestamp2, ...]}
    
    def is_allowed(self, user_id: str) -> bool:
        """Check if user is within rate limit"""
        now = time.time()
        
        # Get user's request history
        user_requests = self.requests.get(user_id, [])
        
        # Remove old requests outside window
        user_requests = [req_time for req_time in user_requests if now - req_time < self.window]
        
        # Check if under limit
        if len(user_requests) < self.max_requests:
            # Add current request
            user_requests.append(now)
            self.requests[user_id] = user_requests
            return True
        
        return False
    
    def get_remaining_requests(self, user_id: str) -> int:
        """Get remaining requests for user"""
        now = time.time()
        user_requests = self.requests.get(user_id, [])
        user_requests = [req_time for req_time in user_requests if now - req_time < self.window]
        return max(0, self.max_requests - len(user_requests))
    
    def reset_user_limit(self, user_id: str):
        """Reset rate limit for specific user (admin function)"""
        if user_id in self.requests:
            del self.requests[user_id]

# Global instances
auth = SecureAuth()
rate_limiter = RateLimiter(max_requests=100, window=60)  # 100 requests per minute
login_rate_limiter = RateLimiter(max_requests=10, window=60)  # 10 login attempts per minute

if __name__ == "__main__":
    # Test the secure authentication
    print("[SECURE] AUTHENTICATION TEST")
    print("=" * 40)
    
    # Test password hashing
    password = "admin123"
    hashed = auth.hash_password(password)
    print(f"Password: {password}")
    print(f"Hashed: {hashed[:50]}...")
    print(f"Verify: {auth.verify_password(password, hashed)}")
    
    # Test token creation
    token = auth.create_token("admin", "admin")
    print(f"Token: {token[:50]}...")
    
    # Test token verification
    payload = auth.verify_token(token)
    print(f"Payload: {payload}")
    
    # Security info
    security_info = auth.get_security_info()
    print(f"Security: {security_info}")
    
    # Test rate limiting
    print(f"Rate limit test: {rate_limiter.is_allowed('test_user')}")
    print(f"Remaining: {rate_limiter.get_remaining_requests('test_user')}")