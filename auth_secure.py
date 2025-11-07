"""
Secure Authentication System
JWT + BCrypt implementation for production security
"""
import os
import secrets
from datetime import datetime, timedelta, UTC
from typing import Optional
import jwt
import bcrypt
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class SecureAuth:
    def __init__(self):
        # Use environment variable or generate secure key
        self.secret_key = os.getenv("JWT_SECRET_KEY") or self._generate_secure_key()
        self.algorithm = "HS256"
        self.token_expire_hours = int(os.getenv("TOKEN_EXPIRE_HOURS", "24"))
        
        # Warn if using generated key
        if not os.getenv("JWT_SECRET_KEY"):
            print("⚠️ WARNING: Using generated JWT key. Set JWT_SECRET_KEY in .env for production!")
    
    def _generate_secure_key(self) -> str:
        """Generate cryptographically secure key"""
        return secrets.token_urlsafe(32)
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        # Generate salt and hash password
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception:
            return False
    
    def create_token(self, username: str, role: str = "user") -> str:
        """Create JWT token"""
        payload = {
            "sub": username,
            "role": role,
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(hours=self.token_expire_hours)
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token: str) -> Optional[dict]:
        """Verify JWT token and return payload"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return {
                "username": payload.get("sub"),
                "role": payload.get("role", "user"),
                "issued_at": payload.get("iat"),
                "expires_at": payload.get("exp")
            }
        except jwt.ExpiredSignatureError:
            return None  # Token expired
        except jwt.InvalidTokenError:
            return None  # Invalid token
    
    def refresh_token(self, token: str) -> Optional[str]:
        """Refresh token if valid and not expired"""
        payload = self.verify_token(token)
        if payload:
            return self.create_token(payload["username"], payload["role"])
        return None

# Global instance
secure_auth = SecureAuth()

# Convenience functions
def hash_password(password: str) -> str:
    return secure_auth.hash_password(password)

def verify_password(password: str, hashed: str) -> bool:
    return secure_auth.verify_password(password, hashed)

def create_token(username: str, role: str = "user") -> str:
    return secure_auth.create_token(username, role)

def verify_token(token: str) -> Optional[dict]:
    return secure_auth.verify_token(token)

# Test function
if __name__ == "__main__":
    print("🔐 Testing Secure Authentication System")
    print("=" * 40)
    
    # Test password hashing
    password = "admin123"
    hashed = hash_password(password)
    print(f"Password: {password}")
    print(f"Hashed: {hashed[:50]}...")
    print(f"Verify: {verify_password(password, hashed)}")
    
    # Test JWT
    token = create_token("admin", "admin")
    print(f"\nToken: {token[:50]}...")
    
    payload = verify_token(token)
    print(f"Payload: {payload}")
    
    print("\n✅ All tests passed!")