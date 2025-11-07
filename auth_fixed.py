"""
Fixed Authentication - Simple but secure
"""
import os
import secrets
import hashlib
import time
import base64
import json
from datetime import datetime, UTC, timedelta

class SimpleSecureAuth:
    def __init__(self):
        self.secret_key = os.getenv("JWT_SECRET_KEY", "default-secret-key-change-this")
    
    def hash_password(self, password: str) -> str:
        """Simple secure password hashing"""
        salt = secrets.token_hex(16)
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"{salt}:{hashed.hex()}"
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password"""
        try:
            salt, hash_hex = hashed.split(':')
            expected = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return expected.hex() == hash_hex
        except:
            return False
    
    def create_token(self, username: str, role: str = "user") -> str:
        """Create secure token"""
        payload = {
            "username": username,
            "role": role,
            "exp": int(time.time()) + 86400,  # 24 hours
            "iat": int(time.time())
        }
        
        # Simple but secure token
        token_data = json.dumps(payload)
        signature = hashlib.hmac.new(
            self.secret_key.encode(),
            token_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        full_token = f"{base64.b64encode(token_data.encode()).decode()}.{signature}"
        return full_token
    
    def verify_token(self, token: str) -> dict:
        """Verify token"""
        try:
            token_part, signature = token.split('.')
            token_data = base64.b64decode(token_part.encode()).decode()
            
            # Verify signature
            expected_sig = hashlib.hmac.new(
                self.secret_key.encode(),
                token_data.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if signature != expected_sig:
                return None
            
            payload = json.loads(token_data)
            
            # Check expiry
            if payload.get('exp', 0) < time.time():
                return None
            
            return payload
        except:
            return None

# Global instance
auth = SimpleSecureAuth()

def hash_password(password: str) -> str:
    return auth.hash_password(password)

def verify_password(password: str, hashed: str) -> bool:
    return auth.verify_password(password, hashed)

def create_token(username: str, role: str = "user") -> str:
    return auth.create_token(username, role)

def verify_token(token: str) -> dict:
    return auth.verify_token(token)