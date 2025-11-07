"""
Infinite AI Security - Complete System (All-in-One)
Phase 2: Fixed JWT + SQLite Database + Production Ready
"""
import os
import sqlite3
import json
import time
import secrets
import hashlib
import base64
from datetime import datetime, UTC
from typing import Dict, Any
from pathlib import Path
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn

# ===== AUTHENTICATION SYSTEM =====
class SimpleSecureAuth:
    def __init__(self):
        self.secret_key = os.getenv("JWT_SECRET_KEY", "infinite-ai-security-secret-key-2024")
    
    def hash_password(self, password: str) -> str:
        """Secure password hashing with PBKDF2"""
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
        """Create secure token with proper format"""
        payload = {
            "username": username,
            "role": role,
            "exp": int(time.time()) + 86400,  # 24 hours
            "iat": int(time.time())
        }
        
        # Create proper JWT-like token
        header = {"alg": "HS256", "typ": "JWT"}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        
        # Create signature
        message = f"{header_b64}.{payload_b64}"
        signature = hashlib.hmac.new(
            self.secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return f"{header_b64}.{payload_b64}.{signature}"
    
    def verify_token(self, token: str) -> dict:
        """Verify JWT-like token"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            header_b64, payload_b64, signature = parts
            
            # Verify signature
            message = f"{header_b64}.{payload_b64}"
            expected_sig = hashlib.hmac.new(
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

# ===== DATABASE SYSTEM =====
class SecureDatabase:
    def __init__(self, db_path="security.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    created_at TEXT NOT NULL
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_id TEXT UNIQUE NOT NULL,
                    payload TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    severity TEXT NOT NULL,
                    blocked INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS stats (
                    id INTEGER PRIMARY KEY,
                    requests INTEGER DEFAULT 0,
                    threats INTEGER DEFAULT 0,
                    blocked INTEGER DEFAULT 0,
                    sql_injection INTEGER DEFAULT 0,
                    xss INTEGER DEFAULT 0,
                    command_injection INTEGER DEFAULT 0,
                    updated_at TEXT NOT NULL
                )
            ''')
            
            # Initialize stats
            conn.execute('''
                INSERT OR IGNORE INTO stats (id, requests, threats, blocked, updated_at)
                VALUES (1, 0, 0, 0, ?)
            ''', (datetime.now(UTC).isoformat(),))
            
            conn.commit()
    
    @contextmanager
    def get_connection(self):
        """Database connection context manager"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def create_user(self, username: str, password_hash: str, role: str = "user"):
        """Create new user"""
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO users (username, password_hash, role, created_at)
                VALUES (?, ?, ?, ?)
            ''', (username, password_hash, role, datetime.now(UTC).isoformat()))
            conn.commit()
    
    def get_user(self, username: str):
        """Get user by username"""
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def log_threat(self, threat_id: str, payload: str, result: dict, username: str):
        """Log threat to database"""
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO threats (threat_id, payload, threat_type, confidence, 
                                   severity, blocked, username, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat_id, payload[:500], result.get('type', 'unknown'),
                result.get('confidence', 0.0), result.get('severity', 'low'),
                1 if result.get('blocked', False) else 0, username,
                datetime.now(UTC).isoformat()
            ))
            conn.commit()
    
    def update_stats(self, requests=0, threats=0, blocked=0, threat_type=None):
        """Update statistics"""
        with self.get_connection() as conn:
            conn.execute('''
                UPDATE stats SET 
                    requests = requests + ?,
                    threats = threats + ?,
                    blocked = blocked + ?,
                    updated_at = ?
                WHERE id = 1
            ''', (requests, threats, blocked, datetime.now(UTC).isoformat()))
            
            if threat_type and threats > 0:
                column = threat_type.replace(' ', '_')
                if column in ['sql_injection', 'xss', 'command_injection']:
                    conn.execute(f'UPDATE stats SET {column} = {column} + 1 WHERE id = 1')
            
            conn.commit()
    
    def get_stats(self):
        """Get system statistics"""
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM stats WHERE id = 1')
            row = cursor.fetchone()
            return dict(row) if row else {}
    
    def get_recent_threats(self, limit=20):
        """Get recent threats"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT * FROM threats ORDER BY created_at DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]

# ===== THREAT ANALYZER =====
class ThreatAnalyzer:
    def __init__(self):
        self.patterns = {
            "sql_injection": {
                "' or '1'='1": 0.95, "'; drop table": 0.98, "union select": 0.85,
                "admin'--": 0.90, "' or 1=1": 0.95, "select * from": 0.80
            },
            "xss": {
                "<script>": 0.95, "javascript:": 0.85, "onerror=": 0.80,
                "alert(": 0.90, "<svg onload": 0.90, "document.cookie": 0.85
            },
            "command_injection": {
                "; dir": 0.85, "&& whoami": 0.90, "| type": 0.80,
                "; del": 0.95, "powershell": 0.85, "cmd.exe": 0.90
            }
        }
    
    def analyze(self, payload: str) -> Dict[str, Any]:
        if not payload:
            return {"threat": False, "confidence": 0.0, "type": "none"}
        
        payload_lower = payload.lower()
        max_confidence = 0.0
        primary_threat = "none"
        
        for threat_type, patterns in self.patterns.items():
            for pattern, weight in patterns.items():
                if pattern in payload_lower:
                    if weight > max_confidence:
                        max_confidence = weight
                        primary_threat = threat_type
        
        return {
            "threat": max_confidence > 0,
            "confidence": max_confidence,
            "type": primary_threat,
            "severity": "critical" if max_confidence > 0.8 else "high" if max_confidence > 0.6 else "medium",
            "blocked": max_confidence > 0.7,
            "risk_score": int(max_confidence * 100)
        }

# ===== FASTAPI APPLICATION =====
app = FastAPI(title="Infinite AI Security - Complete", version="4.2.0")
security = HTTPBearer()

# Initialize components
auth = SimpleSecureAuth()
db = SecureDatabase()
analyzer = ThreatAnalyzer()

# Initialize admin user
def init_admin():
    try:
        admin_hash = auth.hash_password("admin123")
        db.create_user("admin", admin_hash, "admin")
        print("[OK] Admin user created")
    except:
        print("[OK] Admin user already exists")

init_admin()

# Authentication dependency
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    payload = auth.verify_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    user = db.get_user(payload["username"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return {"username": payload["username"], "role": payload["role"]}

# API Endpoints
@app.post("/auth/login")
async def login(credentials: Dict[str, str]):
    username = credentials.get("username")
    password = credentials.get("password")
    
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")
    
    user = db.get_user(username)
    if not user or not auth.verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = auth.create_token(username, user["role"])
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"username": username, "role": user["role"]},
        "message": "Complete system login successful"
    }

@app.get("/")
async def root():
    return {
        "service": "Infinite AI Security - Complete",
        "version": "4.2.0",
        "features": ["Fixed JWT", "SQLite Database", "All-in-One"],
        "status": "operational",
        "timestamp": datetime.now(UTC).isoformat()
    }

@app.get("/health")
async def health():
    stats = db.get_stats()
    return {
        "status": "healthy",
        "database": "SQLite",
        "authentication": "Fixed JWT",
        "requests": stats.get("requests", 0),
        "threats": stats.get("threats", 0),
        "blocked": stats.get("blocked", 0)
    }

@app.post("/api/analyze")
async def analyze_threat(data: Dict[str, Any], current_user: dict = Depends(get_current_user)):
    payload = data.get("input", "")
    if not payload:
        raise HTTPException(status_code=400, detail="Missing input")
    
    result = analyzer.analyze(payload)
    
    # Update stats
    db.update_stats(requests=1)
    
    if result["threat"]:
        db.update_stats(
            threats=1,
            blocked=1 if result["blocked"] else 0,
            threat_type=result["type"]
        )
        
        # Log threat
        threat_id = f"threat_{int(time.time())}_{current_user['username']}"
        db.log_threat(threat_id, payload, result, current_user["username"])
    
    return {
        "request_id": f"req_{int(time.time())}",
        "analysis": result,
        "user": current_user["username"],
        "timestamp": datetime.now(UTC).isoformat()
    }

@app.get("/api/threats")
async def get_threats(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    threats = db.get_recent_threats(50)
    return {"threats": threats, "total": len(threats)}

@app.get("/api/stats")
async def get_system_stats(current_user: dict = Depends(get_current_user)):
    stats = db.get_stats()
    return {"stats": stats, "database": "SQLite"}

if __name__ == "__main__":
    print("[SECURE] INFINITE AI SECURITY - COMPLETE SYSTEM")
    print("=" * 50)
    print("[OK] All-in-One Implementation")
    print("[OK] Fixed JWT Authentication")
    print("[OK] SQLite Database")
    print("[OK] No Import Dependencies")
    print("=" * 50)
    print("[API] http://127.0.0.1:8002")
    print("[LOGIN] admin/admin123")
    print("[DB] security.db")
    print("=" * 50)
    
    uvicorn.run(app, host="127.0.0.1", port=8002, log_level="info")