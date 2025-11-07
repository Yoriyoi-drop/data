"""
Infinite AI Security - Production Ready API
Implements all critical security fixes recommended by AI consultant team
"""
import os
import sys
import time
import sqlite3
from datetime import datetime, UTC
from typing import Dict, Any, Optional
from pathlib import Path
from contextlib import contextmanager

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Import our secure authentication
from auth_secure_fixed import auth, rate_limiter, login_rate_limiter, normalize_input

app = FastAPI(
    title="Infinite AI Security - Production Ready",
    version="4.3.0",
    description="Enterprise-grade AI security platform with enhanced authentication"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# Enhanced Database with proper security
class ProductionDatabase:
    def __init__(self, db_path="production_security.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database with enhanced security schema"""
        with sqlite3.connect(self.db_path) as conn:
            # Users table with security features
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    last_login TEXT,
                    failed_attempts INTEGER DEFAULT 0,
                    locked_until TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            ''')
            
            # Threats table with detailed analysis
            conn.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_id TEXT UNIQUE NOT NULL,
                    payload TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    severity TEXT NOT NULL,
                    blocked INTEGER NOT NULL,
                    patterns_matched TEXT,
                    username TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at TEXT NOT NULL
                )
            ''')
            
            # Sessions table for token management
            conn.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_hash TEXT UNIQUE NOT NULL,
                    username TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_used TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT
                )
            ''')
            
            # Statistics with time series
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
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def create_user(self, username: str, password_hash: str, role: str = "user"):
        with self.get_connection() as conn:
            now = datetime.now(UTC).isoformat()
            conn.execute('''
                INSERT INTO users (username, password_hash, role, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, password_hash, role, now, now))
            conn.commit()
    
    def get_user(self, username: str):
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def update_failed_attempts(self, username: str, attempts: int):
        with self.get_connection() as conn:
            conn.execute('''
                UPDATE users SET failed_attempts = ?, updated_at = ?
                WHERE username = ?
            ''', (attempts, datetime.now(UTC).isoformat(), username))
            conn.commit()
    
    def lock_user(self, username: str, locked_until: str):
        with self.get_connection() as conn:
            conn.execute('''
                UPDATE users SET locked_until = ?, updated_at = ?
                WHERE username = ?
            ''', (locked_until, datetime.now(UTC).isoformat(), username))
            conn.commit()
    
    def log_threat(self, threat_id: str, payload: str, result: dict, username: str, ip: str = None):
        import hashlib
        payload_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]
        
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO threats (threat_id, payload, payload_hash, threat_type, 
                                   confidence, severity, blocked, username, ip_address, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat_id, payload[:500], payload_hash, result.get('type', 'unknown'),
                result.get('confidence', 0.0), result.get('severity', 'low'),
                1 if result.get('blocked', False) else 0, username, ip,
                datetime.now(UTC).isoformat()
            ))
            conn.commit()
    
    def update_stats(self, requests=0, threats=0, blocked=0):
        with self.get_connection() as conn:
            conn.execute('''
                UPDATE stats SET 
                    requests = requests + ?,
                    threats = threats + ?,
                    blocked = blocked + ?,
                    updated_at = ?
                WHERE id = 1
            ''', (requests, threats, blocked, datetime.now(UTC).isoformat()))
            conn.commit()
    
    def get_stats(self):
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM stats WHERE id = 1')
            row = cursor.fetchone()
            return dict(row) if row else {}

# Enhanced Threat Analyzer with input normalization
class EnhancedThreatAnalyzer:
    def __init__(self):
        self.patterns = {
            "sql_injection": {
                "' or '1'='1": 0.95, "'; drop table": 0.98, "union select": 0.85,
                "admin'--": 0.90, "' or 1=1": 0.95, "select * from": 0.80,
                "insert into": 0.85, "delete from": 0.90
            },
            "xss": {
                "<script>": 0.95, "javascript:": 0.85, "onerror=": 0.80,
                "alert(": 0.90, "<svg onload": 0.90, "document.cookie": 0.85,
                "<iframe": 0.80, "eval(": 0.85
            },
            "command_injection": {
                "; dir": 0.85, "&& whoami": 0.90, "| type": 0.80,
                "; del": 0.95, "powershell": 0.85, "cmd.exe": 0.90,
                "bash": 0.80, "sh -c": 0.85
            }
        }
    
    def analyze(self, payload: str) -> Dict[str, Any]:
        if not payload:
            return {"threat": False, "confidence": 0.0, "type": "none"}
        
        # Normalize input to prevent bypass (as recommended)
        normalized_payload = normalize_input(payload)
        
        max_confidence = 0.0
        primary_threat = "none"
        matched_patterns = []
        
        for threat_type, patterns in self.patterns.items():
            for pattern, weight in patterns.items():
                if pattern in normalized_payload:
                    matched_patterns.append(pattern)
                    if weight > max_confidence:
                        max_confidence = weight
                        primary_threat = threat_type
        
        return {
            "threat": max_confidence > 0,
            "confidence": max_confidence,
            "type": primary_threat,
            "severity": "critical" if max_confidence > 0.8 else "high" if max_confidence > 0.6 else "medium",
            "blocked": max_confidence > 0.7,
            "risk_score": int(max_confidence * 100),
            "patterns_matched": matched_patterns
        }

# Initialize components
db = ProductionDatabase()
analyzer = EnhancedThreatAnalyzer()

# Initialize admin user with secure password
def init_admin():
    try:
        admin_hash = auth.hash_password("admin123")
        db.create_user("admin", admin_hash, "admin")
        print("[OK] Admin user created with secure hash")
    except:
        print("[OK] Admin user already exists")

init_admin()

# Enhanced authentication with rate limiting
async def get_current_user(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)):
    # Check rate limit
    client_ip = request.client.host
    if not rate_limiter.is_allowed(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    # Verify token
    payload = auth.verify_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    # Check user exists
    user = db.get_user(payload["username"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return {"username": payload["username"], "role": payload.get("role", "user")}

# API Endpoints with enhanced security
@app.post("/auth/login")
async def secure_login(request: Request, credentials: Dict[str, str]):
    """Secure login with rate limiting and account lockout"""
    client_ip = request.client.host
    
    # Check login rate limit
    if not login_rate_limiter.is_allowed(client_ip):
        raise HTTPException(status_code=429, detail="Too many login attempts")
    
    username = credentials.get("username")
    password = credentials.get("password")
    
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")
    
    user = db.get_user(username)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Check if account is locked
    if user.get('locked_until'):
        locked_until = datetime.fromisoformat(user['locked_until'])
        if datetime.now(UTC) < locked_until:
            raise HTTPException(status_code=423, detail="Account locked")
    
    # Verify password
    if not auth.verify_password(password, user["password_hash"]):
        # Increment failed attempts
        failed_attempts = user.get('failed_attempts', 0) + 1
        if failed_attempts >= 5:
            # Lock account for 15 minutes
            from datetime import timedelta
            locked_until = datetime.now(UTC) + timedelta(minutes=15)
            db.lock_user(username, locked_until.isoformat())
        else:
            db.update_failed_attempts(username, failed_attempts)
        
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Reset failed attempts on successful login
    db.update_failed_attempts(username, 0)
    
    # Create secure token
    token = auth.create_token(username, user["role"])
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"username": username, "role": user["role"]},
        "security_info": auth.get_security_info(),
        "message": "Production-ready login successful"
    }

@app.get("/")
async def root():
    return {
        "service": "Infinite AI Security - Production Ready",
        "version": "4.3.0",
        "security": auth.get_security_info(),
        "status": "operational",
        "timestamp": datetime.now(UTC).isoformat()
    }

@app.get("/health")
async def health():
    stats = db.get_stats()
    return {
        "status": "healthy",
        "security": auth.get_security_info(),
        "database": "SQLite Production",
        "requests": stats.get("requests", 0),
        "threats": stats.get("threats", 0),
        "blocked": stats.get("blocked", 0),
        "timestamp": datetime.now(UTC).isoformat()
    }

@app.post("/api/analyze")
async def analyze_threat(
    request: Request,
    data: Dict[str, Any],
    current_user: dict = Depends(get_current_user)
):
    """Enhanced threat analysis with normalization and rate limiting"""
    payload = data.get("input", "")
    if not payload:
        raise HTTPException(status_code=400, detail="Missing input")
    
    # Analyze threat with enhanced detection
    result = analyzer.analyze(payload)
    
    # Update statistics
    db.update_stats(requests=1)
    
    if result["threat"]:
        db.update_stats(
            threats=1,
            blocked=1 if result["blocked"] else 0
        )
        
        # Log threat with IP address
        threat_id = f"threat_{int(time.time())}_{current_user['username']}"
        db.log_threat(threat_id, payload, result, current_user["username"], request.client.host)
    
    return {
        "request_id": f"req_{int(time.time())}",
        "analysis": result,
        "user": current_user["username"],
        "security_level": "production",
        "timestamp": datetime.now(UTC).isoformat()
    }

@app.get("/api/security-status")
async def security_status(current_user: dict = Depends(get_current_user)):
    """Get comprehensive security status"""
    return {
        "authentication": auth.get_security_info(),
        "rate_limiting": {
            "enabled": True,
            "api_limit": "100/minute",
            "login_limit": "10/minute"
        },
        "database": "SQLite with enhanced schema",
        "threat_detection": "Enhanced with input normalization",
        "security_level": "Production Ready",
        "user": current_user["username"],
        "timestamp": datetime.now(UTC).isoformat()
    }

if __name__ == "__main__":
    print("[SECURE] INFINITE AI SECURITY - PRODUCTION READY")
    print("=" * 50)
    print("[OK] Enhanced Authentication: bcrypt + PyJWT")
    print("[OK] Rate Limiting: Enabled")
    print("[OK] Input Normalization: Active")
    print("[OK] SQLite Database: Production Schema")
    print("[OK] Account Lockout: 5 attempts / 15 min")
    print("=" * 50)
    print("[API] http://127.0.0.1:8003")
    print("[LOGIN] admin/admin123")
    print("[SECURITY] Production Ready")
    print("=" * 50)
    
    uvicorn.run(app, host="127.0.0.1", port=8003, log_level="info")