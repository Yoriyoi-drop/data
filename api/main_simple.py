"""
Infinite AI Security - Simple Windows Compatible API
No bcrypt dependency issues
"""
import os
import time
import json
import hashlib
import secrets
from datetime import datetime, UTC, timedelta
from typing import Dict, Any, Optional
from pathlib import Path

# Core Framework
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

# Simple password hashing (SHA256 + salt)
def hash_password(password: str, salt: str = None) -> str:
    """Simple password hashing with SHA256"""
    if salt is None:
        salt = secrets.token_hex(16)
    
    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}:{password_hash}"

def verify_password(password: str, hashed: str) -> bool:
    """Verify password against hash"""
    try:
        salt, password_hash = hashed.split(':')
        return hashlib.sha256((password + salt).encode()).hexdigest() == password_hash
    except:
        return password == hashed  # Fallback for plain text

# Simple JWT (base64 encoded for demo)
def create_token(username: str) -> str:
    """Create simple token"""
    import base64
    token_data = f"{username}:{int(time.time())}"
    return base64.b64encode(token_data.encode()).decode()

def verify_token(token: str) -> Optional[str]:
    """Verify token and return username"""
    try:
        import base64
        token_data = base64.b64decode(token.encode()).decode()
        username, timestamp = token_data.split(':')
        
        # Check if token is not older than 1 hour
        if int(time.time()) - int(timestamp) < 3600:
            return username
    except:
        pass
    return None

# Initialize FastAPI
app = FastAPI(
    title="Infinite AI Security API - Simple",
    description="Windows-compatible AI security platform (no bcrypt)",
    version="3.0.0-simple",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Database
DB_FILE = Path("security_simple.json")

def init_database():
    """Initialize simple database"""
    if not DB_FILE.exists():
        initial_data = {
            "users": {
                "admin": {
                    "username": "admin",
                    "password_hash": hash_password("admin123"),
                    "role": "admin",
                    "created_at": datetime.now(UTC).isoformat()
                }
            },
            "threats": [],
            "stats": {"requests": 0, "threats": 0, "blocked": 0}
        }
        
        with open(DB_FILE, 'w', encoding='utf-8') as f:
            json.dump(initial_data, f, indent=2)
        print(f"✅ Simple database initialized: {DB_FILE}")

def load_db():
    """Load database"""
    try:
        with open(DB_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        init_database()
        return load_db()

def save_db(data):
    """Save database"""
    try:
        with open(DB_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"❌ Save error: {e}")

# Authentication
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from token"""
    username = verify_token(credentials.credentials)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    db = load_db()
    user = db["users"].get(username)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return user

# Threat Detection
class SimpleThreatAnalyzer:
    def __init__(self):
        self.patterns = {
            "sql_injection": [
                "' or '1'='1", "'; drop table", "union select", 
                "admin'--", "' or 1=1", "select * from"
            ],
            "xss": [
                "<script>", "javascript:", "onerror=", 
                "alert(", "<svg onload", "document.cookie"
            ],
            "command_injection": [
                "; dir", "&& whoami", "| type", "; del", 
                "cmd.exe", "powershell", "net user"
            ]
        }
    
    def analyze(self, payload: str) -> Dict[str, Any]:
        """Analyze payload for threats"""
        if not payload:
            return {"threat": False, "confidence": 0.0, "type": "none"}
        
        payload_lower = payload.lower()
        threats = []
        max_confidence = 0.0
        primary_threat = "none"
        
        for threat_type, patterns in self.patterns.items():
            matches = [p for p in patterns if p in payload_lower]
            if matches:
                confidence = min(0.95, len(matches) * 0.3 + 0.5)
                threats.append({
                    "type": threat_type,
                    "confidence": confidence,
                    "patterns": matches
                })
                
                if confidence > max_confidence:
                    max_confidence = confidence
                    primary_threat = threat_type
        
        return {
            "threat": len(threats) > 0,
            "confidence": max_confidence,
            "type": primary_threat,
            "severity": "critical" if max_confidence > 0.8 else "high" if max_confidence > 0.6 else "medium",
            "threats_found": threats,
            "blocked": max_confidence > 0.7
        }

analyzer = SimpleThreatAnalyzer()

# Initialize on startup
init_database()

# API Endpoints
@app.post("/auth/login")
async def login(credentials: Dict[str, str]):
    """Simple login"""
    username = credentials.get("username")
    password = credentials.get("password")
    
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")
    
    db = load_db()
    user = db["users"].get(username)
    
    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(username)
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"username": username, "role": user["role"]},
        "message": "Login successful"
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Infinite AI Security API",
        "version": "3.0.0-simple",
        "platform": "Windows Compatible (No bcrypt)",
        "status": "operational",
        "timestamp": datetime.now(UTC).isoformat()
    }

@app.get("/health")
async def health():
    """Health check"""
    db = load_db()
    stats = db["stats"]
    
    return {
        "status": "healthy",
        "platform": "Windows Simple",
        "requests": stats["requests"],
        "threats": stats["threats"],
        "blocked": stats["blocked"],
        "timestamp": datetime.now(UTC).isoformat()
    }

@app.post("/api/analyze")
async def analyze_threat(
    data: Dict[str, Any],
    current_user: dict = Depends(get_current_user)
):
    """Threat analysis"""
    payload = data.get("input", "")
    if not payload:
        raise HTTPException(status_code=400, detail="Missing input")
    
    # Analysis
    result = analyzer.analyze(payload)
    
    # Update stats
    db = load_db()
    db["stats"]["requests"] += 1
    
    if result["threat"]:
        db["stats"]["threats"] += 1
        
        if result["blocked"]:
            db["stats"]["blocked"] += 1
        
        # Log threat
        threat_record = {
            "id": f"threat_{int(time.time())}",
            "payload": payload[:100],
            "result": result,
            "user": current_user["username"],
            "timestamp": datetime.now(UTC).isoformat()
        }
        db["threats"].append(threat_record)
    
    save_db(db)
    
    return {
        "request_id": f"req_{int(time.time())}",
        "analysis": result,
        "user": current_user["username"],
        "timestamp": datetime.now(UTC).isoformat()
    }

@app.get("/api/threats")
async def get_threats(current_user: dict = Depends(get_current_user)):
    """Get recent threats"""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    db = load_db()
    return {
        "threats": db["threats"][-20:],
        "total": len(db["threats"]),
        "timestamp": datetime.now(UTC).isoformat()
    }

@app.get("/api/stats")
async def get_stats(current_user: dict = Depends(get_current_user)):
    """Get system statistics"""
    db = load_db()
    return {
        "stats": db["stats"],
        "total_threats": len(db["threats"]),
        "total_users": len(db["users"]),
        "timestamp": datetime.now(UTC).isoformat()
    }

if __name__ == "__main__":
    print("🛡️ Infinite AI Security API - Simple Edition")
    print("=" * 50)
    print("✅ No bcrypt dependency issues")
    print("✅ Windows compatible")
    print("✅ Simple authentication")
    print("✅ Threat detection active")
    print("=" * 50)
    print("🌐 API: http://127.0.0.1:8000")
    print("📚 Docs: http://127.0.0.1:8000/docs")
    print("🔑 Login: admin/admin123")
    print("=" * 50)
    
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        log_level="info"
    )