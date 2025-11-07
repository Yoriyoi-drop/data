"""
Infinite AI Security - Secure Production API
Phase 1: Stabilization with proper JWT + BCrypt
"""
import time
from datetime import datetime, UTC
from typing import Dict, Any
from pathlib import Path
import json

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse
import uvicorn

# Import secure authentication
from auth_secure import hash_password, verify_password, create_token, verify_token

app = FastAPI(title="Infinite AI Security - Secure", version="4.1.0")
security = HTTPBearer()

# Secure database
DB_FILE = Path("security_secure.json")

def init_secure_database():
    """Initialize database with secure password hashing"""
    if not DB_FILE.exists():
        # Create admin with secure password hash
        admin_password_hash = hash_password("admin123")
        
        initial_data = {
            "users": {
                "admin": {
                    "username": "admin",
                    "password_hash": admin_password_hash,
                    "role": "admin",
                    "created_at": datetime.now(UTC).isoformat()
                }
            },
            "threats": [],
            "stats": {"requests": 0, "threats": 0, "blocked": 0}
        }
        
        with open(DB_FILE, 'w') as f:
            json.dump(initial_data, f, indent=2)
        print("✅ Secure database initialized")

def load_db():
    with open(DB_FILE, 'r') as f:
        return json.load(f)

def save_db(data):
    with open(DB_FILE, 'w') as f:
        json.dump(data, f, indent=2)

# Secure authentication dependency
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Secure token validation"""
    payload = verify_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    db = load_db()
    user = db["users"].get(payload["username"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return {"username": payload["username"], "role": payload["role"]}

# Threat analyzer (same as before)
class ThreatAnalyzer:
    def __init__(self):
        self.patterns = {
            "sql_injection": {
                "' or '1'='1": 0.95, "'; drop table": 0.98, "union select": 0.85,
                "admin'--": 0.90, "' or 1=1": 0.95
            },
            "xss": {
                "<script>": 0.95, "javascript:": 0.85, "onerror=": 0.80,
                "alert(": 0.90, "<svg onload": 0.90
            },
            "command_injection": {
                "; dir": 0.85, "&& whoami": 0.90, "| type": 0.80,
                "; del": 0.95, "powershell": 0.85
            }
        }
    
    def analyze(self, payload: str) -> Dict[str, Any]:
        if not payload:
            return {"threat": False, "confidence": 0.0, "type": "none"}
        
        payload_lower = payload.lower()
        threats = []
        max_confidence = 0.0
        primary_threat = "none"
        
        for threat_type, patterns in self.patterns.items():
            matches = []
            threat_confidence = 0.0
            
            for pattern, weight in patterns.items():
                if pattern in payload_lower:
                    matches.append(pattern)
                    threat_confidence = max(threat_confidence, weight)
            
            if threat_confidence > 0:
                threats.append({
                    "type": threat_type,
                    "confidence": threat_confidence,
                    "patterns": matches
                })
                
                if threat_confidence > max_confidence:
                    max_confidence = threat_confidence
                    primary_threat = threat_type
        
        return {
            "threat": len(threats) > 0,
            "confidence": max_confidence,
            "type": primary_threat,
            "severity": "critical" if max_confidence > 0.8 else "high" if max_confidence > 0.6 else "medium",
            "blocked": max_confidence > 0.7,
            "risk_score": int(max_confidence * 100)
        }

analyzer = ThreatAnalyzer()

# Initialize secure database
init_secure_database()

# API Endpoints
@app.post("/auth/login")
async def secure_login(credentials: Dict[str, str]):
    """Secure login with proper JWT"""
    username = credentials.get("username")
    password = credentials.get("password")
    
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")
    
    db = load_db()
    user = db["users"].get(username)
    
    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create secure JWT token
    token = create_token(username, user["role"])
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"username": username, "role": user["role"]},
        "message": "Secure login successful"
    }

@app.get("/")
async def root():
    return {
        "service": "Infinite AI Security - Secure",
        "version": "4.1.0",
        "security": "JWT + BCrypt Enabled",
        "status": "operational",
        "timestamp": datetime.now(UTC).isoformat()
    }

@app.get("/health")
async def health():
    db = load_db()
    stats = db["stats"]
    
    return {
        "status": "healthy",
        "security": "enhanced",
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
    """Secure threat analysis"""
    payload = data.get("input", "")
    if not payload:
        raise HTTPException(status_code=400, detail="Missing input")
    
    result = analyzer.analyze(payload)
    
    # Update database
    db = load_db()
    db["stats"]["requests"] += 1
    
    if result["threat"]:
        db["stats"]["threats"] += 1
        
        if result["blocked"]:
            db["stats"]["blocked"] += 1
        
        # Log threat with secure user info
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
        "security": "enhanced",
        "timestamp": datetime.now(UTC).isoformat()
    }

@app.get("/api/threats")
async def get_threats(current_user: dict = Depends(get_current_user)):
    """Get threats (admin only)"""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    db = load_db()
    return {
        "threats": db["threats"][-20:],
        "total": len(db["threats"]),
        "security": "enhanced"
    }

@app.get("/api/security-status")
async def security_status(current_user: dict = Depends(get_current_user)):
    """Security status endpoint"""
    return {
        "authentication": "JWT + BCrypt",
        "password_hashing": "BCrypt",
        "token_system": "PyJWT",
        "security_level": "Enhanced",
        "phase": "1 - Stabilization Complete",
        "user": current_user["username"],
        "timestamp": datetime.now(UTC).isoformat()
    }

if __name__ == "__main__":
    print("🔐 INFINITE AI SECURITY - SECURE VERSION")
    print("=" * 50)
    print("✅ JWT Authentication: PyJWT")
    print("✅ Password Hashing: BCrypt")
    print("✅ Environment Variables: Loaded")
    print("✅ Phase 1: Stabilization Complete")
    print("=" * 50)
    print("🌐 API: http://127.0.0.1:8001")
    print("🔑 Login: admin/admin123")
    print("🛡️ Security: Enhanced")
    print("=" * 50)
    
    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="info")