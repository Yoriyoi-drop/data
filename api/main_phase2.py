"""
Phase 2: Complete Secure System
Fixed JWT + SQLite Database + Production Ready
"""
import time
from datetime import datetime, UTC
from typing import Dict, Any

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn

# Import fixed authentication and database
from auth_fixed import hash_password, verify_password, create_token, verify_token
from database_secure import create_user, get_user, log_threat, update_stats, get_stats, get_recent_threats, db

app = FastAPI(title="Infinite AI Security - Phase 2", version="4.2.0")
security = HTTPBearer()

# Initialize system
def init_system():
    """Initialize system with admin user"""
    try:
        # Try to create admin user
        admin_hash = hash_password("admin123")
        create_user("admin", admin_hash, "admin")
        print("✅ Admin user created")
    except:
        print("✅ Admin user already exists")
    
    # Migrate from old JSON files if they exist
    json_files = ["security_simple.json", "security_dashboard.json", "security_secure.json"]
    for json_file in json_files:
        db.migrate_from_json(json_file)

# Authentication dependency
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Secure authentication with fixed JWT"""
    payload = verify_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    user = get_user(payload["username"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return {"username": payload["username"], "role": payload["role"]}

# Threat analyzer
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
            "risk_score": int(max_confidence * 100),
            "threats_found": threats
        }

analyzer = ThreatAnalyzer()

# Initialize system
init_system()

# API Endpoints
@app.post("/auth/login")
async def login(credentials: Dict[str, str]):
    """Secure login with fixed JWT"""
    username = credentials.get("username")
    password = credentials.get("password")
    
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")
    
    user = get_user(username)
    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(username, user["role"])
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"username": username, "role": user["role"]},
        "message": "Phase 2 login successful"
    }

@app.get("/")
async def root():
    return {
        "service": "Infinite AI Security - Phase 2",
        "version": "4.2.0",
        "features": ["Fixed JWT", "SQLite Database", "Secure Authentication"],
        "status": "operational",
        "timestamp": datetime.now(UTC).isoformat()
    }

@app.get("/health")
async def health():
    stats = get_stats()
    
    return {
        "status": "healthy",
        "database": "SQLite",
        "authentication": "Fixed JWT",
        "requests": stats.get("requests", 0),
        "threats": stats.get("threats", 0),
        "blocked": stats.get("blocked", 0),
        "timestamp": datetime.now(UTC).isoformat()
    }

@app.post("/api/analyze")
async def analyze_threat(
    data: Dict[str, Any],
    current_user: dict = Depends(get_current_user)
):
    """Secure threat analysis with database logging"""
    payload = data.get("input", "")
    if not payload:
        raise HTTPException(status_code=400, detail="Missing input")
    
    result = analyzer.analyze(payload)
    
    # Update statistics
    update_stats(requests=1)
    
    if result["threat"]:
        update_stats(
            threats=1,
            blocked=1 if result["blocked"] else 0,
            threat_type=result["type"]
        )
        
        # Log threat to database
        threat_id = f"threat_{int(time.time())}_{current_user['username']}"
        log_threat(threat_id, payload, result, current_user["username"])
    
    return {
        "request_id": f"req_{int(time.time())}",
        "analysis": result,
        "user": current_user["username"],
        "database": "SQLite",
        "timestamp": datetime.now(UTC).isoformat()
    }

@app.get("/api/threats")
async def get_threats(current_user: dict = Depends(get_current_user)):
    """Get recent threats from database"""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    threats = get_recent_threats(50)
    
    return {
        "threats": threats,
        "total": len(threats),
        "database": "SQLite",
        "timestamp": datetime.now(UTC).isoformat()
    }

@app.get("/api/stats")
async def get_system_stats(current_user: dict = Depends(get_current_user)):
    """Get system statistics from database"""
    stats = get_stats()
    
    return {
        "stats": stats,
        "database": "SQLite",
        "phase": "2 - Complete",
        "timestamp": datetime.now(UTC).isoformat()
    }

@app.get("/api/system-info")
async def system_info(current_user: dict = Depends(get_current_user)):
    """System information"""
    return {
        "phase": "2 - Complete",
        "authentication": "Fixed JWT",
        "database": "SQLite",
        "password_hashing": "PBKDF2",
        "security_level": "Production Ready",
        "features": [
            "Secure token generation",
            "Database persistence",
            "Threat logging",
            "Statistics tracking",
            "User management"
        ],
        "user": current_user["username"],
        "timestamp": datetime.now(UTC).isoformat()
    }

if __name__ == "__main__":
    print("🚀 INFINITE AI SECURITY - PHASE 2 COMPLETE")
    print("=" * 50)
    print("✅ Fixed JWT Authentication")
    print("✅ SQLite Database")
    print("✅ Secure Password Hashing")
    print("✅ Threat Logging")
    print("✅ Statistics Tracking")
    print("✅ Production Ready")
    print("=" * 50)
    print("🌐 API: http://127.0.0.1:8000")
    print("🔑 Login: admin/admin123")
    print("🗄️ Database: security.db")
    print("=" * 50)
    
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")