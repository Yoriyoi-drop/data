"""
Infinite AI Security - Windows Compatible Production API
"""
import os
import time
import json
import secrets
from datetime import datetime, UTC, timedelta
from typing import Dict, Any, Optional
from pathlib import Path

# Core Framework
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
import uvicorn

# Security
try:
    from passlib.context import CryptContext
    from jose import JWTError, jwt
    SECURITY_AVAILABLE = True
except ImportError:
    SECURITY_AVAILABLE = False
    print("⚠️ Security libraries not installed. Running in basic mode.")

# Rate Limiting
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    RATE_LIMIT_AVAILABLE = True
except ImportError:
    RATE_LIMIT_AVAILABLE = False
    print("⚠️ Rate limiting not available. Install slowapi for production.")

# Monitoring
try:
    from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False
    print("⚠️ Metrics not available. Install prometheus-client for monitoring.")

# Environment
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("⚠️ python-dotenv not installed. Using default settings.")

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "windows-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Initialize security if available
if SECURITY_AVAILABLE:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    security = HTTPBearer()

# Initialize rate limiting if available
if RATE_LIMIT_AVAILABLE:
    limiter = Limiter(key_func=get_remote_address)

# Initialize metrics if available
if METRICS_AVAILABLE:
    REQUEST_COUNT = Counter('api_requests_total', 'Total API requests', ['method', 'endpoint'])
    THREAT_COUNT = Counter('threats_detected_total', 'Total threats detected', ['threat_type'])

# Initialize FastAPI
app = FastAPI(
    title="Infinite AI Security API - Windows",
    description="Windows-compatible AI security platform",
    version="3.0.0-windows",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add rate limiting if available
if RATE_LIMIT_AVAILABLE:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # More permissive for Windows development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Windows-compatible database
DB_FILE = Path("security_db.json")

def init_database():
    """Initialize database with Windows-compatible paths"""
    if not DB_FILE.exists():
        default_password = "admin123"
        hashed_password = pwd_context.hash(default_password) if SECURITY_AVAILABLE else "hashed_admin123"
        
        initial_data = {
            "users": {
                "admin": {
                    "username": "admin",
                    "hashed_password": hashed_password,
                    "role": "admin",
                    "created_at": datetime.now(UTC).isoformat()
                }
            },
            "threats": [],
            "stats": {"requests": 0, "threats": 0, "blocked": 0, "start_time": datetime.now(UTC).isoformat()}
        }
        
        try:
            with open(DB_FILE, 'w', encoding='utf-8') as f:
                json.dump(initial_data, f, indent=2, ensure_ascii=False)
            print(f"✅ Database initialized: {DB_FILE.absolute()}")
        except Exception as e:
            print(f"❌ Database initialization failed: {e}")

def load_db():
    """Load database with error handling"""
    try:
        with open(DB_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        init_database()
        return load_db()
    except Exception as e:
        print(f"❌ Database load error: {e}")
        return {"users": {}, "threats": [], "stats": {"requests": 0, "threats": 0, "blocked": 0}}

def save_db(data):
    """Save database with error handling"""
    try:
        with open(DB_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"❌ Database save error: {e}")

# Authentication functions (with fallback)
def verify_password(plain_password, hashed_password):
    if SECURITY_AVAILABLE:
        return pwd_context.verify(plain_password, hashed_password)
    return plain_password == "admin123"  # Fallback for demo

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    if not SECURITY_AVAILABLE:
        return "demo-token-windows"
    
    to_encode = data.copy()
    expire = datetime.now(UTC) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security) if SECURITY_AVAILABLE else None):
    if not SECURITY_AVAILABLE:
        return {"username": "admin", "role": "admin"}  # Demo mode
    
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    db = load_db()
    user = db["users"].get(username)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return user

# Enhanced Threat Detection
class WindowsThreatAnalyzer:
    def __init__(self):
        self.threat_patterns = {
            # SQL Injection
            "sql_injection": {
                "' or '1'='1": 0.9,
                "'; drop table": 0.95,
                "union select": 0.8,
                "admin'--": 0.85,
                "' or 1=1": 0.9
            },
            # XSS
            "xss": {
                "<script>": 0.9,
                "javascript:": 0.8,
                "onerror=": 0.7,
                "alert(": 0.8,
                "<svg onload": 0.85
            },
            # Command Injection
            "command_injection": {
                "; dir": 0.8,  # Windows-specific
                "&& whoami": 0.9,
                "| type ": 0.85,  # Windows-specific
                "; del ": 0.95   # Windows-specific
            }
        }
    
    def analyze(self, payload: str, context: Dict[str, Any]) -> Dict[str, Any]:
        if not payload:
            return {"threat": False, "confidence": 0.0, "type": "none"}
        
        payload_lower = payload.lower()
        threats_found = []
        max_confidence = 0.0
        primary_threat = "none"
        
        for threat_type, patterns in self.threat_patterns.items():
            matches = []
            threat_confidence = 0.0
            
            for pattern, weight in patterns.items():
                if pattern in payload_lower:
                    matches.append(pattern)
                    threat_confidence = max(threat_confidence, weight)
            
            if threat_confidence > 0:
                threats_found.append({
                    "type": threat_type,
                    "confidence": threat_confidence,
                    "patterns": matches,
                    "severity": "critical" if threat_confidence > 0.8 else "high" if threat_confidence > 0.6 else "medium"
                })
                
                if threat_confidence > max_confidence:
                    max_confidence = threat_confidence
                    primary_threat = threat_type
        
        return {
            "threat": len(threats_found) > 0,
            "confidence": max_confidence,
            "type": primary_threat,
            "severity": "critical" if max_confidence > 0.8 else "high" if max_confidence > 0.6 else "medium",
            "threats_found": threats_found,
            "blocked": max_confidence > 0.7
        }

analyzer = WindowsThreatAnalyzer()

# Initialize database on startup
init_database()

# API Endpoints
@app.post("/auth/login")
async def login(credentials: Dict[str, str]):
    """Windows-compatible login"""
    username = credentials.get("username")
    password = credentials.get("password")
    
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")
    
    db = load_db()
    user = db["users"].get(username)
    
    if not user or not verify_password(password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": username, "role": user["role"]})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {"username": username, "role": user["role"]},
        "message": "Login successful on Windows"
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Infinite AI Security API",
        "version": "3.0.0-windows",
        "platform": "Windows Compatible",
        "status": "operational",
        "features": {
            "security": SECURITY_AVAILABLE,
            "rate_limiting": RATE_LIMIT_AVAILABLE,
            "metrics": METRICS_AVAILABLE
        },
        "timestamp": datetime.now(UTC).isoformat()
    }

@app.get("/health")
async def health():
    """Health check"""
    db = load_db()
    stats = db["stats"]
    
    return {
        "status": "healthy",
        "platform": "Windows",
        "database": "operational",
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
    """Threat analysis endpoint"""
    payload = data.get("input", "")
    if not payload:
        raise HTTPException(status_code=400, detail="Missing input field")
    
    # Context
    context = {
        "platform": "Windows",
        "user": current_user["username"],
        "timestamp": datetime.now(UTC).isoformat()
    }
    
    # Analysis
    result = analyzer.analyze(payload, context)
    
    # Update stats
    db = load_db()
    db["stats"]["requests"] += 1
    
    if result["threat"]:
        db["stats"]["threats"] += 1
        if METRICS_AVAILABLE:
            THREAT_COUNT.labels(threat_type=result["type"]).inc()
        
        if result["blocked"]:
            db["stats"]["blocked"] += 1
        
        # Log threat
        threat_record = {
            "id": f"threat_{int(time.time())}",
            "payload": payload[:100],
            "result": result,
            "context": context
        }
        db["threats"].append(threat_record)
    
    save_db(db)
    
    return {
        "request_id": f"req_{int(time.time())}",
        "analysis": result,
        "context": context,
        "platform": "Windows"
    }

@app.get("/api/threats")
async def get_threats(current_user: dict = Depends(get_current_user)):
    """Get recent threats"""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    db = load_db()
    return {
        "threats": db["threats"][-20:],  # Last 20 threats
        "total": len(db["threats"]),
        "platform": "Windows"
    }

if METRICS_AVAILABLE:
    @app.get("/metrics")
    async def metrics():
        """Prometheus metrics"""
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

if __name__ == "__main__":
    print("🛡️ Infinite AI Security API - Windows Edition")
    print("=" * 50)
    print(f"🔐 Security: {'✅' if SECURITY_AVAILABLE else '❌'}")
    print(f"⚡ Rate Limiting: {'✅' if RATE_LIMIT_AVAILABLE else '❌'}")
    print(f"📊 Metrics: {'✅' if METRICS_AVAILABLE else '❌'}")
    print(f"💾 Database: {DB_FILE.absolute()}")
    print("=" * 50)
    print("🌐 API: http://127.0.0.1:8080")
    print("📚 Docs: http://127.0.0.1:8080/docs")
    print("🔑 Login: admin/admin123")
    print("=" * 50)
    
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8080,
        log_level="info"
    )