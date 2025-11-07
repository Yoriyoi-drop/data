#!/usr/bin/env python3
"""
Secure FastAPI Main - Production-ready AI Security Platform
"""
from fastapi import FastAPI, HTTPException, WebSocket, Depends, status, Request
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import asyncio
import json
import logging
import os
import sys
import secrets
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional
from pydantic import BaseModel, validator, Field
import aiohttp
import time
from contextlib import asynccontextmanager

# Security imports
from cryptography.fernet import Fernet
import jwt
from passlib.context import CryptContext

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Conditional imports with fallbacks
try:
    from api.metrics import (
        track_response_time, record_threat, update_agent_count, 
        update_labyrinth_stats, get_metrics
    )
except ImportError:
    def track_response_time(name):
        def decorator(func): return func
        return decorator
    def record_threat(t_type, severity): pass
    def update_agent_count(count): pass
    def update_labyrinth_stats(nodes, intruders): pass
    def get_metrics(): return "# No metrics available"

from ai_hub.hub_core import hub
from agents.gpt5_agent import GPT5Agent
from agents.base_agent import MockAgent

# Security Configuration
class SecurityConfig:
    SECRET_KEY = os.getenv('SECRET_KEY', Fernet.generate_key().decode())
    API_KEY = os.getenv('API_KEY', secrets.token_hex(32))
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRATION = 3600  # 1 hour
    MAX_REQUEST_SIZE = 1024 * 1024  # 1MB
    RATE_LIMIT_REQUESTS = 100
    RATE_LIMIT_WINDOW = 60  # seconds

# Security models
class ThreatData(BaseModel):
    type: str = Field(..., min_length=1, max_length=50)
    severity: str = Field(..., regex="^(low|medium|high|critical)$")
    source: str = Field(..., min_length=7, max_length=45)  # IP address
    timestamp: Optional[str] = None
    details: Optional[str] = Field(None, max_length=500)
    
    @validator('type')
    def validate_type(cls, v):
        allowed_types = [
            'SQL Injection', 'XSS Attack', 'DDoS', 'Brute Force', 
            'Malware', 'Path Traversal', 'Command Injection'
        ]
        if v not in allowed_types:
            raise ValueError(f'Invalid threat type. Allowed: {allowed_types}')
        return v

class EmergencyRequest(BaseModel):
    level: str = Field(..., regex="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    reason: Optional[str] = Field(None, max_length=200)

# Security utilities
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

class RateLimiter:
    def __init__(self):
        self.requests = {}
    
    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        if client_ip not in self.requests:
            self.requests[client_ip] = []
        
        # Clean old requests
        self.requests[client_ip] = [
            req_time for req_time in self.requests[client_ip] 
            if now - req_time < SecurityConfig.RATE_LIMIT_WINDOW
        ]
        
        # Check rate limit
        if len(self.requests[client_ip]) >= SecurityConfig.RATE_LIMIT_REQUESTS:
            return False
        
        self.requests[client_ip].append(now)
        return True

rate_limiter = RateLimiter()

# Startup/shutdown context
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logging.info("🚀 Starting Secure AI Security Platform")
    
    # Register agents
    await hub.register_agent("gpt5", GPT5Agent())
    await hub.register_agent("claude", MockAgent("Claude", "claude-3"))
    await hub.register_agent("grok", MockAgent("Grok", "grok-1"))
    await hub.register_agent("mistral", MockAgent("Mistral", "mistral-large"))
    
    # Start monitoring
    asyncio.create_task(hub.start_monitoring())
    
    # Connect to external services
    await connect_to_services()
    
    logging.info("✅ All systems online and secure")
    yield
    
    # Shutdown
    logging.info("🛑 Shutting down secure platform")
    await cleanup_resources()

async def connect_to_services():
    """Connect to Go scanner and Rust labyrinth"""
    try:
        # Test Go scanner connection
        async with aiohttp.ClientSession() as session:
            async with session.get('http://localhost:8080/health', timeout=5) as resp:
                if resp.status == 200:
                    logging.info("✅ Go Scanner connected")
                else:
                    logging.warning("⚠️ Go Scanner not responding")
    except Exception as e:
        logging.warning(f"⚠️ Go Scanner connection failed: {e}")
    
    try:
        # Test Rust labyrinth connection
        async with aiohttp.ClientSession() as session:
            async with session.get('http://localhost:3030/health', timeout=5) as resp:
                if resp.status == 200:
                    logging.info("✅ Rust Labyrinth connected")
                else:
                    logging.warning("⚠️ Rust Labyrinth not responding")
    except Exception as e:
        logging.warning(f"⚠️ Rust Labyrinth connection failed: {e}")

async def cleanup_resources():
    """Cleanup resources on shutdown"""
    # Close WebSocket connections
    for client in connected_clients:
        try:
            await client.close()
        except:
            pass

# FastAPI app with security
app = FastAPI(
    title="Infinite AI Security Platform",
    version="2.0.0",
    description="Secure multi-language AI security platform",
    docs_url=None,  # Disable in production
    redoc_url=None,
    lifespan=lifespan
)

# Security middleware
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# Security functions
async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token"""
    try:
        payload = jwt.decode(
            credentials.credentials, 
            SecurityConfig.SECRET_KEY, 
            algorithms=[SecurityConfig.JWT_ALGORITHM]
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def check_rate_limit(request: Request):
    """Check rate limiting"""
    client_ip = request.client.host
    if not rate_limiter.is_allowed(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    return client_ip

def get_client_ip(request: Request) -> str:
    """Get real client IP"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host

# Secure global state
connected_clients: List[WebSocket] = []
threat_log: List[Dict] = []
MAX_THREAT_LOG = 1000
blocked_ips = set()

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

# API Routes
@app.get("/")
async def root():
    return {
        "message": "Infinite AI Security Platform", 
        "status": "secure",
        "version": "2.0.0"
    }

@app.post("/api/auth/token")
async def get_token(api_key: str):
    """Get JWT token with API key"""
    if not secrets.compare_digest(api_key, SecurityConfig.API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    payload = {
        "exp": datetime.utcnow().timestamp() + SecurityConfig.JWT_EXPIRATION,
        "iat": datetime.utcnow().timestamp(),
        "scope": "api_access"
    }
    
    token = jwt.encode(payload, SecurityConfig.SECRET_KEY, algorithm=SecurityConfig.JWT_ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "expires_in": SecurityConfig.JWT_EXPIRATION}

@app.post("/api/threats/analyze")
@track_response_time("analyze_threat")
async def analyze_threat(
    threat_data: ThreatData,
    request: Request,
    token: dict = Depends(verify_token),
    client_ip: str = Depends(check_rate_limit)
):
    """Secure threat analysis with multi-service integration"""
    try:
        # Check if IP is blocked
        if client_ip in blocked_ips:
            raise HTTPException(status_code=403, detail="IP blocked due to suspicious activity")
        
        # Add timestamp if not provided
        if not threat_data.timestamp:
            threat_data.timestamp = datetime.now(timezone.utc).isoformat()
        
        # Create secure task
        task = {
            "type": "threat_analysis",
            "data": threat_data.dict(),
            "timestamp": threat_data.timestamp,
            "request_id": secrets.token_hex(16),
            "client_ip_hash": hashlib.sha256(client_ip.encode()).hexdigest()[:16]
        }
        
        # Analyze with AI agents
        ai_result = await hub.distribute_task(task)
        
        # Send to Go scanner for additional analysis
        go_result = await analyze_with_go_scanner(threat_data.dict())
        
        # Send to Rust labyrinth if high threat
        if threat_data.severity in ['high', 'critical']:
            await send_to_labyrinth(client_ip, threat_data.severity)
        
        # Combine results
        result = {
            "ai_analysis": ai_result,
            "scanner_analysis": go_result,
            "threat_level": threat_data.severity,
            "actions_taken": []
        }
        
        # Log securely
        if len(threat_log) >= MAX_THREAT_LOG:
            threat_log.pop(0)
            
        threat_log.append({
            "id": len(threat_log) + 1,
            "threat": {k: v for k, v in threat_data.dict().items() if k != 'source'},
            "source_hash": hashlib.sha256(threat_data.source.encode()).hexdigest()[:16],
            "analysis": result,
            "timestamp": threat_data.timestamp
        })
        
        # Record metrics
        record_threat(threat_data.type, threat_data.severity)
        
        # Block IP if critical threat
        if threat_data.severity == 'critical':
            blocked_ips.add(client_ip)
            result["actions_taken"].append("IP blocked")
        
        return {
            "status": "success", 
            "result": result, 
            "request_id": task["request_id"]
        }
        
    except Exception as e:
        logging.error(f"Threat analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail="Analysis failed")

async def analyze_with_go_scanner(threat_data: dict) -> dict:
    """Send threat to Go scanner for analysis"""
    try:
        scan_request = {
            "url": f"threat://{threat_data.get('type', 'unknown')}",
            "method": "ANALYZE",
            "headers": {"Threat-Type": threat_data.get('type', 'unknown')},
            "body": json.dumps(threat_data)
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                'http://localhost:8080/api/scan',
                json=scan_request,
                timeout=5
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
                else:
                    return {"status": "scanner_unavailable"}
    except Exception as e:
        logging.warning(f"Go scanner analysis failed: {e}")
        return {"status": "scanner_error", "error": str(e)}

async def send_to_labyrinth(source_ip: str, threat_level: str) -> dict:
    """Send intruder to Rust labyrinth"""
    try:
        intruder_data = {
            "source_ip": hashlib.sha256(source_ip.encode()).hexdigest()[:16],  # Hash IP for privacy
            "threat_level": {"low": 1, "medium": 3, "high": 7, "critical": 10}.get(threat_level, 5)
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                'http://localhost:3030/intruder',
                json=intruder_data,
                timeout=5
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
                else:
                    return {"status": "labyrinth_unavailable"}
    except Exception as e:
        logging.warning(f"Rust labyrinth integration failed: {e}")
        return {"status": "labyrinth_error", "error": str(e)}

@app.get("/api/threats/log")
async def get_threat_log(token: dict = Depends(verify_token)):
    """Get secure threat log"""
    return {"threats": threat_log[-50:], "total": len(threat_log)}

@app.post("/api/emergency")
async def trigger_emergency(
    emergency: EmergencyRequest,
    token: dict = Depends(verify_token)
):
    """Trigger emergency response"""
    try:
        await hub.emergency_response(emergency.level)
        
        # Log emergency
        logging.critical(f"Emergency {emergency.level} triggered: {emergency.reason}")
        
        return {
            "status": "emergency_activated", 
            "level": emergency.level,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logging.error(f"Emergency response failed: {e}")
        raise HTTPException(status_code=500, detail="Emergency response failed")

@app.get("/api/stats")
async def get_system_stats(token: dict = Depends(verify_token)):
    """Get comprehensive system statistics"""
    try:
        # Get stats from all services
        go_stats = await get_go_scanner_stats()
        rust_stats = await get_rust_labyrinth_stats()
        
        active_count = len([a for a in hub.agents.values() if a.status != "offline"])
        update_agent_count(active_count)
        
        return {
            "agents": {
                "total": len(hub.agents),
                "active": active_count,
                "tasks_completed": sum(a.tasks_completed for a in hub.agents.values())
            },
            "threats": {
                "total": len(threat_log),
                "blocked_ips": len(blocked_ips),
                "critical": len([t for t in threat_log if t.get("threat", {}).get("severity") == "critical"])
            },
            "services": {
                "go_scanner": go_stats,
                "rust_labyrinth": rust_stats
            }
        }
    except Exception as e:
        logging.error(f"Stats error: {e}")
        raise HTTPException(status_code=500, detail="Stats unavailable")

async def get_go_scanner_stats() -> dict:
    """Get Go scanner statistics"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('http://localhost:8080/api/stats', timeout=5) as resp:
                if resp.status == 200:
                    return await resp.json()
                return {"status": "unavailable"}
    except:
        return {"status": "error"}

async def get_rust_labyrinth_stats() -> dict:
    """Get Rust labyrinth statistics"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('http://localhost:3030/stats', timeout=5) as resp:
                if resp.status == 200:
                    return await resp.json()
                return {"status": "unavailable"}
    except:
        return {"status": "error"}

@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    return PlainTextResponse(get_metrics())

@app.websocket("/ws/threats")
async def websocket_endpoint(websocket: WebSocket):
    """Secure WebSocket for real-time threat updates"""
    await websocket.accept()
    connected_clients.append(websocket)
    
    try:
        while True:
            # Send periodic secure updates
            update = {
                "type": "status_update",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "active_agents": len(hub.agents),
                "threats_processed": len(threat_log),
                "system_status": "secure"
            }
            await websocket.send_text(json.dumps(update))
            await asyncio.sleep(5)
            
    except Exception as e:
        logging.error(f"WebSocket error: {e}")
    finally:
        if websocket in connected_clients:
            connected_clients.remove(websocket)

if __name__ == "__main__":
    import uvicorn
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run secure server
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=8000,
        ssl_keyfile=os.getenv("SSL_KEYFILE"),
        ssl_certfile=os.getenv("SSL_CERTFILE"),
        access_log=True
    )