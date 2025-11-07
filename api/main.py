"""
FastAPI Main - REST API untuk AI Security Platform
"""
from fastapi import FastAPI, HTTPException, WebSocket, Depends, status
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional
import sys
import os
from pydantic import BaseModel, validator
import hashlib
import secrets

# Metrics (conditional import)
try:
    from api.metrics import (
        track_response_time, record_threat, update_agent_count, 
        update_labyrinth_stats, get_metrics
    )
except ImportError:
    # Fallback for development
    def track_response_time(name):
        def decorator(func):
            return func
        return decorator
    
    def record_threat(t_type, severity): pass
    def update_agent_count(count): pass
    def update_labyrinth_stats(nodes, intruders): pass
    def get_metrics(): return "# No metrics available"

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_hub.hub_core import hub
from agents.gpt5_agent import GPT5Agent
from agents.base_agent import MockAgent
from api.agents_route import router as agents_router

# Security models
class ThreatData(BaseModel):
    type: str
    severity: str
    source: str
    timestamp: Optional[str] = None
    
    @validator('type')
    def validate_type(cls, v):
        allowed_types = ['SQL Injection', 'XSS', 'DDoS', 'Brute Force', 'Malware']
        if v not in allowed_types:
            raise ValueError('Invalid threat type')
        return v

# Security setup
security = HTTPBearer()
API_KEY = os.getenv('API_KEY', secrets.token_hex(32))

app = FastAPI(
    title="Infinite AI Security API", 
    version="2.0.0",
    docs_url=None,  # Disable docs in production
    redoc_url=None
)

# Secure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# Security middleware
async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token_hash = hashlib.sha256(credentials.credentials.encode()).hexdigest()
    expected_hash = hashlib.sha256(API_KEY.encode()).hexdigest()
    if not secrets.compare_digest(token_hash, expected_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    return credentials.credentials

# Include AI Agents router
app.include_router(agents_router)

# Secure global state
connected_clients: List[WebSocket] = []
threat_log: List[Dict] = []
MAX_THREAT_LOG = 1000  # Prevent memory exhaustion

@app.on_event("startup")
async def startup_event():
    """Initialize AI agents saat startup"""
    # Register agents
    await hub.register_agent("gpt5", GPT5Agent())
    await hub.register_agent("claude", MockAgent("Claude", "claude-3"))
    await hub.register_agent("grok", MockAgent("Grok", "grok-1"))
    await hub.register_agent("mistral", MockAgent("Mistral", "mistral-large"))
    
    # Start monitoring
    asyncio.create_task(hub.start_monitoring())
    print("🤖 AI Security Platform started - All agents online")

@app.get("/")
async def root():
    return {"message": "Infinite AI Security Platform", "status": "online"}

# Legacy endpoint - redirects to new agents API
@app.get("/api/agents/status/legacy")
async def get_agents_status_legacy():
    """Legacy status endpoint"""
    status = {}
    for name, agent in hub.agents.items():
        status[name] = await agent.health_check()
    return status

@app.post("/api/threats/analyze")
@track_response_time("analyze_threat")
async def analyze_threat(
    threat_data: ThreatData, 
    token: str = Depends(verify_token)
):
    """Secure threat analysis with AI agents"""
    try:
        # Add timestamp if not provided
        if not threat_data.timestamp:
            threat_data.timestamp = datetime.now(timezone.utc).isoformat()
        
        task = {
            "type": "threat_analysis",
            "data": threat_data.dict(),
            "timestamp": threat_data.timestamp,
            "request_id": secrets.token_hex(16)
        }
        
        result = await hub.distribute_task(task)
        
        # Secure logging with size limit
        if len(threat_log) >= MAX_THREAT_LOG:
            threat_log.pop(0)  # Remove oldest entry
            
        threat_log.append({
            "id": len(threat_log) + 1,
            "threat": threat_data.dict(),
            "analysis": result,
            "timestamp": threat_data.timestamp,
            "source_hash": hashlib.sha256(threat_data.source.encode()).hexdigest()[:16]
        })
        
        # Record metrics
        record_threat(threat_data.type, threat_data.severity)
        
        return {"status": "success", "result": result, "request_id": task["request_id"]}
        
    except Exception as e:
        logging.error(f"Threat analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail="Analysis failed")

@app.get("/api/threats/log")
async def get_threat_log():
    """Ambil log ancaman terbaru"""
    return {"threats": threat_log[-50:]}  # 50 terakhir

@app.post("/api/emergency")
async def trigger_emergency(level: str = "CRITICAL"):
    """Trigger emergency response"""
    await hub.emergency_response(level)
    return {"status": "emergency_activated", "level": level}

@app.get("/api/labyrinth/stats")
async def get_labyrinth_stats():
    """Stats Infinite Labyrinth (mock data)"""
    return {
        "active_nodes": 1247,
        "trapped_intruders": 23,
        "generation_rate": "2.3 nodes/sec",
        "trap_success_rate": "94.7%",
        "uptime": "72h 15m"
    }

@app.websocket("/ws/threats")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket untuk real-time threat updates"""
    await websocket.accept()
    connected_clients.append(websocket)
    
    try:
        while True:
            # Send periodic updates
            update = {
                "type": "status_update",
                "timestamp": datetime.now().isoformat(),
                "active_agents": len(hub.agents),
                "threats_processed": len(threat_log)
            }
            await websocket.send_text(json.dumps(update))
            await asyncio.sleep(5)
            
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        connected_clients.remove(websocket)

@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(get_metrics())

@app.get("/api/dashboard/data")
@track_response_time("dashboard_data")
async def get_dashboard_data():
    """Data untuk dashboard real-time"""
    # Update metrics
    active_count = len([a for a in hub.agents.values() if a.status != "offline"])
    update_agent_count(active_count)
    update_labyrinth_stats(1247, 23)  # Mock data
    
    return {
        "agents": {
            "total": len(hub.agents),
            "active": active_count,
            "tasks_completed": sum(a.tasks_completed for a in hub.agents.values())
        },
        "threats": {
            "total": len(threat_log),
            "last_24h": len([t for t in threat_log if True]),  # Simplified
            "critical": len([t for t in threat_log if t.get("analysis", {}).get("threat_level") == "high"])
        },
        "labyrinth": {
            "nodes": 1247,
            "intruders": 23,
            "traps_triggered": 156
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)