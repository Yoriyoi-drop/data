"""
Infinite AI Security - Optimized Production API
"""
import time
from datetime import datetime, UTC
from typing import Dict, Any
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI(title="Infinite AI Security API", version="3.1.0")

stats = {"requests": 0, "threats": 0, "blocked": 0, "start": datetime.now(UTC)}
agents = {
    "gpt4": {"confidence": 0.95},
    "claude": {"confidence": 0.92},
    "grok": {"confidence": 0.88}
}

def analyze_threat(payload: str) -> Dict[str, Any]:
    """Analyze payload for threats"""
    if not payload or not isinstance(payload, str):
        return {"threat": False, "confidence": 0.0, "type": "none"}
    
    payload = payload.lower()
    
    # SQL injection patterns
    sql_patterns = ["' or '1'='1", "'; drop", "union select", "admin'--"]
    sql_matches = sum(1 for p in sql_patterns if p in payload)
    
    # XSS patterns  
    xss_patterns = ["<script>", "javascript:", "onerror=", "alert("]
    xss_matches = sum(1 for p in xss_patterns if p in payload)
    
    if sql_matches > 0:
        confidence = min(0.95, sql_matches * 0.3 + 0.5)
        return {
            "threat": True,
            "confidence": confidence,
            "type": "sql_injection",
            "severity": "critical" if confidence > 0.8 else "high"
        }
    
    if xss_matches > 0:
        confidence = min(0.90, xss_matches * 0.25 + 0.4)
        return {
            "threat": True,
            "confidence": confidence,
            "type": "xss",
            "severity": "high" if confidence > 0.7 else "medium"
        }
    
    return {"threat": False, "confidence": 0.1, "type": "none", "severity": "low"}

@app.get("/")
def root():
    return {"service": "Infinite AI Security", "version": "3.1.0", "status": "ok"}

@app.get("/health")
def health():
    uptime = int((datetime.now(UTC) - stats["start"]).total_seconds())
    return {
        "status": "healthy",
        "uptime": uptime,
        "requests": stats["requests"],
        "threats": stats["threats"]
    }

@app.post("/analyze")
def analyze(data: Dict[str, Any]):
    try:
        stats["requests"] += 1
        
        payload = data.get("input", "")
        if not payload:
            raise HTTPException(400, "Missing input")
        
        result = analyze_threat(payload)
        
        if result["confidence"] > 0.5:
            stats["threats"] += 1
        
        if result["threat"] and result["confidence"] > 0.7:
            stats["blocked"] += 1
            result["blocked"] = True
        else:
            result["blocked"] = False
        
        return JSONResponse({
            "id": f"req_{stats['requests']}",
            "analysis": result,
            "timestamp": datetime.now(UTC).isoformat()
        })
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Analysis failed: {str(e)}")

@app.get("/agents")
def get_agents():
    return {"agents": agents, "count": len(agents)}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8080)