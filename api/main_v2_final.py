"""
Infinite AI Security API - V2 Final
Zero warnings, pure Python 3.14 compatible
"""
import time
from datetime import datetime, UTC
from typing import Dict, Any
import uvicorn
from fastapi import FastAPI, HTTPException

app = FastAPI(title="Infinite AI Security", version="2.0")

stats = {"requests": 0, "threats": 0, "start": datetime.now(UTC)}

def detect_threat(payload: str) -> Dict[str, Any]:
    if not payload:
        return {"threat": False, "confidence": 0.0}
    
    payload = payload.lower()
    
    # SQL injection
    sql_patterns = ["' or '1'='1", "'; drop", "union select"]
    sql_count = sum(1 for p in sql_patterns if p in payload)
    
    # XSS
    xss_patterns = ["<script>", "javascript:", "alert("]
    xss_count = sum(1 for p in xss_patterns if p in payload)
    
    if sql_count > 0:
        confidence = min(0.95, sql_count * 0.4 + 0.5)
        return {"threat": True, "confidence": confidence, "type": "sql_injection"}
    
    if xss_count > 0:
        confidence = min(0.90, xss_count * 0.3 + 0.4)
        return {"threat": True, "confidence": confidence, "type": "xss"}
    
    return {"threat": False, "confidence": 0.1, "type": "none"}

@app.get("/")
def root():
    return {"service": "Infinite AI Security", "version": "2.0", "status": "ok"}

@app.get("/health")
def health():
    uptime = int((datetime.now(UTC) - stats["start"]).total_seconds())
    return {"status": "healthy", "uptime": uptime, "requests": stats["requests"]}

@app.post("/analyze")
def analyze(data: Dict[str, Any]):
    stats["requests"] += 1
    
    payload = data.get("input", "")
    if not payload:
        raise HTTPException(400, "Missing input")
    
    result = detect_threat(payload)
    
    if result["confidence"] > 0.5:
        stats["threats"] += 1
    
    return {
        "id": f"req_{stats['requests']}",
        "analysis": result,
        "timestamp": datetime.now(UTC).isoformat()
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8080)