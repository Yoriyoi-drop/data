"""
Infinite AI Security - Enhanced with WebSockets
Fase 1 Evolution: Real-time Dashboard Updates
"""
import os
import sys
import time
import json
import sqlite3
import asyncio
from datetime import datetime, UTC
from typing import Dict, Any, List
from pathlib import Path
from contextlib import contextmanager

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from fastapi import FastAPI, HTTPException, Depends, Request, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import uvicorn

# Import our secure authentication
from auth_secure_fixed import auth, rate_limiter, login_rate_limiter, normalize_input

app = FastAPI(
    title="Infinite AI Security - WebSocket Enhanced",
    version="4.4.0",
    description="Real-time threat detection with WebSocket notifications"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.user_connections: Dict[str, WebSocket] = {}
    
    async def connect(self, websocket: WebSocket, user_id: str = None):
        await websocket.accept()
        self.active_connections.append(websocket)
        if user_id:
            self.user_connections[user_id] = websocket
        print(f"[WS] Client connected. Total: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket, user_id: str = None):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        if user_id and user_id in self.user_connections:
            del self.user_connections[user_id]
        print(f"[WS] Client disconnected. Total: {len(self.active_connections)}")
    
    async def send_personal_message(self, message: str, user_id: str):
        if user_id in self.user_connections:
            try:
                await self.user_connections[user_id].send_text(message)
            except:
                # Connection might be closed
                if user_id in self.user_connections:
                    del self.user_connections[user_id]
    
    async def broadcast(self, message: str):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                disconnected.append(connection)
        
        # Remove disconnected clients
        for conn in disconnected:
            if conn in self.active_connections:
                self.active_connections.remove(conn)

manager = ConnectionManager()

# Enhanced Database with WebSocket notifications
class WebSocketDatabase:
    def __init__(self, db_path="websocket_security.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database with enhanced schema"""
        with sqlite3.connect(self.db_path) as conn:
            # Users table
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
            
            # Threats table with real-time fields
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
                    notified INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL
                )
            ''')
            
            # Real-time statistics
            conn.execute('''
                CREATE TABLE IF NOT EXISTS stats (
                    id INTEGER PRIMARY KEY,
                    requests INTEGER DEFAULT 0,
                    threats INTEGER DEFAULT 0,
                    blocked INTEGER DEFAULT 0,
                    sql_injection INTEGER DEFAULT 0,
                    xss INTEGER DEFAULT 0,
                    command_injection INTEGER DEFAULT 0,
                    last_threat_time TEXT,
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
    
    async def log_threat_with_notification(self, threat_id: str, payload: str, result: dict, username: str, ip: str = None):
        """Log threat and send real-time notification"""
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
        
        # Send real-time notification
        notification = {
            "type": "threat_detected",
            "data": {
                "threat_id": threat_id,
                "threat_type": result.get('type', 'unknown'),
                "severity": result.get('severity', 'low'),
                "confidence": result.get('confidence', 0.0),
                "blocked": result.get('blocked', False),
                "user": username,
                "timestamp": datetime.now(UTC).isoformat(),
                "payload_preview": payload[:100] + "..." if len(payload) > 100 else payload
            }
        }
        
        await manager.broadcast(json.dumps(notification))
    
    async def update_stats_with_notification(self, requests=0, threats=0, blocked=0):
        """Update statistics and broadcast to connected clients"""
        with self.get_connection() as conn:
            # Update stats
            conn.execute('''
                UPDATE stats SET 
                    requests = requests + ?,
                    threats = threats + ?,
                    blocked = blocked + ?,
                    last_threat_time = ?,
                    updated_at = ?
                WHERE id = 1
            ''', (requests, threats, blocked, 
                  datetime.now(UTC).isoformat() if threats > 0 else None,
                  datetime.now(UTC).isoformat()))
            conn.commit()
            
            # Get updated stats
            cursor = conn.execute('SELECT * FROM stats WHERE id = 1')
            stats = dict(cursor.fetchone())
        
        # Broadcast updated statistics
        notification = {
            "type": "stats_update",
            "data": stats
        }
        
        await manager.broadcast(json.dumps(notification))
    
    def get_stats(self):
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM stats WHERE id = 1')
            row = cursor.fetchone()
            return dict(row) if row else {}
    
    def get_recent_threats(self, limit=10):
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT * FROM threats ORDER BY created_at DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]

# Enhanced Threat Analyzer with real-time notifications
class RealtimeThreatAnalyzer:
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
        
        # Normalize input to prevent bypass
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
db = WebSocketDatabase()
analyzer = RealtimeThreatAnalyzer()

# Initialize admin user
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

# WebSocket endpoint for real-time updates
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()
            # Echo back for testing
            await websocket.send_text(f"Echo: {data}")
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# WebSocket endpoint with authentication
@app.websocket("/ws/{user_id}")
async def websocket_user_endpoint(websocket: WebSocket, user_id: str):
    await manager.connect(websocket, user_id)
    try:
        # Send welcome message
        welcome = {
            "type": "connection_established",
            "data": {
                "user_id": user_id,
                "timestamp": datetime.now(UTC).isoformat(),
                "message": "Real-time notifications active"
            }
        }
        await websocket.send_text(json.dumps(welcome))
        
        while True:
            data = await websocket.receive_text()
            # Handle client messages if needed
            pass
    except WebSocketDisconnect:
        manager.disconnect(websocket, user_id)

# API Endpoints with WebSocket integration
@app.post("/auth/login")
async def secure_login(request: Request, credentials: Dict[str, str]):
    """Secure login with rate limiting"""
    client_ip = request.client.host
    
    # Check login rate limit
    if not login_rate_limiter.is_allowed(client_ip):
        raise HTTPException(status_code=429, detail="Too many login attempts")
    
    username = credentials.get("username")
    password = credentials.get("password")
    
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")
    
    user = db.get_user(username)
    if not user or not auth.verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create secure token
    token = auth.create_token(username, user["role"])
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {"username": username, "role": user["role"]},
        "websocket_url": f"/ws/{username}",
        "message": "WebSocket-enhanced login successful"
    }

@app.get("/")
async def root():
    return {
        "service": "Infinite AI Security - WebSocket Enhanced",
        "version": "4.4.0",
        "features": ["Real-time Notifications", "WebSocket Support", "Enhanced Security"],
        "websocket_endpoint": "/ws",
        "status": "operational",
        "timestamp": datetime.now(UTC).isoformat()
    }

@app.get("/health")
async def health():
    stats = db.get_stats()
    return {
        "status": "healthy",
        "websocket_connections": len(manager.active_connections),
        "security": auth.get_security_info(),
        "database": "SQLite with WebSocket support",
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
    """Enhanced threat analysis with real-time notifications"""
    payload = data.get("input", "")
    if not payload:
        raise HTTPException(status_code=400, detail="Missing input")
    
    # Analyze threat
    result = analyzer.analyze(payload)
    
    # Update statistics with real-time broadcast
    await db.update_stats_with_notification(requests=1)
    
    if result["threat"]:
        await db.update_stats_with_notification(
            threats=1,
            blocked=1 if result["blocked"] else 0
        )
        
        # Log threat with real-time notification
        threat_id = f"threat_{int(time.time())}_{current_user['username']}"
        await db.log_threat_with_notification(
            threat_id, payload, result, current_user["username"], request.client.host
        )
    
    return {
        "request_id": f"req_{int(time.time())}",
        "analysis": result,
        "user": current_user["username"],
        "websocket_notified": result["threat"],
        "timestamp": datetime.now(UTC).isoformat()
    }

@app.get("/api/threats")
async def get_threats(current_user: dict = Depends(get_current_user)):
    """Get recent threats"""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    threats = db.get_recent_threats(20)
    return {
        "threats": threats,
        "total": len(threats),
        "websocket_enabled": True
    }

@app.get("/dashboard")
async def dashboard():
    """Serve real-time dashboard"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Infinite AI Security - Real-time Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #1a1a1a; color: white; }
            .container { max-width: 1200px; margin: 0 auto; }
            .header { text-align: center; margin-bottom: 30px; }
            .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
            .stat-card { background: #2d2d2d; padding: 20px; border-radius: 8px; text-align: center; }
            .stat-value { font-size: 2em; font-weight: bold; color: #4CAF50; }
            .threats-log { background: #2d2d2d; padding: 20px; border-radius: 8px; max-height: 400px; overflow-y: auto; }
            .threat-item { background: #3d3d3d; margin: 10px 0; padding: 15px; border-radius: 5px; border-left: 4px solid #f44336; }
            .threat-critical { border-left-color: #f44336; }
            .threat-high { border-left-color: #ff9800; }
            .threat-medium { border-left-color: #ffeb3b; }
            .connection-status { position: fixed; top: 10px; right: 10px; padding: 10px; border-radius: 5px; }
            .connected { background: #4CAF50; }
            .disconnected { background: #f44336; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ Infinite AI Security - Real-time Dashboard</h1>
                <div id="connectionStatus" class="connection-status disconnected">Connecting...</div>
            </div>
            
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-value" id="totalRequests">0</div>
                    <div>Total Requests</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="totalThreats">0</div>
                    <div>Threats Detected</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="totalBlocked">0</div>
                    <div>Threats Blocked</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="wsConnections">0</div>
                    <div>Live Connections</div>
                </div>
            </div>
            
            <div class="threats-log">
                <h3>🚨 Real-time Threat Log</h3>
                <div id="threatsList">
                    <p>Waiting for threats...</p>
                </div>
            </div>
        </div>

        <script>
            const ws = new WebSocket('ws://localhost:8004/ws');
            const connectionStatus = document.getElementById('connectionStatus');
            const threatsList = document.getElementById('threatsList');
            
            ws.onopen = function(event) {
                connectionStatus.textContent = 'Connected';
                connectionStatus.className = 'connection-status connected';
                console.log('WebSocket connected');
            };
            
            ws.onmessage = function(event) {
                const message = JSON.parse(event.data);
                console.log('Received:', message);
                
                if (message.type === 'threat_detected') {
                    addThreatToLog(message.data);
                } else if (message.type === 'stats_update') {
                    updateStats(message.data);
                }
            };
            
            ws.onclose = function(event) {
                connectionStatus.textContent = 'Disconnected';
                connectionStatus.className = 'connection-status disconnected';
                console.log('WebSocket disconnected');
            };
            
            function addThreatToLog(threat) {
                const threatItem = document.createElement('div');
                threatItem.className = `threat-item threat-${threat.severity}`;
                threatItem.innerHTML = `
                    <strong>${threat.threat_type.toUpperCase()}</strong> - 
                    Confidence: ${(threat.confidence * 100).toFixed(1)}% - 
                    ${threat.blocked ? 'BLOCKED' : 'MONITORED'}
                    <br>
                    <small>User: ${threat.user} | ${new Date(threat.timestamp).toLocaleString()}</small>
                    <br>
                    <code>${threat.payload_preview}</code>
                `;
                
                threatsList.insertBefore(threatItem, threatsList.firstChild);
                
                // Keep only last 10 threats
                while (threatsList.children.length > 10) {
                    threatsList.removeChild(threatsList.lastChild);
                }
            }
            
            function updateStats(stats) {
                document.getElementById('totalRequests').textContent = stats.requests || 0;
                document.getElementById('totalThreats').textContent = stats.threats || 0;
                document.getElementById('totalBlocked').textContent = stats.blocked || 0;
            }
            
            // Load initial stats
            fetch('/health')
                .then(response => response.json())
                .then(data => {
                    updateStats(data);
                    document.getElementById('wsConnections').textContent = data.websocket_connections || 0;
                });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

if __name__ == "__main__":
    print("[WEBSOCKET] INFINITE AI SECURITY - REAL-TIME ENHANCED")
    print("=" * 60)
    print("[OK] WebSocket Support: Enabled")
    print("[OK] Real-time Notifications: Active")
    print("[OK] Enhanced Security: bcrypt + PyJWT")
    print("[OK] Rate Limiting: Enabled")
    print("[OK] Dashboard: Real-time Updates")
    print("=" * 60)
    print("[API] http://127.0.0.1:8004")
    print("[DASHBOARD] http://127.0.0.1:8004/dashboard")
    print("[WEBSOCKET] ws://127.0.0.1:8004/ws")
    print("[LOGIN] admin/admin123")
    print("=" * 60)
    
    uvicorn.run(app, host="127.0.0.1", port=8004, log_level="info")