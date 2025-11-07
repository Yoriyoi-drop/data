"""
Infinite AI Security - Complete UI Dashboard
Full-featured web interface with detailed analytics
"""
import os
import time
import json
import hashlib
import secrets
from datetime import datetime, UTC, timedelta
from typing import Dict, Any, Optional
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

# Simple authentication
def hash_password(password: str, salt: str = None) -> str:
    if salt is None:
        salt = secrets.token_hex(16)
    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}:{password_hash}"

def verify_password(password: str, hashed: str) -> bool:
    try:
        salt, password_hash = hashed.split(':')
        return hashlib.sha256((password + salt).encode()).hexdigest() == password_hash
    except:
        return password == hashed

def create_token(username: str) -> str:
    import base64
    token_data = f"{username}:{int(time.time())}"
    return base64.b64encode(token_data.encode()).decode()

def verify_token(token: str) -> Optional[str]:
    try:
        import base64
        token_data = base64.b64decode(token.encode()).decode()
        username, timestamp = token_data.split(':')
        if int(time.time()) - int(timestamp) < 3600:
            return username
    except:
        pass
    return None

# Initialize FastAPI
app = FastAPI(title="Infinite AI Security Dashboard", version="4.0.0")
security = HTTPBearer()

# Database
DB_FILE = Path("security_dashboard.json")

def init_database():
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
            "stats": {
                "requests": 0, "threats": 0, "blocked": 0, "users_online": 0,
                "sql_injection": 0, "xss": 0, "command_injection": 0,
                "high_severity": 0, "medium_severity": 0, "low_severity": 0
            },
            "system_info": {
                "start_time": datetime.now(UTC).isoformat(),
                "version": "4.0.0",
                "platform": "Windows"
            }
        }
        
        with open(DB_FILE, 'w', encoding='utf-8') as f:
            json.dump(initial_data, f, indent=2)

def load_db():
    try:
        with open(DB_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        init_database()
        return load_db()

def save_db(data):
    with open(DB_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

# Threat Detection
class AdvancedThreatAnalyzer:
    def __init__(self):
        self.patterns = {
            "sql_injection": {
                "' or '1'='1": 0.95, "'; drop table": 0.98, "union select": 0.85,
                "admin'--": 0.90, "' or 1=1": 0.95, "select * from": 0.80,
                "insert into": 0.85, "delete from": 0.90, "update set": 0.80
            },
            "xss": {
                "<script>": 0.95, "javascript:": 0.85, "onerror=": 0.80,
                "alert(": 0.90, "<svg onload": 0.90, "document.cookie": 0.85,
                "<iframe": 0.80, "eval(": 0.85, "onclick=": 0.75
            },
            "command_injection": {
                "; dir": 0.85, "&& whoami": 0.90, "| type": 0.80,
                "; del": 0.95, "cmd.exe": 0.90, "powershell": 0.85,
                "net user": 0.80, "; cat": 0.85, "&& ls": 0.80
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
                severity = "critical" if threat_confidence > 0.8 else "high" if threat_confidence > 0.6 else "medium"
                threats.append({
                    "type": threat_type,
                    "confidence": threat_confidence,
                    "patterns": matches,
                    "severity": severity
                })
                
                if threat_confidence > max_confidence:
                    max_confidence = threat_confidence
                    primary_threat = threat_type
        
        return {
            "threat": len(threats) > 0,
            "confidence": max_confidence,
            "type": primary_threat,
            "severity": "critical" if max_confidence > 0.8 else "high" if max_confidence > 0.6 else "medium",
            "threats_found": threats,
            "blocked": max_confidence > 0.7,
            "risk_score": int(max_confidence * 100)
        }

analyzer = AdvancedThreatAnalyzer()

# Authentication
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    username = verify_token(credentials.credentials)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    db = load_db()
    user = db["users"].get(username)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return user

# Initialize
init_database()

# Complete Dashboard HTML
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ Infinite AI Security Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { 
            background: rgba(255,255,255,0.95); 
            padding: 20px; 
            border-radius: 15px; 
            margin-bottom: 20px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
        }
        .header h1 { color: #2c3e50; text-align: center; font-size: 2.5em; margin-bottom: 10px; }
        .header p { text-align: center; color: #7f8c8d; font-size: 1.2em; }
        
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px; 
        }
        .stat-card { 
            background: rgba(255,255,255,0.95); 
            padding: 25px; 
            border-radius: 15px; 
            text-align: center;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
            transition: transform 0.3s ease;
        }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-value { font-size: 3em; font-weight: bold; margin-bottom: 10px; }
        .stat-label { color: #7f8c8d; font-size: 1.1em; }
        .stat-requests .stat-value { color: #3498db; }
        .stat-threats .stat-value { color: #e74c3c; }
        .stat-blocked .stat-value { color: #27ae60; }
        .stat-uptime .stat-value { color: #f39c12; }
        
        .main-content { 
            display: grid; 
            grid-template-columns: 1fr 1fr; 
            gap: 20px; 
            margin-bottom: 30px; 
        }
        .panel { 
            background: rgba(255,255,255,0.95); 
            padding: 25px; 
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
        }
        .panel h3 { color: #2c3e50; margin-bottom: 20px; font-size: 1.5em; }
        
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; font-weight: bold; color: #2c3e50; }
        .form-group input, .form-group textarea { 
            width: 100%; 
            padding: 12px; 
            border: 2px solid #ecf0f1; 
            border-radius: 8px; 
            font-size: 16px;
            transition: border-color 0.3s ease;
        }
        .form-group input:focus, .form-group textarea:focus { 
            outline: none; 
            border-color: #3498db; 
        }
        
        .btn { 
            background: linear-gradient(45deg, #3498db, #2980b9); 
            color: white; 
            padding: 12px 30px; 
            border: none; 
            border-radius: 8px; 
            cursor: pointer; 
            font-size: 16px; 
            font-weight: bold;
            transition: all 0.3s ease;
        }
        .btn:hover { 
            transform: translateY(-2px); 
            box-shadow: 0 5px 15px rgba(52, 152, 219, 0.4); 
        }
        
        .result { 
            margin-top: 20px; 
            padding: 20px; 
            border-radius: 10px; 
            animation: fadeIn 0.5s ease;
        }
        .result.safe { 
            background: linear-gradient(45deg, #d5f4e6, #a8e6cf); 
            border-left: 5px solid #27ae60; 
        }
        .result.threat { 
            background: linear-gradient(45deg, #fadbd8, #f1948a); 
            border-left: 5px solid #e74c3c; 
        }
        .result h4 { margin-bottom: 15px; font-size: 1.3em; }
        .threat-details { font-size: 14px; line-height: 1.6; }
        .threat-details strong { color: #2c3e50; }
        
        .threat-history { max-height: 400px; overflow-y: auto; }
        .threat-item { 
            background: #f8f9fa; 
            padding: 15px; 
            margin-bottom: 10px; 
            border-radius: 8px; 
            border-left: 4px solid #e74c3c;
        }
        .threat-item.blocked { border-left-color: #27ae60; }
        .threat-meta { font-size: 12px; color: #7f8c8d; margin-top: 5px; }
        
        .system-info { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 15px; 
        }
        .info-item { 
            background: #f8f9fa; 
            padding: 15px; 
            border-radius: 8px; 
            text-align: center;
        }
        .info-value { font-weight: bold; color: #2c3e50; font-size: 1.2em; }
        .info-label { color: #7f8c8d; font-size: 0.9em; margin-top: 5px; }
        
        @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        
        .login-form { 
            max-width: 400px; 
            margin: 100px auto; 
            background: rgba(255,255,255,0.95); 
            padding: 40px; 
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
        }
        .login-form h2 { text-align: center; margin-bottom: 30px; color: #2c3e50; }
        
        .hidden { display: none; }
        
        @media (max-width: 768px) {
            .main-content { grid-template-columns: 1fr; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
        }
    </style>
</head>
<body>
    <!-- Login Form -->
    <div id="loginForm" class="login-form">
        <h2>🛡️ Security Login</h2>
        <form id="loginFormElement">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" id="username" value="admin" required>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" id="password" value="admin123" required>
            </div>
            <button type="submit" class="btn" style="width: 100%;">🔐 Login</button>
        </form>
    </div>

    <!-- Main Dashboard -->
    <div id="dashboard" class="container hidden">
        <div class="header">
            <h1>🛡️ Infinite AI Security Dashboard</h1>
            <p>Advanced Threat Detection & Real-time Monitoring System</p>
            <button onclick="logout()" class="btn" style="float: right; margin-top: -40px;">Logout</button>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card stat-requests">
                <div class="stat-value" id="totalRequests">0</div>
                <div class="stat-label">Total Requests</div>
            </div>
            <div class="stat-card stat-threats">
                <div class="stat-value" id="totalThreats">0</div>
                <div class="stat-label">Threats Detected</div>
            </div>
            <div class="stat-card stat-blocked">
                <div class="stat-value" id="totalBlocked">0</div>
                <div class="stat-label">Threats Blocked</div>
            </div>
            <div class="stat-card stat-uptime">
                <div class="stat-value" id="uptime">0s</div>
                <div class="stat-label">System Uptime</div>
            </div>
        </div>
        
        <div class="main-content">
            <div class="panel">
                <h3>🔍 Threat Analysis</h3>
                <form id="analyzeForm">
                    <div class="form-group">
                        <label>Enter text to analyze for security threats:</label>
                        <textarea id="input" rows="4" placeholder="Example: admin' OR '1'='1 -- SQL Injection&#10;<script>alert('xss')</script> -- XSS Attack&#10;; dir && whoami -- Command Injection"></textarea>
                    </div>
                    <button type="submit" class="btn">🛡️ Analyze Threat</button>
                </form>
                <div id="result"></div>
            </div>
            
            <div class="panel">
                <h3>📊 Threat Statistics</h3>
                <div class="system-info">
                    <div class="info-item">
                        <div class="info-value" id="sqlCount">0</div>
                        <div class="info-label">SQL Injection</div>
                    </div>
                    <div class="info-item">
                        <div class="info-value" id="xssCount">0</div>
                        <div class="info-label">XSS Attacks</div>
                    </div>
                    <div class="info-item">
                        <div class="info-value" id="cmdCount">0</div>
                        <div class="info-label">Command Injection</div>
                    </div>
                    <div class="info-item">
                        <div class="info-value" id="highSeverity">0</div>
                        <div class="info-label">High Severity</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="panel">
            <h3>🚨 Recent Threats</h3>
            <div id="threatHistory" class="threat-history">
                <p style="text-align: center; color: #7f8c8d;">No threats detected yet. System is secure.</p>
            </div>
        </div>
    </div>

    <script>
        let authToken = localStorage.getItem('authToken');
        
        // Check if already logged in
        if (authToken) {
            showDashboard();
        }
        
        // Login form handler
        document.getElementById('loginFormElement').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            try {
                const response = await fetch('/auth/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username, password})
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    authToken = data.access_token;
                    localStorage.setItem('authToken', authToken);
                    showDashboard();
                } else {
                    alert('Login failed: ' + data.detail);
                }
            } catch (error) {
                alert('Login error: ' + error.message);
            }
        });
        
        // Show dashboard
        function showDashboard() {
            document.getElementById('loginForm').classList.add('hidden');
            document.getElementById('dashboard').classList.remove('hidden');
            updateStats();
            loadThreats();
            setInterval(updateStats, 3000); // Update every 3 seconds
        }
        
        // Logout
        function logout() {
            localStorage.removeItem('authToken');
            location.reload();
        }
        
        // Update statistics
        async function updateStats() {
            try {
                const response = await fetch('/api/stats', {
                    headers: {'Authorization': `Bearer ${authToken}`}
                });
                
                const data = await response.json();
                const stats = data.stats;
                
                document.getElementById('totalRequests').textContent = stats.requests;
                document.getElementById('totalThreats').textContent = stats.threats;
                document.getElementById('totalBlocked').textContent = stats.blocked;
                document.getElementById('sqlCount').textContent = stats.sql_injection || 0;
                document.getElementById('xssCount').textContent = stats.xss || 0;
                document.getElementById('cmdCount').textContent = stats.command_injection || 0;
                document.getElementById('highSeverity').textContent = stats.high_severity || 0;
                
                // Calculate uptime
                const startTime = new Date(data.system_info?.start_time || Date.now());
                const uptime = Math.floor((Date.now() - startTime.getTime()) / 1000);
                document.getElementById('uptime').textContent = formatUptime(uptime);
                
            } catch (error) {
                console.error('Stats update error:', error);
            }
        }
        
        // Format uptime
        function formatUptime(seconds) {
            const hours = Math.floor(seconds / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            const secs = seconds % 60;
            
            if (hours > 0) return `${hours}h ${minutes}m`;
            if (minutes > 0) return `${minutes}m ${secs}s`;
            return `${secs}s`;
        }
        
        // Analyze form handler
        document.getElementById('analyzeForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const input = document.getElementById('input').value;
            if (!input.trim()) {
                alert('Please enter some text to analyze');
                return;
            }
            
            try {
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${authToken}`
                    },
                    body: JSON.stringify({input})
                });
                
                const data = await response.json();
                const analysis = data.analysis;
                
                const resultDiv = document.getElementById('result');
                
                if (analysis.threat) {
                    resultDiv.className = 'result threat';
                    resultDiv.innerHTML = `
                        <h4>⚠️ THREAT DETECTED</h4>
                        <div class="threat-details">
                            <strong>Type:</strong> ${analysis.type}<br>
                            <strong>Confidence:</strong> ${(analysis.confidence * 100).toFixed(1)}%<br>
                            <strong>Risk Score:</strong> ${analysis.risk_score}/100<br>
                            <strong>Severity:</strong> ${analysis.severity.toUpperCase()}<br>
                            <strong>Status:</strong> ${analysis.blocked ? '🚫 BLOCKED' : '⚠️ MONITORED'}<br>
                            <strong>Request ID:</strong> ${data.request_id}<br>
                            <strong>Patterns Found:</strong> ${analysis.threats_found.map(t => t.patterns.join(', ')).join('; ')}
                        </div>
                    `;
                } else {
                    resultDiv.className = 'result safe';
                    resultDiv.innerHTML = `
                        <h4>✅ NO THREAT DETECTED</h4>
                        <div class="threat-details">
                            <strong>Status:</strong> SAFE<br>
                            <strong>Confidence:</strong> ${(analysis.confidence * 100).toFixed(1)}%<br>
                            <strong>Request ID:</strong> ${data.request_id}
                        </div>
                    `;
                }
                
                updateStats();
                loadThreats();
                
            } catch (error) {
                alert('Analysis failed: ' + error.message);
            }
        });
        
        // Load threat history
        async function loadThreats() {
            try {
                const response = await fetch('/api/threats', {
                    headers: {'Authorization': `Bearer ${authToken}`}
                });
                
                const data = await response.json();
                const threats = data.threats;
                
                const historyDiv = document.getElementById('threatHistory');
                
                if (threats.length === 0) {
                    historyDiv.innerHTML = '<p style="text-align: center; color: #7f8c8d;">No threats detected yet. System is secure.</p>';
                    return;
                }
                
                historyDiv.innerHTML = threats.slice(-10).reverse().map(threat => `
                    <div class="threat-item ${threat.result.blocked ? 'blocked' : ''}">
                        <strong>${threat.result.type.toUpperCase()}</strong> - 
                        Confidence: ${(threat.result.confidence * 100).toFixed(1)}% - 
                        ${threat.result.blocked ? '🚫 BLOCKED' : '⚠️ MONITORED'}
                        <br>
                        <small>${threat.payload}</small>
                        <div class="threat-meta">
                            ${threat.id} | ${new Date(threat.timestamp).toLocaleString()}
                        </div>
                    </div>
                `).join('');
                
            } catch (error) {
                console.error('Threat loading error:', error);
            }
        }
    </script>
</body>
</html>
"""

# API Endpoints
@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Complete dashboard interface"""
    return DASHBOARD_HTML

@app.post("/auth/login")
async def login(credentials: Dict[str, str]):
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
        "user": {"username": username, "role": user["role"]}
    }

@app.post("/api/analyze")
async def analyze_threat(data: Dict[str, Any], current_user: dict = Depends(get_current_user)):
    payload = data.get("input", "")
    if not payload:
        raise HTTPException(status_code=400, detail="Missing input")
    
    result = analyzer.analyze(payload)
    
    # Update database
    db = load_db()
    db["stats"]["requests"] += 1
    
    if result["threat"]:
        db["stats"]["threats"] += 1
        db["stats"][result["type"]] = db["stats"].get(result["type"], 0) + 1
        
        if result["severity"] == "high":
            db["stats"]["high_severity"] = db["stats"].get("high_severity", 0) + 1
        elif result["severity"] == "medium":
            db["stats"]["medium_severity"] = db["stats"].get("medium_severity", 0) + 1
        
        if result["blocked"]:
            db["stats"]["blocked"] += 1
        
        threat_record = {
            "id": f"threat_{int(time.time())}_{len(db['threats'])+1}",
            "payload": payload[:100],
            "result": result,
            "user": current_user["username"],
            "timestamp": datetime.now(UTC).isoformat()
        }
        db["threats"].append(threat_record)
    
    save_db(db)
    
    return {
        "request_id": f"req_{int(time.time())}_{db['stats']['requests']}",
        "analysis": result,
        "timestamp": datetime.now(UTC).isoformat()
    }

@app.get("/api/threats")
async def get_threats(current_user: dict = Depends(get_current_user)):
    db = load_db()
    return {
        "threats": db["threats"][-50:],  # Last 50 threats
        "total": len(db["threats"])
    }

@app.get("/api/stats")
async def get_stats(current_user: dict = Depends(get_current_user)):
    db = load_db()
    return {
        "stats": db["stats"],
        "system_info": db["system_info"],
        "total_threats": len(db["threats"]),
        "total_users": len(db["users"])
    }

if __name__ == "__main__":
    print("🛡️ Infinite AI Security - Complete Dashboard")
    print("=" * 50)
    print("✅ Full-featured web interface")
    print("✅ Real-time threat monitoring")
    print("✅ Advanced analytics dashboard")
    print("✅ Detailed threat history")
    print("=" * 50)
    print("🌐 Dashboard: http://127.0.0.1:8000")
    print("🔑 Login: admin/admin123")
    print("=" * 50)
    
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")