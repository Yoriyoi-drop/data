"""
AI Security Server with Web UI
"""
import json
import time
from datetime import datetime, UTC
from http.server import HTTPServer, BaseHTTPRequestHandler

stats = {"requests": 0, "threats": 0, "start": datetime.now(UTC)}

def detect_threat(payload):
    if not payload:
        return {"threat": False, "confidence": 0.0, "type": "none"}
    
    payload = payload.lower()
    
    # SQL injection
    sql_patterns = ["' or '1'='1", "'; drop", "union select", "admin'--"]
    sql_count = sum(1 for p in sql_patterns if p in payload)
    
    # XSS
    xss_patterns = ["<script>", "javascript:", "alert(", "onerror="]
    xss_count = sum(1 for p in xss_patterns if p in payload)
    
    if sql_count > 0:
        confidence = min(0.95, sql_count * 0.4 + 0.5)
        return {"threat": True, "confidence": confidence, "type": "sql_injection", "severity": "critical"}
    
    if xss_count > 0:
        confidence = min(0.90, xss_count * 0.3 + 0.4)
        return {"threat": True, "confidence": confidence, "type": "xss", "severity": "high"}
    
    return {"threat": False, "confidence": 0.1, "type": "none", "severity": "low"}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>🛡️ Infinite AI Security</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; color: #2c3e50; margin-bottom: 30px; }
        .stats { display: flex; justify-content: space-around; margin: 20px 0; }
        .stat { text-align: center; padding: 15px; background: #ecf0f1; border-radius: 8px; }
        .stat-value { font-size: 24px; font-weight: bold; color: #3498db; }
        .stat-label { color: #7f8c8d; margin-top: 5px; }
        .form-group { margin: 15px 0; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input, .form-group textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
        .btn { background: #3498db; color: white; padding: 12px 24px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        .btn:hover { background: #2980b9; }
        .result { margin-top: 20px; padding: 15px; border-radius: 5px; }
        .result.safe { background: #d5f4e6; border-left: 4px solid #27ae60; }
        .result.threat { background: #fadbd8; border-left: 4px solid #e74c3c; }
        .threat-details { margin-top: 10px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Infinite AI Security Platform</h1>
            <p>Real-time Threat Detection & Analysis</p>
        </div>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-value" id="requests">0</div>
                <div class="stat-label">Total Requests</div>
            </div>
            <div class="stat">
                <div class="stat-value" id="threats">0</div>
                <div class="stat-label">Threats Detected</div>
            </div>
            <div class="stat">
                <div class="stat-value" id="uptime">0s</div>
                <div class="stat-label">Uptime</div>
            </div>
        </div>
        
        <form id="analyzeForm">
            <div class="form-group">
                <label for="input">Enter text to analyze for threats:</label>
                <textarea id="input" rows="4" placeholder="Example: admin' OR '1'='1"></textarea>
            </div>
            <button type="submit" class="btn">🔍 Analyze Threat</button>
        </form>
        
        <div id="result"></div>
    </div>

    <script>
        // Update stats every 2 seconds
        function updateStats() {
            fetch('/health')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('requests').textContent = data.requests;
                    document.getElementById('threats').textContent = data.threats || 0;
                    document.getElementById('uptime').textContent = data.uptime + 's';
                });
        }
        
        // Analyze form submission
        document.getElementById('analyzeForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const input = document.getElementById('input').value;
            if (!input.trim()) {
                alert('Please enter some text to analyze');
                return;
            }
            
            fetch('/analyze', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({input: input})
            })
            .then(response => response.json())
            .then(data => {
                const result = document.getElementById('result');
                const analysis = data.analysis;
                
                if (analysis.threat) {
                    result.className = 'result threat';
                    result.innerHTML = `
                        <h3>⚠️ THREAT DETECTED</h3>
                        <div class="threat-details">
                            <strong>Type:</strong> ${analysis.type}<br>
                            <strong>Confidence:</strong> ${(analysis.confidence * 100).toFixed(1)}%<br>
                            <strong>Severity:</strong> ${analysis.severity}<br>
                            <strong>Request ID:</strong> ${data.id}
                        </div>
                    `;
                } else {
                    result.className = 'result safe';
                    result.innerHTML = `
                        <h3>✅ NO THREAT DETECTED</h3>
                        <div class="threat-details">
                            <strong>Confidence:</strong> ${(analysis.confidence * 100).toFixed(1)}%<br>
                            <strong>Request ID:</strong> ${data.id}
                        </div>
                    `;
                }
                
                updateStats();
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Analysis failed. Please try again.');
            });
        });
        
        // Initial stats load
        updateStats();
        setInterval(updateStats, 2000);
    </script>
</body>
</html>
"""

class APIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode())
        elif self.path == "/health":
            uptime = int((datetime.now(UTC) - stats["start"]).total_seconds())
            response = {"status": "healthy", "uptime": uptime, "requests": stats["requests"], "threats": stats["threats"]}
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_error(404)
    
    def do_POST(self):
        if self.path == "/analyze":
            stats["requests"] += 1
            
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data.decode('utf-8'))
                payload = data.get("input", "")
                
                if not payload:
                    self.send_error(400, "Missing input")
                    return
                
                result = detect_threat(payload)
                
                if result["confidence"] > 0.5:
                    stats["threats"] += 1
                
                response = {
                    "id": f"req_{stats['requests']}",
                    "analysis": result,
                    "timestamp": datetime.now(UTC).isoformat()
                }
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())
                
            except Exception as e:
                self.send_error(500, str(e))
        else:
            self.send_error(404)

if __name__ == "__main__":
    server = HTTPServer(('127.0.0.1', 8000), APIHandler)
    print("🚀 Infinite AI Security Platform")
    print("📡 Web UI: http://127.0.0.1:8000")
    print("🛡️ Real-time threat detection active")
    print("=" * 40)
    server.serve_forever()