"""
Simple HTTP Server - No external dependencies
"""
import json
import time
from datetime import datetime, UTC
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

stats = {"requests": 0, "threats": 0, "start": datetime.now(UTC)}

def detect_threat(payload):
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

class APIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        
        if path == "/":
            response = {"service": "Infinite AI Security", "version": "2.0", "status": "ok"}
        elif path == "/health":
            uptime = int((datetime.now(UTC) - stats["start"]).total_seconds())
            response = {"status": "healthy", "uptime": uptime, "requests": stats["requests"]}
        else:
            self.send_error(404)
            return
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())
    
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
                self.end_headers()
                self.wfile.write(json.dumps(response).encode())
                
            except Exception as e:
                self.send_error(500, str(e))
        else:
            self.send_error(404)

if __name__ == "__main__":
    server = HTTPServer(('127.0.0.1', 8080), APIHandler)
    print("🚀 Infinite AI Security API v2.0")
    print("📡 Running on http://127.0.0.1:8080")
    print("🤖 No external dependencies required")
    print("=" * 40)
    server.serve_forever()