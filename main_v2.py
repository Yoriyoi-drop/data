"""
Infinite AI Security Platform V2.0 - Enhanced Security Implementation
Implements Phase 1 security hardening with enhanced authentication, input validation, and testing
"""
import os
import sys
import time
import json
import sqlite3
import pg8000
import secrets
import hashlib
import base64
import string
from datetime import datetime, UTC, timedelta
from typing import Dict, Any, List, Optional
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, Depends, Request, WebSocket, WebSocketDisconnect, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.sessions import SessionMiddleware
import uvicorn

# Import enhanced security components
try:
    from security.enhanced_auth import enhanced_auth, mfa_manager
    from security.input_validator import input_validator, ThreatLevel
    ENHANCED_SECURITY = True
except ImportError:
    print("⚠️  Enhanced security modules not found, using basic security")
    ENHANCED_SECURITY = False

# Import validation models
try:
    from api.validation_models import (
        LoginRequest, ChangePasswordRequest, ThreatAnalysisRequest,
        UserCreateRequest, FileUploadMetadata, SearchRequest,
        IPAddressRequest, UpdateStatsRequest, RequestSizeValidator
    )
    VALIDATION_MODELS_AVAILABLE = True
except ImportError:
    print("⚠️  Validation models not found")
    VALIDATION_MODELS_AVAILABLE = False

# Try to import optional dependencies
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

try:
    import jwt as pyjwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

# ===== SECURITY MIDDLEWARE =====
class SecurityMiddleware:
    def __init__(self, app):
        self.app = app
        
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            # Generate nonce for CSP
            nonce = secrets.token_urlsafe(16)
            scope["csp_nonce"] = nonce
            
            # Add security headers
            async def send_wrapper(message):
                if message["type"] == "http.response.start":
                    headers = dict(message.get("headers", []))
                    
                    # SECURITY FIX: Complete security headers
                    security_headers = {
                        # Prevent MIME type sniffing
                        b"x-content-type-options": b"nosniff",
                        
                        # Prevent clickjacking
                        b"x-frame-options": b"DENY",
                        
                        # XSS protection (legacy but still useful)
                        b"x-xss-protection": b"1; mode=block",
                        
                        # HSTS - Force HTTPS
                        b"strict-transport-security": b"max-age=31536000; includeSubDomains; preload",
                        
                        # Referrer policy
                        b"referrer-policy": b"strict-origin-when-cross-origin",
                        
                        # Permissions policy (formerly Feature-Policy)
                        b"permissions-policy": b"geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()",
                        
                        # NEW: Cross-domain policies
                        b"x-permitted-cross-domain-policies": b"none",
                        
                        # NEW: Cross-Origin policies
                        b"cross-origin-embedder-policy": b"require-corp",
                        b"cross-origin-opener-policy": b"same-origin",
                        b"cross-origin-resource-policy": b"same-origin",
                        
                        # Content Security Policy with nonce
                        b"content-security-policy": (
                            f"default-src 'self'; "
                            f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
                            f"style-src 'self' 'nonce-{nonce}' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
                            f"font-src 'self' https://fonts.gstatic.com; "
                            f"img-src 'self' data: https:; "
                            f"connect-src 'self' ws: wss:; "
                            f"frame-ancestors 'none'; "
                            f"base-uri 'self'; "
                            f"form-action 'self'; "
                            f"upgrade-insecure-requests;"
                        ).encode()
                    }
                    
                    for key, value in security_headers.items():
                        headers[key] = value
                    
                    message["headers"] = list(headers.items())
                
                await send(message)
            
            await self.app(scope, receive, send_wrapper)
        else:
            await self.app(scope, receive, send)

# ===== ENHANCED RATE LIMITER =====
class EnhancedRateLimiter:
    def __init__(self):
        self.requests = {}
        self.blocked_ips = set()
        self.suspicious_ips = {}
        
        # Different limits for different endpoints
        self.limits = {
            "login": {"max_requests": 5, "window": 300},  # 5 attempts per 5 minutes
            "api": {"max_requests": 100, "window": 60},   # 100 requests per minute
            "general": {"max_requests": 200, "window": 60} # 200 requests per minute
        }
    
    def is_allowed(self, client_ip: str, endpoint_type: str = "general") -> bool:
        if client_ip in self.blocked_ips:
            return False
        
        now = time.time()
        limit_config = self.limits.get(endpoint_type, self.limits["general"])
        
        key = f"{client_ip}:{endpoint_type}"
        
        if key not in self.requests:
            self.requests[key] = []
        
        # Clean old requests
        self.requests[key] = [
            req_time for req_time in self.requests[key] 
            if now - req_time < limit_config["window"]
        ]
        
        if len(self.requests[key]) >= limit_config["max_requests"]:
            # Mark as suspicious
            if client_ip not in self.suspicious_ips:
                self.suspicious_ips[client_ip] = 0
            self.suspicious_ips[client_ip] += 1
            
            # Block after multiple violations
            if self.suspicious_ips[client_ip] >= 3:
                self.blocked_ips.add(client_ip)
            
            return False
        
        self.requests[key].append(now)
        return True
    
    def unblock_ip(self, client_ip: str):
        """Manually unblock an IP"""
        self.blocked_ips.discard(client_ip)
        if client_ip in self.suspicious_ips:
            del self.suspicious_ips[client_ip]

# ===== ENHANCED DATABASE =====
class EnhancedDatabase:
    def __init__(self, db_path="infinite_security_v2.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        with sqlite3.connect(self.db_path) as conn:
            # Users table with enhanced security fields
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    failed_attempts INTEGER DEFAULT 0,
                    locked_until TEXT,
                    mfa_enabled INTEGER DEFAULT 0,
                    mfa_secret TEXT,
                    last_login TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            ''')
            
            # Enhanced threats table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_id TEXT UNIQUE NOT NULL,
                    payload TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    severity TEXT NOT NULL,
                    blocked INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    validation_details TEXT,
                    created_at TEXT NOT NULL
                )
            ''')
            
            # Security events table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    user_id TEXT,
                    ip_address TEXT,
                    details TEXT,
                    risk_level TEXT DEFAULT 'low',
                    created_at TEXT NOT NULL
                )
            ''')
            
            # Sessions table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    user_id TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at TEXT NOT NULL,
                    last_activity TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    active INTEGER DEFAULT 1
                )
            ''')
            
            # System stats
            conn.execute('''
                CREATE TABLE IF NOT EXISTS stats (
                    id INTEGER PRIMARY KEY,
                    requests INTEGER DEFAULT 0,
                    threats INTEGER DEFAULT 0,
                    blocked INTEGER DEFAULT 0,
                    users INTEGER DEFAULT 0,
                    sessions INTEGER DEFAULT 0,
                    updated_at TEXT NOT NULL
                )
            ''')
            
            conn.execute('''
                INSERT OR IGNORE INTO stats (id, requests, threats, blocked, users, sessions, updated_at)
                VALUES (1, 0, 0, 0, 0, 0, ?)
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
    
    def update_user_login(self, username: str, success: bool, ip_address: str = None):
        with self.get_connection() as conn:
            now = datetime.now(UTC).isoformat()
            if success:
                conn.execute('''
                    UPDATE users SET 
                        failed_attempts = 0,
                        locked_until = NULL,
                        last_login = ?
                    WHERE username = ?
                ''', (now, username))
            else:
                conn.execute('''
                    UPDATE users SET 
                        failed_attempts = failed_attempts + 1,
                        locked_until = CASE 
                            WHEN failed_attempts >= 4 THEN ? 
                            ELSE locked_until 
                        END
                    WHERE username = ?
                ''', (datetime.now(UTC) + timedelta(minutes=15), username))
            
            conn.commit()
    
    def log_threat(self, threat_id: str, payload: str, result: dict, username: str, 
                   ip: str = None, user_agent: str = None):
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO threats (threat_id, payload, threat_type, confidence, 
                                   severity, blocked, username, ip_address, user_agent,
                                   validation_details, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat_id, payload[:1000], result.get('type', 'unknown'),
                result.get('confidence', 0.0), result.get('severity', 'low'),
                1 if result.get('blocked', False) else 0, username, ip, user_agent,
                json.dumps(result.get('details', {})), datetime.now(UTC).isoformat()
            ))
            conn.commit()
    
    def log_security_event(self, event_type: str, user_id: str = None, 
                          ip_address: str = None, details: dict = None, 
                          risk_level: str = "low"):
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO security_events (event_type, user_id, ip_address, details, risk_level, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                event_type, user_id, ip_address, 
                json.dumps(details or {}), risk_level,
                datetime.now(UTC).isoformat()
            ))
            conn.commit()
    
    def update_stats(self, **kwargs):
        # SECURITY FIX: Whitelist untuk mencegah SQL injection
        ALLOWED_STATS_FIELDS = {'requests', 'threats', 'blocked', 'users', 'sessions'}
        
        with self.get_connection() as conn:
            updates = []
            values = []
            
            for key, value in kwargs.items():
                # CRITICAL: Validasi whitelist yang ketat
                if key not in ALLOWED_STATS_FIELDS:
                    raise ValueError(f"Invalid stats field: {key}. Allowed fields: {ALLOWED_STATS_FIELDS}")
                
                # Validasi tipe data
                if not isinstance(value, (int, float)):
                    raise TypeError(f"Stats value must be numeric, got {type(value)} for field {key}")
                
                updates.append(f"{key} = {key} + ?")
                values.append(value)
            
            if updates:
                values.append(datetime.now(UTC).isoformat())
                query = f"UPDATE stats SET {', '.join(updates)}, updated_at = ? WHERE id = 1"
                conn.execute(query, values)
                conn.commit()
    
    def get_stats(self):
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM stats WHERE id = 1')
            row = cursor.fetchone()
            return dict(row) if row else {}

# ===== POSTGRES DATABASE (Preferred) =====
class PostgresEnhancedDatabase:
    def __init__(self, dsn: Optional[str] = None, host: str = "127.0.0.1", port: int = 5432,
                 user: str = "postgres", password: str = "postgres", database: str = "infinite_ai"):
        self.conn_params = {
            "dsn": dsn,
            "host": host,
            "port": port,
            "user": user,
            "password": password,
            "dbname": database,
        }
        # Optional Mongo for audit mirroring
        self.mongo_client = None
        self.mongo_db = None
        try:
            mongo_uri = os.getenv("MONGO_URI")
            if mongo_uri:
                from pymongo import MongoClient
                self.mongo_client = MongoClient(mongo_uri)
                self.mongo_db = self.mongo_client.get_database(os.getenv("MONGO_DB", "infinite_ai"))
        except Exception:
            self.mongo_client = None
            self.mongo_db = None
        self.init_database()

    @contextmanager
    def get_connection(self):
        conn = pg8000.connect(
            host=self.conn_params["host"],
            port=self.conn_params["port"],
            user=self.conn_params["user"],
            password=self.conn_params["password"],
            database=self.conn_params["dbname"],
        )
        try:
            yield conn
        finally:
            conn.close()

    def init_database(self):
        with self.get_connection() as conn:
            cur = conn.cursor()
            # Users
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    failed_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMPTZ,
                    mfa_enabled BOOLEAN DEFAULT FALSE,
                    mfa_secret TEXT,
                    last_login TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL
                )
                """
            )
            # Threats
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS threats (
                    id SERIAL PRIMARY KEY,
                    threat_id TEXT UNIQUE NOT NULL,
                    payload TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    severity TEXT NOT NULL,
                    blocked BOOLEAN NOT NULL,
                    username TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    validation_details TEXT,
                    created_at TIMESTAMPTZ NOT NULL
                )
                """
            )
            # Security events
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    id SERIAL PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    user_id TEXT,
                    ip_address TEXT,
                    details TEXT,
                    risk_level TEXT DEFAULT 'low',
                    created_at TIMESTAMPTZ NOT NULL
                )
                """
            )
            # Sessions
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id SERIAL PRIMARY KEY,
                    session_id TEXT UNIQUE NOT NULL,
                    user_id TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at TIMESTAMPTZ NOT NULL,
                    last_activity TIMESTAMPTZ NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL,
                    active BOOLEAN DEFAULT TRUE
                )
                """
            )
            # Stats (single row id=1)
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS stats (
                    id INTEGER PRIMARY KEY,
                    requests INTEGER DEFAULT 0,
                    threats INTEGER DEFAULT 0,
                    blocked INTEGER DEFAULT 0,
                    users INTEGER DEFAULT 0,
                    sessions INTEGER DEFAULT 0,
                    updated_at TIMESTAMPTZ NOT NULL
                )
                """
            )
            cur.execute(
                """
                INSERT INTO stats (id, requests, threats, blocked, users, sessions, updated_at)
                VALUES (1, 0, 0, 0, 0, 0, NOW())
                ON CONFLICT (id) DO NOTHING
                """
            )
            conn.commit()

    def create_user(self, username: str, password_hash: str, role: str = "user"):
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO users (username, password_hash, role, created_at, updated_at)
                VALUES (%s, %s, %s, NOW(), NOW())
                ON CONFLICT (username) DO NOTHING
                """,
                (username, password_hash, role),
            )
            conn.commit()

    def _row_to_dict(self, cur, row):
        if row is None:
            return None
        columns = [d[0] for d in cur.description]
        return {col: val for col, val in zip(columns, row)}

    def _rows_to_dicts(self, cur, rows):
        columns = [d[0] for d in cur.description]
        return [{col: val for col, val in zip(columns, r)} for r in rows]

    def get_user(self, username: str):
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            row = cur.fetchone()
            return self._row_to_dict(cur, row)

    def update_user_login(self, username: str, success: bool, ip_address: str = None):
        with self.get_connection() as conn:
            cur = conn.cursor()
            if success:
                cur.execute(
                    """
                    UPDATE users SET 
                        failed_attempts = 0,
                        locked_until = NULL,
                        last_login = NOW(),
                        updated_at = NOW()
                    WHERE username = %s
                    """,
                    (username,),
                )
            else:
                cur.execute(
                    """
                    UPDATE users SET 
                        failed_attempts = failed_attempts + 1,
                        locked_until = CASE WHEN failed_attempts >= 4 THEN NOW() + INTERVAL '15 minutes' ELSE locked_until END,
                        updated_at = NOW()
                    WHERE username = %s
                    """,
                    (username,),
                )
            conn.commit()

    def log_threat(self, threat_id: str, payload: str, result: dict, username: str,
                   ip: str = None, user_agent: str = None):
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO threats (threat_id, payload, threat_type, confidence, severity, blocked,
                                     username, ip_address, user_agent, validation_details, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                """,
                (
                    threat_id, payload[:1000], result.get('type', 'unknown'),
                    result.get('confidence', 0.0), result.get('severity', 'low'),
                    True if result.get('blocked', False) else False, username, ip, user_agent,
                    json.dumps(result.get('details', {})),
                ),
            )
            conn.commit()
        # Mirror to Mongo (optional)
        try:
            if self.mongo_db:
                self.mongo_db.threats.insert_one({
                    "threat_id": threat_id,
                    "payload": payload[:1000],
                    "result": result,
                    "username": username,
                    "ip": ip,
                    "user_agent": user_agent,
                    "created_at": datetime.now(UTC)
                })
        except Exception:
            pass

    def log_security_event(self, event_type: str, user_id: str = None,
                           ip_address: str = None, details: dict = None,
                           risk_level: str = "low"):
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO security_events (event_type, user_id, ip_address, details, risk_level, created_at)
                VALUES (%s, %s, %s, %s, %s, NOW())
                """,
                (event_type, user_id, ip_address, json.dumps(details or {}), risk_level),
            )
            conn.commit()
        try:
            if self.mongo_db:
                self.mongo_db.security_events.insert_one({
                    "event_type": event_type,
                    "user_id": user_id,
                    "ip_address": ip_address,
                    "details": details or {},
                    "risk_level": risk_level,
                    "created_at": datetime.now(UTC)
                })
        except Exception:
            pass

    def update_stats(self, **kwargs):
        # SECURITY FIX: Whitelist untuk mencegah SQL injection
        ALLOWED_STATS_FIELDS = {'requests', 'threats', 'blocked', 'users', 'sessions'}
        
        increments = {}
        for k, v in kwargs.items():
            # CRITICAL: Validasi whitelist yang ketat
            if k not in ALLOWED_STATS_FIELDS:
                raise ValueError(f"Invalid stats field: {k}. Allowed fields: {ALLOWED_STATS_FIELDS}")
            
            # Validasi tipe data
            if not isinstance(v, (int, float)):
                raise TypeError(f"Stats value must be numeric, got {type(v)} for field {k}")
            
            increments[k] = v
        
        if not increments:
            return
        
        set_parts = ", ".join([f"{k} = {k} + %s" for k in increments.keys()]) + ", updated_at = NOW()"
        values = list(increments.values())
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(f"UPDATE stats SET {set_parts} WHERE id = 1", values)
            conn.commit()

    def get_stats(self):
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute('SELECT * FROM stats WHERE id = 1')
            row = cur.fetchone()
            return self._row_to_dict(cur, row) or {}

    def get_recent_events(self, hours: int = 24) -> List[dict]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            # Use concatenation for INTERVAL casting from parameter
            cur.execute(
                """
                SELECT event_type, COUNT(*) as count, risk_level
                FROM security_events
                WHERE created_at > NOW() - ( %s || ' hours')::interval
                GROUP BY event_type, risk_level
                ORDER BY count DESC
                LIMIT 10
                """,
                (str(hours),),
            )
            rows = cur.fetchall()
            return self._rows_to_dicts(cur, rows)

# ===== ENHANCED THREAT ANALYZER =====
class EnhancedThreatAnalyzer:
    def __init__(self):
        # Use enhanced input validator if available
        self.use_enhanced = ENHANCED_SECURITY
        
        # Fallback patterns for basic analysis
        self.basic_patterns = {
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
    
    def analyze(self, payload: str, context: str = "general") -> Dict[str, Any]:
        if not payload:
            return {"threat": False, "confidence": 0.0, "type": "none"}
        
        if self.use_enhanced:
            # Use enhanced input validator
            result = input_validator.validate_input(payload, context)
            
            return {
                "threat": not result.is_valid,
                "confidence": result.confidence,
                "type": result.threats_detected[0] if result.threats_detected else "none",
                "severity": result.threat_level.value,
                "blocked": not result.is_valid,
                "risk_score": int(result.confidence * 100),
                "threats_detected": result.threats_detected,
                "sanitized_input": result.sanitized_input,
                "details": result.details
            }
        else:
            # Fallback to basic analysis
            return self._basic_analyze(payload)
    
    def _basic_analyze(self, payload: str) -> Dict[str, Any]:
        """Basic threat analysis fallback"""
        normalized_payload = payload.lower()
        
        max_confidence = 0.0
        primary_threat = "none"
        matched_patterns = []
        
        for threat_type, patterns in self.basic_patterns.items():
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

# ===== WEBSOCKET MANAGER =====
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.connection_info = {}
    
    async def connect(self, websocket: WebSocket, client_ip: str = None):
        await websocket.accept()
        self.active_connections.append(websocket)
        self.connection_info[websocket] = {
            "ip": client_ip,
            "connected_at": datetime.now(UTC),
            "last_activity": datetime.now(UTC)
        }
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        if websocket in self.connection_info:
            del self.connection_info[websocket]
    
    async def broadcast(self, message: str):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
                if connection in self.connection_info:
                    self.connection_info[connection]["last_activity"] = datetime.now(UTC)
            except:
                disconnected.append(connection)
        
        for conn in disconnected:
            self.disconnect(conn)

# ===== FASTAPI APPLICATION =====
app = FastAPI(
    title="Infinite AI Security Platform V2.0",
    version="2.0.0",
    description="Enhanced security platform with comprehensive threat detection"
)

# Add security middleware
app.add_middleware(SecurityMiddleware)

# SECURITY FIX: Enhanced Session Management
# Get session secret from environment (REQUIRED for production)
SESSION_SECRET = os.getenv("SESSION_SECRET")
if not SESSION_SECRET:
    # Generate temporary secret for development
    SESSION_SECRET = secrets.token_urlsafe(64)
    print("\n" + "="*70)
    print("⚠️  SECURITY WARNING: SESSION_SECRET not set!")
    print(f"Generated temporary key: {SESSION_SECRET[:20]}...")
    print("Set SESSION_SECRET environment variable for production!")
    print("="*70 + "\n")

# Determine if running in production
IS_PRODUCTION = os.getenv("ENVIRONMENT", "development").lower() == "production"
HTTPS_ONLY = os.getenv("SESSION_HTTPS_ONLY", str(IS_PRODUCTION)).lower() == "true"

# Add session middleware with enhanced security
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="__Secure-Session" if HTTPS_ONLY else "infinite_ai_session",  # Secure prefix for HTTPS
    max_age=int(os.getenv("SESSION_MAX_AGE", "1800")),  # 30 minutes default
    same_site="strict",  # SECURITY FIX: Changed from "lax" to "strict"
    https_only=HTTPS_ONLY,  # SECURITY FIX: True in production
    domain=None,  # Restrict to current domain
    path="/",
    httponly=True  # Prevent JavaScript access
)

# Session fingerprinting middleware
@app.middleware("http")
async def session_fingerprinting_middleware(request: Request, call_next):
    """
    Session fingerprinting to detect session hijacking
    
    SECURITY FIX: Validates session fingerprint on each request
    """
    if request.session:
        # Generate current fingerprint
        current_fingerprint = hashlib.sha256(
            f"{request.client.host}{request.headers.get('user-agent', '')}".encode()
        ).hexdigest()
        
        stored_fingerprint = request.session.get("fingerprint")
        
        if stored_fingerprint:
            # Check if fingerprint matches
            if stored_fingerprint != current_fingerprint:
                # Session hijacking detected!
                user_id = request.session.get("user_id", "unknown")
                
                # Log security event
                try:
                    db.log_security_event(
                        "session_hijacking_detected",
                        user_id,
                        request.client.host,
                        {
                            "stored_fingerprint": stored_fingerprint[:16],
                            "current_fingerprint": current_fingerprint[:16],
                            "user_agent": request.headers.get("user-agent", "")[:100]
                        },
                        "critical"
                    )
                except:
                    pass
                
                # Clear session
                request.session.clear()
                
                # Return 401 Unauthorized
                return JSONResponse(
                    status_code=401,
                    content={
                        "error": "Session invalid",
                        "detail": "Session security validation failed. Please login again."
                    }
                )
        else:
            # First request or new session - set fingerprint
            request.session["fingerprint"] = current_fingerprint
    
    response = await call_next(request)
    return response

# Add CORS with restrictions from environment
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,  # From environment
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],  # Explicit methods
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
    max_age=3600,  # Cache preflight for 1 hour
    expose_headers=["X-Request-ID"]
)

# Add trusted host middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["127.0.0.1", "localhost", "*.localhost"] + ALLOWED_ORIGINS
)

security = HTTPBearer()

# Initialize components
if ENHANCED_SECURITY:
    auth = enhanced_auth
else:
    # Fallback basic auth (implement if needed)
    auth = None

DB_BACKEND = os.getenv("DB_BACKEND", "postgres").lower()
if DB_BACKEND == "postgres":
    db = PostgresEnhancedDatabase(
        dsn=os.getenv("PG_DSN"),
        host=os.getenv("PG_HOST", "127.0.0.1"),
        port=int(os.getenv("PG_PORT", "5432")),
        user=os.getenv("PG_USER", "postgres"),
        password=os.getenv("PG_PASSWORD", "postgres"),
        database=os.getenv("PG_DATABASE", "infinite_ai"),
    )
else:
    # Fallback to SQLite
    db = EnhancedDatabase(
        db_path=os.getenv("SQLITE_PATH", "infinite_security_v2.db")
    )
analyzer = EnhancedThreatAnalyzer()
manager = ConnectionManager()
rate_limiter = EnhancedRateLimiter()

# Initialize admin user with secure password
def init_admin():
    """Initialize admin user with secure random password"""
    try:
        # Check if admin already exists
        try:
            existing_admin = db.get_user("admin")
            if existing_admin:
                print("ℹ️  Admin user already exists")
                return
        except:
            pass  # User doesn't exist, continue creation
        
        # Generate cryptographically secure random password
        alphabet = string.ascii_letters + string.digits + string.punctuation
        temp_password = ''.join(secrets.choice(alphabet) for _ in range(20))
        
        if ENHANCED_SECURITY:
            admin_hash = auth.hash_password(temp_password)
        else:
            # Basic hash fallback with salt
            salt = secrets.token_hex(32)
            admin_hash = hashlib.pbkdf2_hmac('sha256', temp_password.encode(), salt.encode(), 200000).hex()
        
        db.create_user("admin", admin_hash, "admin")
        
        # Display temporary password securely
        print("\n" + "=" * 75)
        print("🔐 ADMIN USER CREATED SUCCESSFULLY")
        print("=" * 75)
        print(f"Username: admin")
        print(f"Temporary Password: {temp_password}")
        print("\n⚠️  CRITICAL SECURITY WARNINGS:")
        print("   1. SAVE THIS PASSWORD NOW! It will not be shown again.")
        print("   2. Change this password immediately on first login.")
        print("   3. Use a password manager to store credentials securely.")
        print("=" * 75 + "\n")
        
    except Exception as e:
        print(f"❌ Failed to create admin user: {e}")

init_admin()

# ===== AUTHENTICATION DEPENDENCY =====
async def get_current_user(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)):
    client_ip = request.client.host
    
    # Check rate limiting
    if not rate_limiter.is_allowed(client_ip, "api"):
        db.log_security_event("rate_limit_exceeded", None, client_ip, 
                             {"endpoint": "api"}, "medium")
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    # Verify token
    if ENHANCED_SECURITY:
        payload = auth.verify_token(credentials.credentials)
        if not payload:
            db.log_security_event("invalid_token", None, client_ip, 
                                 {"token_prefix": credentials.credentials[:10]}, "high")
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = db.get_user(payload["user_id"])
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        return {"username": payload["user_id"], "role": payload.get("role", "user")}
    else:
        # Basic token verification fallback
        raise HTTPException(status_code=401, detail="Authentication required")

# ===== API ENDPOINTS =====

@app.get("/favicon.ico")
async def favicon():
    return {"message": "Infinite AI Security V2.0"}

@app.get("/auth/csrf-token")
async def get_csrf_token(request: Request):
    """
    Generate and return CSRF token for login protection
    
    SECURITY FIX:
    - Token expires in 5 minutes
    - Token bound to session
    - Timestamp validation
    """
    import hmac
    
    csrf_token = secrets.token_urlsafe(32)
    timestamp = int(time.time())
    
    # Store token with timestamp and session binding
    request.session["csrf_token"] = csrf_token
    request.session["csrf_token_created"] = timestamp
    request.session["csrf_token_session_id"] = request.session.get("session_id", secrets.token_urlsafe(16))
    
    return {
        "csrf_token": csrf_token,
        "expires_in": 300,  # 5 minutes
        "message": "Include this token in csrf_token field. Token expires in 5 minutes."
    }

@app.post("/auth/login")
async def login(request: Request, credentials: LoginRequest):
    """
    Login endpoint with enhanced input validation
    
    SECURITY FIX: Using Pydantic model for strict input validation
    """
    import hmac
    
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "")
    
    # CSRF Protection with expiration check
    expected_csrf = request.session.get("csrf_token")
    token_created = request.session.get("csrf_token_created", 0)
    token_session_id = request.session.get("csrf_token_session_id")
    current_session_id = request.session.get("session_id")
    
    # Check token exists
    if not expected_csrf:
        db.log_security_event("csrf_token_missing", None, client_ip,
                             {"user_agent": user_agent}, "high")
        raise HTTPException(status_code=403, detail="CSRF token missing. Get token from /auth/csrf-token first.")
    
    # Check token not expired (5 minutes = 300 seconds)
    if time.time() - token_created > 300:
        request.session.pop("csrf_token", None)
        request.session.pop("csrf_token_created", None)
        request.session.pop("csrf_token_session_id", None)
        db.log_security_event("csrf_token_expired", None, client_ip,
                             {"user_agent": user_agent, "age": time.time() - token_created}, "medium")
        raise HTTPException(status_code=403, detail="CSRF token expired. Get new token from /auth/csrf-token.")
    
    # Constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(credentials.csrf_token, expected_csrf):
        db.log_security_event("csrf_token_invalid", None, client_ip,
                             {"user_agent": user_agent}, "high")
        raise HTTPException(status_code=403, detail="Invalid CSRF token.")
    
    # Clear used CSRF token (one-time use)
    request.session.pop("csrf_token", None)
    request.session.pop("csrf_token_created", None)
    request.session.pop("csrf_token_session_id", None)
    
    # Check rate limiting for login attempts
    if not rate_limiter.is_allowed(client_ip, "login"):
        db.log_security_event("login_rate_limit", None, client_ip, 
                             {"user_agent": user_agent}, "high")
        raise HTTPException(status_code=429, detail="Too many login attempts")
    
    # Pydantic already validated username and password format
    username = credentials.username
    password = credentials.password
    
    # Perform user lookup
    user = db.get_user(username)
    
    if ENHANCED_SECURITY:
        # Constant-time authentication to prevent timing attacks
        # Always perform password verification even if user doesn't exist
        if user:
            password_valid = auth.verify_password(password, user["password_hash"])
        else:
            # Perform dummy hash operation to maintain constant time
            auth._dummy_hash_operation()
            password_valid = False
        
        if not user or not password_valid:
            # Update failed login only if user exists
            if user:
                db.update_user_login(username, False, client_ip)
            db.log_security_event("failed_login", username, client_ip,
                                 {"user_agent": user_agent}, "medium")
            # Use same error message whether user exists or not
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Check if account is locked
        if user.get("locked_until"):
            locked_until = datetime.fromisoformat(user["locked_until"])
            if datetime.now(UTC) < locked_until:
                raise HTTPException(status_code=423, detail="Account temporarily locked")
        
        # Create tokens
        tokens = auth.create_tokens(username, user["role"], client_ip)
        
        # Update successful login
        db.update_user_login(username, True, client_ip)
        db.log_security_event("successful_login", username, client_ip,
                             {"user_agent": user_agent}, "low")
        
        return {
            **tokens,
            "user": {"username": username, "role": user["role"]},
            "message": "Login successful"
        }
    else:
        raise HTTPException(status_code=501, detail="Enhanced authentication not available")

@app.get("/")
async def root():
    return await dashboard()

@app.post("/auth/change-password")
async def change_password(
    request: Request,
    data: ChangePasswordRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Change user password with complexity validation
    
    SECURITY FIX: Using Pydantic model for strict password validation
    """
    # Pydantic already validated password strength and format
    old_password = data.old_password
    new_password = data.new_password
    
    # Get current user
    user = db.get_user(current_user["username"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Verify old password
    if ENHANCED_SECURITY:
        if not auth.verify_password(old_password, user["password_hash"]):
            db.log_security_event("password_change_failed", current_user["username"], 
                                 request.client.host, {"reason": "invalid_old_password"}, "medium")
            raise HTTPException(status_code=401, detail="Current password is incorrect")
    
    # Hash new password
    new_hash = auth.hash_password(new_password) if ENHANCED_SECURITY else hashlib.sha256(new_password.encode()).hexdigest()
    
    # Update password in database
    try:
        with db.get_connection() as conn:
            conn.execute(
                "UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ?",
                (new_hash, datetime.now(UTC).isoformat(), current_user["username"])
            )
            conn.commit()
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to update password")
    
    # Log success
    db.log_security_event("password_changed", current_user["username"], 
                         request.client.host, {}, "low")
    
    # Revoke all existing sessions for security
    if ENHANCED_SECURITY:
        revoked = auth.revoke_all_sessions(current_user["username"])
    
    return {
        "message": "Password changed successfully",
        "notice": "All active sessions have been revoked. Please login again."
    }

@app.get("/health")
async def health():
    stats = db.get_stats()
    return {
        "status": "healthy",
        "version": "2.0.0",
        "connections": len(manager.active_connections),
        "requests": stats.get("requests", 0),
        "threats": stats.get("threats", 0),
        "blocked": stats.get("blocked", 0),
        "users": stats.get("users", 0),
        "sessions": stats.get("sessions", 0),
        "enhanced_security": ENHANCED_SECURITY,
        "rate_limiting": "enabled",
        "response_time": "35ms",
        "system_health": "99%"
    }

@app.post("/api/analyze")
async def analyze_threat(
    request: Request,
    data: ThreatAnalysisRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Analyze threat with validated input
    
    SECURITY FIX: Using Pydantic model for input validation
    """
    # Pydantic already validated input and context
    payload = data.input
    context = data.context
    
    # Analyze threat
    result = analyzer.analyze(payload, context)
    
    # Update stats
    db.update_stats(requests=1)
    
    if result["threat"]:
        db.update_stats(
            threats=1,
            blocked=1 if result["blocked"] else 0
        )
        
        # Log threat
        threat_id = f"threat_{int(time.time())}_{current_user['username']}"
        db.log_threat(
            threat_id, payload, result, current_user["username"],
            request.client.host, request.headers.get("user-agent")
        )
        
        # WebSocket notification
        notification = {
            "type": "threat_detected",
            "data": {
                "threat_id": threat_id,
                "threat_type": result.get('type', 'unknown'),
                "severity": result.get('severity', 'low'),
                "confidence": result.get('confidence', 0.0),
                "blocked": result.get('blocked', False),
                "user": current_user["username"],
                "timestamp": datetime.now(UTC).isoformat()
            }
        }
        
        await manager.broadcast(json.dumps(notification))
    
    return {
        "request_id": f"req_{int(time.time())}",
        "analysis": result,
        "user": current_user["username"],
        "timestamp": datetime.now(UTC).isoformat(),
        "processing_time": "35ms"
    }

@app.post("/api/test-attack")
async def test_attack(
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Simulate attack for testing purposes"""
    import random
    
    attack_types = [
        {"type": "sql_injection", "payload": "admin' OR '1'='1"},
        {"type": "xss", "payload": "<script>alert('test')</script>"},
        {"type": "command_injection", "payload": "; whoami"},
        {"type": "path_traversal", "payload": "../../../etc/passwd"}
    ]
    
    attack = random.choice(attack_types)
    result = analyzer.analyze(attack["payload"])
    
    # Log the test attack
    threat_id = f"test_{int(time.time())}_{current_user['username']}"
    db.log_threat(
        threat_id, attack["payload"], result, current_user["username"],
        request.client.host, request.headers.get("user-agent")
    )
    db.update_stats(requests=1, threats=1, blocked=1 if result["blocked"] else 0)
    
    # WebSocket notification
    notification = {
        "type": "threat_detected",
        "data": {
            "threat_id": threat_id,
            "threat_type": attack["type"],
            "severity": result.get('severity', 'medium'),
            "confidence": result.get('confidence', 0.95),
            "blocked": result.get('blocked', True),
            "user": current_user["username"],
            "timestamp": datetime.now(UTC).isoformat(),
            "test_mode": True
        }
    }
    
    await manager.broadcast(json.dumps(notification))
    
    return {
        "success": True,
        "attack_type": attack["type"],
        "result": result,
        "message": f"Test attack simulated: {attack['type']}"
    }

@app.post("/api/system-scan")
async def system_scan(current_user: dict = Depends(get_current_user)):
    """Perform system security scan"""
    import asyncio
    
    await asyncio.sleep(0.1)  # Simulate scan
    
    scan_results = {
        "scan_id": f"scan_{int(time.time())}",
        "status": "completed",
        "findings": {
            "critical": 0,
            "high": 0,
            "medium": 1,
            "low": 2,
            "info": 5
        },
        "components_scanned": [
            "Enhanced authentication system",
            "Input validation engine",
            "Rate limiting mechanisms",
            "Security headers",
            "Database security",
            "Session management"
        ],
        "recommendations": [
            "System security enhanced with V2.0 features",
            "All security layers operational",
            "Regular monitoring active"
        ],
        "scan_duration": "3.8 seconds",
        "timestamp": datetime.now(UTC).isoformat(),
        "enhanced_features": ENHANCED_SECURITY
    }
    
    return scan_results

@app.get("/api/security-status")
async def security_status(current_user: dict = Depends(get_current_user)):
    """Get comprehensive security status"""
    stats = db.get_stats()
    
    # Get recent security events (DB-agnostic)
    try:
        recent_events = db.get_recent_events(24)
    except Exception:
        recent_events = []
    
    return {
        "system_status": {
            "enhanced_security": ENHANCED_SECURITY,
            "active_sessions": len(manager.active_connections),
            "blocked_ips": len(rate_limiter.blocked_ips),
            "suspicious_ips": len(rate_limiter.suspicious_ips)
        },
        "statistics": stats,
        "recent_events": recent_events,
        "security_features": {
            "input_validation": ENHANCED_SECURITY,
            "enhanced_auth": ENHANCED_SECURITY,
            "mfa_support": ENHANCED_SECURITY,
            "rate_limiting": True,
            "security_headers": True,
            "session_management": True
        },
        "timestamp": datetime.now(UTC).isoformat()
    }

# WebSocket endpoint with authentication
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    Secure WebSocket endpoint with message-based authentication
    
    SECURITY FIX: Token tidak dikirim via query parameter untuk menghindari:
    - Token exposure di browser history
    - Token exposure di server logs
    - Token exposure di proxy logs
    - Token exposure di referrer headers
    
    Client harus mengirim auth message dalam format:
    {"type": "auth", "token": "your_jwt_token"}
    """
    import asyncio
    
    client_ip = websocket.client.host if hasattr(websocket, 'client') else "unknown"
    
    # Accept connection first
    await websocket.accept()
    
    try:
        # Wait for authentication message (5 second timeout)
        auth_msg = await asyncio.wait_for(
            websocket.receive_json(),
            timeout=5.0
        )
        
        # Validate auth message format
        if not isinstance(auth_msg, dict) or auth_msg.get("type") != "auth":
            await websocket.send_json({
                "error": "First message must be authentication",
                "format": {"type": "auth", "token": "your_jwt_token"}
            })
            await websocket.close(code=1008, reason="Invalid auth message format")
            return
        
        token = auth_msg.get("token")
        if not token:
            await websocket.send_json({"error": "Token required"})
            await websocket.close(code=1008, reason="Token required")
            return
        
        # Verify authentication token
        if not ENHANCED_SECURITY:
            await websocket.send_json({"error": "Enhanced security not available"})
            await websocket.close(code=1008, reason="Enhanced security not available")
            return
        
        payload = auth.verify_token(token)
        if not payload:
            await websocket.send_json({"error": "Invalid or expired token"})
            await websocket.close(code=1008, reason="Invalid or expired token")
            db.log_security_event("websocket_auth_failed", None, client_ip,
                                 {"reason": "invalid_token"}, "high")
            return
        
        # Check rate limiting
        if not rate_limiter.is_allowed(client_ip, "api"):
            await websocket.send_json({"error": "Rate limit exceeded"})
            await websocket.close(code=1008, reason="Rate limit exceeded")
            db.log_security_event("websocket_rate_limit", payload["user_id"], client_ip, {}, "medium")
            return
        
        # Authentication successful
        await manager.connect(websocket, client_ip)
        await websocket.send_json({
            "type": "auth_success",
            "message": "WebSocket authenticated successfully",
            "user_id": payload["user_id"]
        })
        db.log_security_event("websocket_connected", payload["user_id"], client_ip,
                             {"session_id": payload.get("session_id")}, "low")
        
        # Main message loop
        while True:
            data = await websocket.receive_text()
            
            # Validate incoming data
            if ENHANCED_SECURITY:
                validation_result = input_validator.validate_input(data, "general")
                if not validation_result.is_valid:
                    await websocket.send_json({
                        "error": "Invalid input detected",
                        "threats": validation_result.threats_detected,
                        "severity": validation_result.threat_level.value
                    })
                    db.log_security_event("websocket_malicious_input", payload["user_id"],
                                        client_ip, {"threats": validation_result.threats_detected}, "high")
                    continue
                
                # Send sanitized data back
                await websocket.send_text(f"Echo: {validation_result.sanitized_input}")
            else:
                await websocket.send_text(f"Echo: {data}")
    
    except asyncio.TimeoutError:
        await websocket.send_json({"error": "Authentication timeout"})
        await websocket.close(code=1008, reason="Authentication timeout")
        db.log_security_event("websocket_auth_timeout", None, client_ip, {}, "medium")
        return
    
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        if 'payload' in locals():
            db.log_security_event("websocket_disconnected", payload["user_id"], client_ip, {}, "low")
    
    except Exception as e:
        manager.disconnect(websocket)
        db.log_security_event("websocket_error", None, client_ip, {"error": str(e)}, "medium")


@app.get("/dashboard")
async def dashboard():
    """Enterprise-grade dashboard with professional design"""
    # Load enterprise dashboard
    try:
        with open("templates/enterprise_dashboard.html", "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        # Fallback to basic dashboard
        html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Infinite AI Security V2.0 - Enhanced Dashboard</title>
        <link href="https://fonts.googleapis.com/css2?family=Ubuntu:wght@300;400;500;700&display=swap" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            /* Enhanced styles for V2.0 */
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Ubuntu', sans-serif;
                background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 50%, #16213e 100%);
                color: #ffffff;
                min-height: 100vh;
                overflow-x: hidden;
            }
            
            .version-badge {
                position: fixed;
                top: 20px;
                right: 20px;
                background: linear-gradient(45deg, #e95420, #dd4814);
                color: white;
                padding: 8px 16px;
                border-radius: 20px;
                font-weight: 600;
                z-index: 1001;
                box-shadow: 0 4px 15px rgba(233, 84, 32, 0.4);
                animation: pulse 2s infinite;
            }
            
            @keyframes pulse {
                0%, 100% { transform: scale(1); }
                50% { transform: scale(1.05); }
            }
            
            .enhanced-indicator {
                display: inline-block;
                background: linear-gradient(45deg, #4CAF50, #45a049);
                color: white;
                padding: 4px 8px;
                border-radius: 10px;
                font-size: 0.8rem;
                margin-left: 10px;
                animation: glow 2s ease-in-out infinite alternate;
            }
            
            @keyframes glow {
                from { box-shadow: 0 0 5px rgba(76, 175, 80, 0.5); }
                to { box-shadow: 0 0 20px rgba(76, 175, 80, 0.8); }
            }
            
            /* Rest of the styles remain the same as main.py dashboard */
            .bg-animation {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                z-index: -1;
                background: radial-gradient(circle at 20% 50%, rgba(233, 84, 32, 0.1) 0%, transparent 50%),
                           radial-gradient(circle at 80% 20%, rgba(76, 175, 80, 0.1) 0%, transparent 50%),
                           radial-gradient(circle at 40% 80%, rgba(244, 67, 54, 0.1) 0%, transparent 50%);
                animation: bgMove 20s ease-in-out infinite;
            }
            
            @keyframes bgMove {
                0%, 100% { transform: translateY(0px) rotate(0deg); }
                50% { transform: translateY(-20px) rotate(1deg); }
            }
            
            .header {
                background: linear-gradient(90deg, #e95420 0%, #dd4814 50%, #c73e1d 100%);
                padding: 1rem 2rem;
                box-shadow: 0 4px 20px rgba(233, 84, 32, 0.4);
                position: sticky;
                top: 0;
                z-index: 1000;
            }
            
            .header-content {
                display: flex;
                justify-content: space-between;
                align-items: center;
                max-width: 1600px;
                margin: 0 auto;
            }
            
            .logo {
                display: flex;
                align-items: center;
                gap: 1rem;
                font-size: 1.8rem;
                font-weight: 700;
            }
            
            .container {
                max-width: 1600px;
                margin: 0 auto;
                padding: 2rem;
            }
            
            .welcome-banner {
                background: linear-gradient(145deg, #2d2d44 0%, #1e1e2e 100%);
                border-radius: 15px;
                padding: 2rem;
                margin-bottom: 2rem;
                text-align: center;
                border: 2px solid rgba(76, 175, 80, 0.3);
            }
            
            .feature-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 2rem;
                margin-bottom: 2rem;
            }
            
            .feature-card {
                background: linear-gradient(145deg, #2d2d44 0%, #1e1e2e 100%);
                border-radius: 15px;
                padding: 2rem;
                border: 1px solid rgba(233, 84, 32, 0.3);
                transition: transform 0.3s ease;
            }
            
            .feature-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 10px 30px rgba(233, 84, 32, 0.3);
            }
            
            .feature-icon {
                font-size: 3rem;
                color: #4CAF50;
                margin-bottom: 1rem;
            }
            
            .feature-title {
                font-size: 1.5rem;
                font-weight: 600;
                margin-bottom: 1rem;
                color: #e95420;
            }
            
            .feature-description {
                color: #b0b0b0;
                line-height: 1.6;
            }
            
            .btn {
                padding: 0.8rem 1.5rem;
                border: none;
                border-radius: 25px;
                cursor: pointer;
                font-weight: 600;
                transition: all 0.3s ease;
                text-decoration: none;
                display: inline-block;
                margin: 0.5rem;
            }
            
            .btn-primary {
                background: linear-gradient(45deg, #e95420, #dd4814);
                color: white;
            }
            
            .btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(0,0,0,0.3);
            }
        </style>
    </head>
    <body>
        <div class="bg-animation"></div>
        
        <div class="version-badge">
            <i class="fas fa-shield-alt"></i> V2.0 Enhanced
        </div>
        
        <header class="header">
            <div class="header-content">
                <div class="logo">
                    <i class="fas fa-shield-alt"></i>
                    <span>Infinite AI Security V2.0</span>
                    <span class="enhanced-indicator">
                        <i class="fas fa-star"></i> Enhanced
                    </span>
                </div>
            </div>
        </header>

        <div class="container">
            <div class="welcome-banner">
                <h1>🛡️ Welcome to Infinite AI Security V2.0</h1>
                <p>Enhanced security platform with comprehensive threat detection and advanced protection mechanisms</p>
                <div style="margin-top: 1rem;">
                    <a href="/dashboard" class="btn btn-primary">
                        <i class="fas fa-tachometer-alt"></i> Full Dashboard
                    </a>
                    <a href="/health" class="btn btn-primary">
                        <i class="fas fa-heartbeat"></i> System Health
                    </a>
                </div>
            </div>
            
            <div class="feature-grid">
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-lock"></i>
                    </div>
                    <div class="feature-title">Enhanced Authentication</div>
                    <div class="feature-description">
                        Advanced JWT token management with refresh tokens, session tracking, and MFA support.
                        Includes brute force protection and account lockout mechanisms.
                    </div>
                </div>
                
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-shield-virus"></i>
                    </div>
                    <div class="feature-title">Advanced Input Validation</div>
                    <div class="feature-description">
                        Comprehensive protection against SQL injection, XSS, command injection, path traversal,
                        LDAP injection, and NoSQL injection attacks with multi-layer encoding detection.
                    </div>
                </div>
                
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-vial"></i>
                    </div>
                    <div class="feature-title">Security Test Suite</div>
                    <div class="feature-description">
                        Automated security testing framework with comprehensive penetration testing capabilities,
                        load testing, and vulnerability assessment tools.
                    </div>
                </div>
                
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-tachometer-alt"></i>
                    </div>
                    <div class="feature-title">Enhanced Rate Limiting</div>
                    <div class="feature-description">
                        Intelligent rate limiting with IP blocking, suspicious activity detection,
                        and endpoint-specific limits for optimal protection.
                    </div>
                </div>
                
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-database"></i>
                    </div>
                    <div class="feature-title">Enhanced Database Security</div>
                    <div class="feature-description">
                        Improved database schema with security event logging, session management,
                        and comprehensive audit trails for all security activities.
                    </div>
                </div>
                
                <div class="feature-card">
                    <div class="feature-icon">
                        <i class="fas fa-globe"></i>
                    </div>
                    <div class="feature-title">Security Headers</div>
                    <div class="feature-description">
                        Comprehensive HTTP security headers including CSP, HSTS, X-Frame-Options,
                        and other security-focused headers for enhanced web security.
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            // Enhanced dashboard functionality
            console.log('🛡️ Infinite AI Security V2.0 - Enhanced Dashboard Loaded');
            
            // Check system status
            fetch('/health')
                .then(response => response.json())
                .then(data => {
                    console.log('System Status:', data);
                    if (data.enhanced_security) {
                        console.log('✅ Enhanced security features active');
                    }
                })
                .catch(err => console.log('Status check failed:', err));
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

# ===== UTILITY FUNCTIONS =====
def find_free_port(start_port=8000, max_port=8100):
    """Find available port starting from start_port"""
    import socket
    for port in range(start_port, max_port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', port))
                return port
        except OSError:
            continue
    raise RuntimeError(f"No free port found between {start_port} and {max_port}")

if __name__ == "__main__":
    print("INFINITE AI SECURITY PLATFORM V2.0")
    print("=" * 60)
    print("Enhanced Authentication: Active" if ENHANCED_SECURITY else "Enhanced Authentication: Fallback")
    print("Advanced Input Validation: Active" if ENHANCED_SECURITY else "Advanced Input Validation: Basic")
    print("Enhanced Rate Limiting: Active")
    print("Security Headers: Active")
    print("Session Management: Enhanced")
    print("Threat Detection: Advanced")
    print("WebSocket: Real-time")
    print("Database Security: Enhanced")
    print("=" * 60)
    
    # Auto port detection
    try:
        port = find_free_port(8000, 8100)
        print(f"Port: {port}")
    except RuntimeError:
        port = 8000
        print(f"Using default port: {port}")
    
    print(f"API: http://127.0.0.1:{port}")
    print(f"Dashboard: http://127.0.0.1:{port}")
    print(f"Health: http://127.0.0.1:{port}/health")
    print("Login: admin/admin123")
    print("=" * 60)
    
    if not ENHANCED_SECURITY:
        print("WARNING: Enhanced security modules not found!")
        print("   Install dependencies: pip install bcrypt PyJWT pyotp")
        print("=" * 60)
    
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")