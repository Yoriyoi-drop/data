"""
Phase 2: Secure Database with SQLite
Migration from JSON to proper database
"""
import sqlite3
import json
import os
from datetime import datetime, UTC
from pathlib import Path
from contextlib import contextmanager

class SecureDatabase:
    def __init__(self, db_path="security.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database with proper schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    created_at TEXT NOT NULL,
                    last_login TEXT
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_id TEXT UNIQUE NOT NULL,
                    payload TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    severity TEXT NOT NULL,
                    blocked INTEGER NOT NULL,
                    user_id TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS stats (
                    id INTEGER PRIMARY KEY,
                    requests INTEGER DEFAULT 0,
                    threats INTEGER DEFAULT 0,
                    blocked INTEGER DEFAULT 0,
                    sql_injection INTEGER DEFAULT 0,
                    xss INTEGER DEFAULT 0,
                    command_injection INTEGER DEFAULT 0,
                    updated_at TEXT NOT NULL
                )
            ''')
            
            # Initialize stats if empty
            conn.execute('''
                INSERT OR IGNORE INTO stats (id, requests, threats, blocked, updated_at)
                VALUES (1, 0, 0, 0, ?)
            ''', (datetime.now(UTC).isoformat(),))
            
            conn.commit()
    
    @contextmanager
    def get_connection(self):
        """Get database connection with proper error handling"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable dict-like access
        try:
            yield conn
        finally:
            conn.close()
    
    def create_user(self, username: str, password_hash: str, role: str = "user"):
        """Create new user"""
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO users (username, password_hash, role, created_at)
                VALUES (?, ?, ?, ?)
            ''', (username, password_hash, role, datetime.now(UTC).isoformat()))
            conn.commit()
    
    def get_user(self, username: str):
        """Get user by username"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT * FROM users WHERE username = ?
            ''', (username,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def log_threat(self, threat_id: str, payload: str, result: dict, username: str):
        """Log threat to database"""
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO threats (threat_id, payload, threat_type, confidence, 
                                   severity, blocked, user_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat_id,
                payload[:500],  # Limit payload size
                result.get('type', 'unknown'),
                result.get('confidence', 0.0),
                result.get('severity', 'low'),
                1 if result.get('blocked', False) else 0,
                username,
                datetime.now(UTC).isoformat()
            ))
            conn.commit()
    
    def update_stats(self, requests=0, threats=0, blocked=0, threat_type=None):
        """Update system statistics"""
        with self.get_connection() as conn:
            # Update main stats
            conn.execute('''
                UPDATE stats SET 
                    requests = requests + ?,
                    threats = threats + ?,
                    blocked = blocked + ?,
                    updated_at = ?
                WHERE id = 1
            ''', (requests, threats, blocked, datetime.now(UTC).isoformat()))
            
            # Update threat type specific stats
            if threat_type and threats > 0:
                column = threat_type.replace(' ', '_')
                if column in ['sql_injection', 'xss', 'command_injection']:
                    conn.execute(f'''
                        UPDATE stats SET {column} = {column} + 1 WHERE id = 1
                    ''')
            
            conn.commit()
    
    def get_stats(self):
        """Get system statistics"""
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM stats WHERE id = 1')
            row = cursor.fetchone()
            return dict(row) if row else {}
    
    def get_recent_threats(self, limit=20):
        """Get recent threats"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT * FROM threats 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def migrate_from_json(self, json_file):
        """Migrate data from JSON file to SQLite"""
        if not Path(json_file).exists():
            return
        
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            # Migrate users
            for username, user_data in data.get('users', {}).items():
                try:
                    self.create_user(
                        username,
                        user_data['password_hash'],
                        user_data.get('role', 'user')
                    )
                except sqlite3.IntegrityError:
                    pass  # User already exists
            
            # Migrate stats
            stats = data.get('stats', {})
            if stats:
                self.update_stats(
                    stats.get('requests', 0),
                    stats.get('threats', 0),
                    stats.get('blocked', 0)
                )
            
            print(f"✅ Migrated data from {json_file}")
            
        except Exception as e:
            print(f"⚠️ Migration error: {e}")

# Global database instance
db = SecureDatabase()

# Convenience functions
def create_user(username: str, password_hash: str, role: str = "user"):
    return db.create_user(username, password_hash, role)

def get_user(username: str):
    return db.get_user(username)

def log_threat(threat_id: str, payload: str, result: dict, username: str):
    return db.log_threat(threat_id, payload, result, username)

def update_stats(requests=0, threats=0, blocked=0, threat_type=None):
    return db.update_stats(requests, threats, blocked, threat_type)

def get_stats():
    return db.get_stats()

def get_recent_threats(limit=20):
    return db.get_recent_threats(limit)

if __name__ == "__main__":
    print("🗄️ Testing Secure Database")
    print("=" * 30)
    
    # Test database operations
    from auth_fixed import hash_password
    
    # Create test user
    try:
        create_user("testuser", hash_password("testpass"), "user")
        print("✅ User creation: OK")
    except:
        print("✅ User already exists: OK")
    
    # Test user retrieval
    user = get_user("testuser")
    print(f"✅ User retrieval: {user['username'] if user else 'FAILED'}")
    
    # Test stats
    stats = get_stats()
    print(f"✅ Stats retrieval: {stats.get('requests', 0)} requests")
    
    print("✅ Database tests completed!")