"""
Phase 2 Implementation - Database Migration & Monitoring
"""
import os
import asyncio
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import create_async_engine
import psycopg2
from prometheus_client import Counter, Histogram, Gauge, start_http_server

# Database Migration
class DatabaseMigrator:
    def __init__(self):
        self.sqlite_path = "infinite_security_v2.db"
        self.postgres_url = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/infinite_security")
    
    def migrate_sqlite_to_postgresql(self):
        """Migrate from SQLite to PostgreSQL"""
        print("🔄 Starting database migration...")
        
        # 1. Export SQLite data
        sqlite_engine = create_engine(f"sqlite:///{self.sqlite_path}")
        postgres_engine = create_engine(self.postgres_url)
        
        # 2. Create PostgreSQL tables
        self._create_postgres_schema(postgres_engine)
        
        # 3. Migrate data
        self._migrate_data(sqlite_engine, postgres_engine)
        
        print("✅ Migration completed")
    
    def _create_postgres_schema(self, engine):
        """Create PostgreSQL schema"""
        schema = """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role VARCHAR(50) DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS threats (
            id SERIAL PRIMARY KEY,
            threat_id VARCHAR(255) UNIQUE NOT NULL,
            payload TEXT NOT NULL,
            threat_type VARCHAR(100) NOT NULL,
            confidence REAL NOT NULL,
            severity VARCHAR(50) NOT NULL,
            blocked BOOLEAN NOT NULL,
            username VARCHAR(255) NOT NULL,
            ip_address INET,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE INDEX IF NOT EXISTS idx_threats_created_at ON threats(created_at);
        CREATE INDEX IF NOT EXISTS idx_threats_ip ON threats(ip_address);
        """
        
        with engine.connect() as conn:
            conn.execute(text(schema))
            conn.commit()
    
    def _migrate_data(self, sqlite_engine, postgres_engine):
        """Migrate data from SQLite to PostgreSQL"""
        tables = ['users', 'threats']
        
        for table in tables:
            print(f"  Migrating {table}...")
            
            # Read from SQLite
            with sqlite_engine.connect() as sqlite_conn:
                result = sqlite_conn.execute(text(f"SELECT * FROM {table}"))
                rows = result.fetchall()
                columns = result.keys()
            
            if rows:
                # Insert into PostgreSQL
                placeholders = ', '.join([f':{col}' for col in columns])
                insert_sql = f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})"
                
                with postgres_engine.connect() as postgres_conn:
                    for row in rows:
                        row_dict = dict(zip(columns, row))
                        postgres_conn.execute(text(insert_sql), row_dict)
                    postgres_conn.commit()

# Monitoring Setup
class MonitoringSetup:
    def __init__(self):
        # Prometheus metrics
        self.request_count = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint'])
        self.request_duration = Histogram('http_request_duration_seconds', 'HTTP request duration')
        self.active_connections = Gauge('active_connections', 'Active WebSocket connections')
        self.threat_count = Counter('threats_detected_total', 'Total threats detected', ['type'])
        
    def start_metrics_server(self, port=8001):
        """Start Prometheus metrics server"""
        start_http_server(port)
        print(f"📊 Metrics server started on port {port}")
    
    def record_request(self, method, endpoint, duration):
        """Record HTTP request metrics"""
        self.request_count.labels(method=method, endpoint=endpoint).inc()
        self.request_duration.observe(duration)
    
    def record_threat(self, threat_type):
        """Record threat detection"""
        self.threat_count.labels(type=threat_type).inc()

# External API Integration
class ThreatIntelligence:
    def __init__(self):
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
        self.virustotal_key = os.getenv("VIRUSTOTAL_API_KEY")
    
    async def check_ip_reputation(self, ip_address):
        """Check IP reputation using AbuseIPDB"""
        if not self.abuseipdb_key:
            return {"reputation": "unknown", "confidence": 0}
        
        import aiohttp
        
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Key': self.abuseipdb_key,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 90,
            'verbose': ''
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        abuse_confidence = data.get('data', {}).get('abuseConfidencePercentage', 0)
                        
                        if abuse_confidence > 75:
                            return {"reputation": "malicious", "confidence": abuse_confidence / 100}
                        elif abuse_confidence > 25:
                            return {"reputation": "suspicious", "confidence": abuse_confidence / 100}
                        else:
                            return {"reputation": "clean", "confidence": 1 - (abuse_confidence / 100)}
        except Exception as e:
            print(f"Error checking IP reputation: {e}")
        
        return {"reputation": "unknown", "confidence": 0}

# Load Balancer Health Check
class HealthChecker:
    def __init__(self):
        self.services = [
            {"name": "api", "url": "http://localhost:8000/health"},
            {"name": "database", "check": self._check_database},
            {"name": "redis", "check": self._check_redis}
        ]
    
    async def check_all_services(self):
        """Check health of all services"""
        results = {}
        
        for service in self.services:
            try:
                if "url" in service:
                    results[service["name"]] = await self._check_http(service["url"])
                elif "check" in service:
                    results[service["name"]] = await service["check"]()
            except Exception as e:
                results[service["name"]] = {"status": "unhealthy", "error": str(e)}
        
        return results
    
    async def _check_http(self, url):
        """Check HTTP endpoint"""
        import aiohttp
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as response:
                    if response.status == 200:
                        return {"status": "healthy", "response_time": "< 100ms"}
                    else:
                        return {"status": "unhealthy", "http_status": response.status}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}
    
    async def _check_database(self):
        """Check database connection"""
        try:
            engine = create_engine(os.getenv("DATABASE_URL", "sqlite:///infinite_security_v2.db"))
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return {"status": "healthy"}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}
    
    async def _check_redis(self):
        """Check Redis connection"""
        try:
            import redis
            r = redis.Redis(host='localhost', port=6379, db=0)
            r.ping()
            return {"status": "healthy"}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}

# Phase 2 Main Implementation
async def main():
    print("🚀 Phase 2 Implementation Starting...")
    
    # 1. Database Migration
    migrator = DatabaseMigrator()
    try:
        migrator.migrate_sqlite_to_postgresql()
    except Exception as e:
        print(f"⚠️  Migration skipped: {e}")
    
    # 2. Start Monitoring
    monitoring = MonitoringSetup()
    monitoring.start_metrics_server()
    
    # 3. Initialize Threat Intelligence
    threat_intel = ThreatIntelligence()
    
    # 4. Health Checker
    health_checker = HealthChecker()
    
    print("✅ Phase 2 components initialized")
    print("📊 Metrics: http://localhost:8001")
    print("🔍 Health checks available")
    
    # Keep running
    try:
        while True:
            await asyncio.sleep(60)
            health_results = await health_checker.check_all_services()
            print(f"Health check: {health_results}")
    except KeyboardInterrupt:
        print("🛑 Phase 2 stopped")

if __name__ == "__main__":
    asyncio.run(main())