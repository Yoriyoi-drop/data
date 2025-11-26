"""
System configuration
"""
import os

# API Configuration
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", 8000))

# Database Configuration (PostgreSQL preferred) 
DB_BACKEND = os.getenv("DB_BACKEND", "postgres")
PG_DSN = os.getenv("PG_DSN")
PG_HOST = os.getenv("PG_HOST", "127.0.0.1")
PG_PORT = int(os.getenv("PG_PORT", 5432))
PG_USER = os.getenv("PG_USER", "postgres")
PG_PASSWORD = os.getenv("PG_PASSWORD", "postgres")
PG_DATABASE = os.getenv("PG_DATABASE", "infinite_ai")

# Optional Mongo for audit mirroring
MONGO_URI = os.getenv("MONGO_URI", "")
MONGO_DB = os.getenv("MONGO_DB", "infinite_ai")

# Security Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-secret-change-in-production")
API_KEY = os.getenv("API_KEY", "infinite-ai-security-2024")

# AI Agents Configuration
AGENTS_CONFIG = {
    "gpt5": {"enabled": True, "timeout": 30},
    "claude": {"enabled": True, "timeout": 30}, 
    "grok": {"enabled": True, "timeout": 20},
    "mistral": {"enabled": True, "timeout": 15}
}

# Performance Configuration
MAX_CONCURRENT_TASKS = 100
REQUEST_TIMEOUT = 30
CACHE_TTL = 300
