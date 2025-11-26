# Infinite AI Security Platform V2.0
# Centralized Configuration

"""
Centralized configuration management for the application.
All settings are loaded from environment variables with sensible defaults.
"""

import os
from typing import List, Optional
from pydantic import BaseSettings, validator, Field
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings with validation"""
    
    # ===== APPLICATION =====
    APP_NAME: str = "Infinite AI Security Platform"
    APP_VERSION: str = "2.0.0"
    ENVIRONMENT: str = Field(default="development", env="ENVIRONMENT")
    DEBUG: bool = Field(default=False, env="DEBUG")
    
    # ===== SERVER =====
    HOST: str = Field(default="0.0.0.0", env="HOST")
    PORT: int = Field(default=8000, env="PORT")
    WORKERS: int = Field(default=4, env="WORKERS")
    RELOAD: bool = Field(default=False, env="RELOAD")
    
    # ===== SECURITY - SECRETS =====
    JWT_SECRET_KEY: str = Field(..., env="JWT_SECRET_KEY")
    JWT_REFRESH_SECRET: str = Field(..., env="JWT_REFRESH_SECRET")
    SESSION_SECRET: str = Field(..., env="SESSION_SECRET")
    API_SECRET_KEY: str = Field(..., env="API_SECRET_KEY")
    
    # ===== SECURITY - JWT =====
    JWT_ALGORITHM: str = Field(default="HS256", env="JWT_ALGORITHM")
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=15, env="JWT_ACCESS_TOKEN_EXPIRE_MINUTES")
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, env="JWT_REFRESH_TOKEN_EXPIRE_DAYS")
    
    # ===== SECURITY - SESSION =====
    SESSION_MAX_AGE: int = Field(default=1800, env="SESSION_MAX_AGE")  # 30 minutes
    SESSION_HTTPS_ONLY: bool = Field(default=False, env="SESSION_HTTPS_ONLY")
    SESSION_SAME_SITE: str = Field(default="strict", env="SESSION_SAME_SITE")
    
    # ===== SECURITY - CSRF =====
    CSRF_TOKEN_EXPIRE_SECONDS: int = Field(default=300, env="CSRF_TOKEN_EXPIRE_SECONDS")  # 5 minutes
    
    # ===== SECURITY - RATE LIMITING =====
    RATE_LIMIT_ENABLED: bool = Field(default=True, env="RATE_LIMIT_ENABLED")
    RATE_LIMIT_PER_MINUTE: int = Field(default=60, env="RATE_LIMIT_PER_MINUTE")
    RATE_LIMIT_LOGIN_PER_HOUR: int = Field(default=5, env="RATE_LIMIT_LOGIN_PER_HOUR")
    
    # ===== DATABASE =====
    DB_BACKEND: str = Field(default="sqlite", env="DB_BACKEND")  # sqlite or postgres
    DATABASE_URL: Optional[str] = Field(default=None, env="DATABASE_URL")
    
    # PostgreSQL
    PG_HOST: str = Field(default="127.0.0.1", env="PG_HOST")
    PG_PORT: int = Field(default=5432, env="PG_PORT")
    PG_USER: str = Field(default="postgres", env="PG_USER")
    PG_PASSWORD: str = Field(default="postgres", env="PG_PASSWORD")
    PG_DATABASE: str = Field(default="infinite_ai", env="PG_DATABASE")
    
    # SQLite
    SQLITE_DB_PATH: str = Field(default="infinite_security_v2.db", env="SQLITE_DB_PATH")
    
    # Connection Pool
    DB_POOL_SIZE: int = Field(default=20, env="DB_POOL_SIZE")
    DB_MAX_OVERFLOW: int = Field(default=10, env="DB_MAX_OVERFLOW")
    
    # ===== REDIS =====
    REDIS_ENABLED: bool = Field(default=False, env="REDIS_ENABLED")
    REDIS_URL: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    REDIS_PASSWORD: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    
    # ===== CORS =====
    ALLOWED_ORIGINS: List[str] = Field(
        default=["http://localhost:3000", "http://127.0.0.1:3000"],
        env="ALLOWED_ORIGINS"
    )
    ALLOWED_METHODS: List[str] = Field(
        default=["GET", "POST", "PUT", "DELETE"],
        env="ALLOWED_METHODS"
    )
    ALLOWED_HEADERS: List[str] = Field(
        default=["Authorization", "Content-Type", "X-CSRF-Token"],
        env="ALLOWED_HEADERS"
    )
    
    # ===== LOGGING =====
    LOG_LEVEL: str = Field(default="INFO", env="LOG_LEVEL")
    LOG_FORMAT: str = Field(default="json", env="LOG_FORMAT")  # json or text
    LOG_DIR: str = Field(default="logs", env="LOG_DIR")
    LOG_MAX_SIZE: int = Field(default=10485760, env="LOG_MAX_SIZE")  # 10MB
    LOG_BACKUP_COUNT: int = Field(default=10, env="LOG_BACKUP_COUNT")
    
    # ===== MONITORING =====
    METRICS_ENABLED: bool = Field(default=True, env="METRICS_ENABLED")
    PROMETHEUS_PORT: int = Field(default=9090, env="PROMETHEUS_PORT")
    SENTRY_DSN: Optional[str] = Field(default=None, env="SENTRY_DSN")
    
    # ===== BACKUP =====
    BACKUP_ENABLED: bool = Field(default=True, env="BACKUP_ENABLED")
    BACKUP_DIR: str = Field(default="backups", env="BACKUP_DIR")
    BACKUP_RETENTION_DAYS: int = Field(default=30, env="BACKUP_RETENTION_DAYS")
    BACKUP_INTERVAL_HOURS: int = Field(default=24, env="BACKUP_INTERVAL_HOURS")
    
    # ===== EMAIL (Optional) =====
    SMTP_ENABLED: bool = Field(default=False, env="SMTP_ENABLED")
    SMTP_HOST: Optional[str] = Field(default=None, env="SMTP_HOST")
    SMTP_PORT: int = Field(default=587, env="SMTP_PORT")
    SMTP_USER: Optional[str] = Field(default=None, env="SMTP_USER")
    SMTP_PASSWORD: Optional[str] = Field(default=None, env="SMTP_PASSWORD")
    SMTP_FROM: Optional[str] = Field(default=None, env="SMTP_FROM")
    
    # ===== FEATURES =====
    ENABLE_MFA: bool = Field(default=True, env="ENABLE_MFA")
    ENABLE_WEBSOCKET: bool = Field(default=True, env="ENABLE_WEBSOCKET")
    ENABLE_SWAGGER: bool = Field(default=True, env="ENABLE_SWAGGER")
    
    @validator("ALLOWED_ORIGINS", pre=True)
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v
    
    @validator("ENVIRONMENT")
    def validate_environment(cls, v):
        allowed = ["development", "staging", "production", "testing"]
        if v not in allowed:
            raise ValueError(f"ENVIRONMENT must be one of {allowed}")
        return v
    
    @validator("JWT_SECRET_KEY", "JWT_REFRESH_SECRET", "SESSION_SECRET", "API_SECRET_KEY")
    def validate_secrets(cls, v, field):
        if not v or len(v) < 32:
            raise ValueError(f"{field.name} must be at least 32 characters long")
        if v.startswith("CHANGE_ME"):
            raise ValueError(f"{field.name} must be changed from default value")
        return v
    
    @property
    def is_production(self) -> bool:
        """Check if running in production"""
        return self.ENVIRONMENT == "production"
    
    @property
    def is_development(self) -> bool:
        """Check if running in development"""
        return self.ENVIRONMENT == "development"
    
    @property
    def database_url_computed(self) -> str:
        """Get computed database URL"""
        if self.DATABASE_URL:
            return self.DATABASE_URL
        
        if self.DB_BACKEND == "postgres":
            return f"postgresql://{self.PG_USER}:{self.PG_PASSWORD}@{self.PG_HOST}:{self.PG_PORT}/{self.PG_DATABASE}"
        else:
            return f"sqlite:///{self.SQLITE_DB_PATH}"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance
    
    Returns:
        Settings instance
    """
    return Settings()


# Global settings instance
settings = get_settings()


# Validation on import
if __name__ != "__main__":
    try:
        settings = get_settings()
        print(f"✅ Configuration loaded successfully")
        print(f"   Environment: {settings.ENVIRONMENT}")
        print(f"   Database: {settings.DB_BACKEND}")
        print(f"   Redis: {'Enabled' if settings.REDIS_ENABLED else 'Disabled'}")
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        raise
