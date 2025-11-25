"""
Production Environment Configuration Validator
Security Enhancement - Validates production settings
"""
import os
from typing import Dict, List, Tuple


class ProductionConfigValidator:
    """
    Validate production environment configuration
    
    Ensures all security settings are properly configured for production
    """
    
    def __init__(self):
        """Initialize validator"""
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.recommendations: List[str] = []
    
    def validate_all(self) -> Tuple[bool, Dict]:
        """
        Validate all production settings
        
        Returns:
            Tuple of (is_valid, results_dict)
        """
        self.errors.clear()
        self.warnings.clear()
        self.recommendations.clear()
        
        # Check environment
        self._check_environment()
        
        # Check secrets
        self._check_secrets()
        
        # Check database
        self._check_database()
        
        # Check security settings
        self._check_security_settings()
        
        # Check CORS
        self._check_cors()
        
        # Check session
        self._check_session()
        
        # Check logging
        self._check_logging()
        
        is_valid = len(self.errors) == 0
        
        return is_valid, {
            "valid": is_valid,
            "errors": self.errors,
            "warnings": self.warnings,
            "recommendations": self.recommendations
        }
    
    def _check_environment(self):
        """Check environment variable"""
        env = os.getenv("ENVIRONMENT", "development")
        
        if env != "production":
            self.warnings.append(
                f"ENVIRONMENT is '{env}', should be 'production' for production deployment"
            )
    
    def _check_secrets(self):
        """Check secret keys"""
        required_secrets = [
            "JWT_SECRET_KEY",
            "JWT_REFRESH_SECRET",
            "SESSION_SECRET",
            "API_SECRET_KEY"
        ]
        
        for secret in required_secrets:
            value = os.getenv(secret)
            
            if not value:
                self.errors.append(f"CRITICAL: {secret} not set in environment")
            elif len(value) < 32:
                self.errors.append(f"CRITICAL: {secret} is too short (minimum 32 characters)")
            elif value.startswith("CHANGE_ME"):
                self.errors.append(f"CRITICAL: {secret} still has default value")
    
    def _check_database(self):
        """Check database configuration"""
        db_backend = os.getenv("DB_BACKEND", "sqlite")
        
        if db_backend == "sqlite":
            self.warnings.append(
                "Using SQLite database. PostgreSQL recommended for production."
            )
        elif db_backend == "postgres":
            # Check PostgreSQL settings
            pg_password = os.getenv("PG_PASSWORD")
            
            if not pg_password:
                self.errors.append("CRITICAL: PG_PASSWORD not set")
            elif pg_password == "postgres":
                self.errors.append("CRITICAL: PG_PASSWORD is default value 'postgres'")
            elif len(pg_password) < 16:
                self.warnings.append("PG_PASSWORD should be at least 16 characters")
    
    def _check_security_settings(self):
        """Check security settings"""
        # HTTPS
        https_only = os.getenv("SESSION_HTTPS_ONLY", "false").lower()
        if https_only != "true":
            self.errors.append(
                "CRITICAL: SESSION_HTTPS_ONLY must be 'true' in production"
            )
        
        # Debug mode
        debug = os.getenv("DEBUG", "false").lower()
        if debug == "true":
            self.errors.append(
                "CRITICAL: DEBUG must be 'false' in production"
            )
        
        # Rate limiting
        rate_limit_enabled = os.getenv("RATE_LIMIT_ENABLED", "true").lower()
        if rate_limit_enabled != "true":
            self.warnings.append("Rate limiting should be enabled in production")
    
    def _check_cors(self):
        """Check CORS configuration"""
        allowed_origins = os.getenv("ALLOWED_ORIGINS", "")
        
        if not allowed_origins:
            self.warnings.append("ALLOWED_ORIGINS not set, using defaults")
        elif "localhost" in allowed_origins.lower():
            self.warnings.append(
                "ALLOWED_ORIGINS contains 'localhost', remove for production"
            )
        elif "*" in allowed_origins:
            self.errors.append(
                "CRITICAL: ALLOWED_ORIGINS contains '*' (wildcard), too permissive"
            )
    
    def _check_session(self):
        """Check session configuration"""
        session_max_age = os.getenv("SESSION_MAX_AGE", "1800")
        
        try:
            max_age = int(session_max_age)
            if max_age > 3600:
                self.warnings.append(
                    f"SESSION_MAX_AGE is {max_age}s (>{1} hour), consider shorter duration"
                )
        except ValueError:
            self.errors.append("SESSION_MAX_AGE must be a number")
    
    def _check_logging(self):
        """Check logging configuration"""
        log_level = os.getenv("LOG_LEVEL", "INFO")
        
        if log_level == "DEBUG":
            self.warnings.append(
                "LOG_LEVEL is DEBUG, should be INFO or WARNING in production"
            )
        
        # Check if Sentry is configured
        sentry_dsn = os.getenv("SENTRY_DSN")
        if not sentry_dsn:
            self.recommendations.append(
                "Consider setting up Sentry (SENTRY_DSN) for error tracking"
            )
    
    def print_report(self):
        """Print validation report"""
        print("\n" + "="*70)
        print("🔒 PRODUCTION CONFIGURATION VALIDATION REPORT")
        print("="*70)
        
        if self.errors:
            print(f"\n❌ ERRORS ({len(self.errors)}):")
            for i, error in enumerate(self.errors, 1):
                print(f"   {i}. {error}")
        
        if self.warnings:
            print(f"\n⚠️  WARNINGS ({len(self.warnings)}):")
            for i, warning in enumerate(self.warnings, 1):
                print(f"   {i}. {warning}")
        
        if self.recommendations:
            print(f"\n💡 RECOMMENDATIONS ({len(self.recommendations)}):")
            for i, rec in enumerate(self.recommendations, 1):
                print(f"   {i}. {rec}")
        
        if not self.errors and not self.warnings:
            print("\n✅ All checks passed! Configuration is production-ready.")
        elif not self.errors:
            print("\n✅ No critical errors, but please review warnings.")
        else:
            print(f"\n❌ {len(self.errors)} critical error(s) must be fixed before production deployment!")
        
        print("="*70 + "\n")


# Global validator
config_validator = ProductionConfigValidator()


def validate_production_config() -> bool:
    """
    Validate production configuration and print report
    
    Returns:
        True if valid, False otherwise
    """
    is_valid, results = config_validator.validate_all()
    config_validator.print_report()
    return is_valid
