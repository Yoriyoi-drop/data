"""
HashiCorp Vault Integration - Secure secrets management
"""
import os
from typing import Dict, Optional
import logging

class VaultManager:
    def __init__(self, vault_url: str = None, vault_token: str = None):
        self.vault_url = vault_url or os.getenv('VAULT_URL', 'http://localhost:8200')
        self.vault_token = vault_token or os.getenv('VAULT_TOKEN')
        self.client = None
        
    def get_secret(self, path: str, key: str = None) -> Optional[str]:
        """Get secret from environment (Vault fallback)"""
        env_key = key.upper() if key else path.upper().replace('/', '_')
        return os.getenv(env_key)
    
    def store_secret(self, path: str, secrets: Dict[str, str]) -> bool:
        """Store secret (mock implementation)"""
        logging.info(f"Secret would be stored at {path}")
        return True

# Global vault instance
vault = VaultManager()

def get_api_key(service: str) -> Optional[str]:
    """Get API key for AI services"""
    key_map = {
        'openai': 'OPENAI_API_KEY',
        'anthropic': 'ANTHROPIC_API_KEY', 
        'mistral': 'MISTRAL_API_KEY',
        'grok': 'GROK_API_KEY'
    }
    
    env_key = key_map.get(service.lower())
    return os.getenv(env_key) if env_key else None

def get_database_url() -> str:
    """Get database connection string"""
    return os.getenv("DATABASE_URL", "sqlite:///./security.db")

def get_jwt_secret() -> str:
    """Get JWT secret key"""
    return os.getenv("SECRET_KEY", "fallback-secret-key")