"""
URL Redirect Validator
Security Enhancement - Prevents open redirect attacks
"""
import urllib.parse
from typing import List, Optional


class RedirectValidator:
    """
    Validate redirect URLs to prevent open redirect attacks
    
    Features:
    - Whitelist-based validation
    - Relative URL support
    - Protocol validation
    - Domain validation
    """
    
    def __init__(self, allowed_domains: Optional[List[str]] = None):
        """
        Initialize redirect validator
        
        Args:
            allowed_domains: List of allowed domains for redirects
        """
        self.allowed_domains = allowed_domains or [
            "localhost",
            "127.0.0.1",
            "yourdomain.com"  # Replace with your actual domain
        ]
        
        # Allowed protocols
        self.allowed_protocols = ["http", "https"]
    
    def validate(self, url: str) -> bool:
        """
        Validate redirect URL
        
        Args:
            url: URL to validate
        
        Returns:
            True if valid, False otherwise
        """
        if not url:
            return False
        
        try:
            parsed = urllib.parse.urlparse(url)
            
            # Allow relative URLs (no scheme/netloc)
            if not parsed.netloc:
                # Relative URL - check for path traversal
                if ".." in url or url.startswith("//"):
                    return False
                return True
            
            # Check protocol
            if parsed.scheme and parsed.scheme not in self.allowed_protocols:
                return False
            
            # Check domain against whitelist
            domain = parsed.netloc.lower()
            
            # Remove port if present
            if ":" in domain:
                domain = domain.split(":")[0]
            
            # Check exact match or subdomain
            for allowed_domain in self.allowed_domains:
                if domain == allowed_domain or domain.endswith(f".{allowed_domain}"):
                    return True
            
            return False
            
        except Exception:
            return False
    
    def sanitize(self, url: str) -> Optional[str]:
        """
        Sanitize and validate URL
        
        Args:
            url: URL to sanitize
        
        Returns:
            Sanitized URL or None if invalid
        """
        if not self.validate(url):
            return None
        
        # Remove any dangerous characters
        url = url.replace("\n", "").replace("\r", "").replace("\t", "")
        
        return url
    
    def add_allowed_domain(self, domain: str):
        """
        Add domain to whitelist
        
        Args:
            domain: Domain to add
        """
        if domain not in self.allowed_domains:
            self.allowed_domains.append(domain.lower())
    
    def remove_allowed_domain(self, domain: str):
        """
        Remove domain from whitelist
        
        Args:
            domain: Domain to remove
        """
        if domain in self.allowed_domains:
            self.allowed_domains.remove(domain.lower())


# Global instance
redirect_validator = RedirectValidator()
