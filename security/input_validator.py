"""
Enhanced Input Validation System - V1.0 Security Hardening
Comprehensive protection against injection attacks and malicious input
"""
import re
import html
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

class ThreatLevel(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ValidationResult:
    is_valid: bool
    threat_level: ThreatLevel
    threats_detected: List[str]
    sanitized_input: str
    confidence: float
    details: Dict[str, Any]

class InputValidator:
    def __init__(self):
        # SQL Injection patterns
        self.sql_patterns = {
            # Union-based attacks
            r'(?i)\bunion\s+select\b': 0.95,
            r'(?i)\bunion\s+all\s+select\b': 0.98,
            
            # Boolean-based blind attacks
            r"(?i)'\s*or\s*'1'\s*=\s*'1": 0.95,
            r"(?i)'\s*or\s*1\s*=\s*1": 0.95,
            r'(?i)"\s*or\s*"1"\s*=\s*"1': 0.95,
            r'(?i)"\s*or\s*1\s*=\s*1': 0.95,
            
            # Time-based blind attacks
            r'(?i)\bwaitfor\s+delay\b': 0.90,
            r'(?i)\bsleep\s*\(': 0.90,
            r'(?i)\bbenchmark\s*\(': 0.90,
            
            # Error-based attacks
            r'(?i)\bextractvalue\s*\(': 0.85,
            r'(?i)\bupdatexml\s*\(': 0.85,
            
            # Stacked queries
            r'(?i);\s*drop\s+table': 0.98,
            r'(?i);\s*delete\s+from': 0.95,
            r'(?i);\s*insert\s+into': 0.90,
            r'(?i);\s*update\s+': 0.90,
            
            # Comment-based evasion
            r'(?i)--\s*$': 0.70,
            r'/\*.*?\*/': 0.70,
            r'(?i)#.*$': 0.70,
            
            # Function-based attacks
            r'(?i)\bchar\s*\(': 0.80,
            r'(?i)\bascii\s*\(': 0.80,
            r'(?i)\bsubstring\s*\(': 0.75,
            r'(?i)\bconcat\s*\(': 0.75,
            
            # Database-specific attacks
            r'(?i)\bxp_cmdshell\b': 0.98,
            r'(?i)\bsp_executesql\b': 0.95,
            r'(?i)\bload_file\s*\(': 0.95,
            r'(?i)\binto\s+outfile\b': 0.95,
        }
        
        # XSS patterns
        self.xss_patterns = {
            # Script tags
            r'(?i)<script[^>]*>': 0.95,
            r'(?i)</script>': 0.95,
            r'(?i)<script[^>]*/>': 0.95,
            
            # Event handlers
            r'(?i)\bon\w+\s*=': 0.90,
            r'(?i)\bonerror\s*=': 0.95,
            r'(?i)\bonload\s*=': 0.90,
            r'(?i)\bonclick\s*=': 0.85,
            r'(?i)\bonmouseover\s*=': 0.85,
            
            # JavaScript protocols
            r'(?i)javascript\s*:': 0.90,
            r'(?i)vbscript\s*:': 0.90,
            r'(?i)data\s*:': 0.75,
            
            # HTML entities and encoding
            r'&#x[0-9a-f]+;': 0.70,
            r'&#[0-9]+;': 0.70,
            r'%[0-9a-f]{2}': 0.60,
            
            # Dangerous tags
            r'(?i)<iframe[^>]*>': 0.85,
            r'(?i)<object[^>]*>': 0.85,
            r'(?i)<embed[^>]*>': 0.85,
            r'(?i)<form[^>]*>': 0.80,
            r'(?i)<input[^>]*>': 0.75,
            
            # SVG-based XSS
            r'(?i)<svg[^>]*>': 0.80,
            r'(?i)<animate[^>]*>': 0.80,
            
            # CSS-based attacks
            r'(?i)expression\s*\(': 0.85,
            r'(?i)@import': 0.75,
            r'(?i)url\s*\(': 0.70,
            
            # Common XSS payloads
            r'(?i)alert\s*\(': 0.85,
            r'(?i)confirm\s*\(': 0.85,
            r'(?i)prompt\s*\(': 0.85,
            r'(?i)document\.cookie': 0.90,
            r'(?i)document\.write': 0.85,
            r'(?i)window\.location': 0.80,
        }
        
        # Command injection patterns
        self.command_patterns = {
            # Unix/Linux commands
            r'(?i);\s*cat\s+': 0.90,
            r'(?i);\s*ls\s+': 0.85,
            r'(?i);\s*pwd\s*': 0.85,
            r'(?i);\s*whoami\s*': 0.90,
            r'(?i);\s*id\s*': 0.85,
            r'(?i);\s*uname\s+': 0.85,
            r'(?i);\s*ps\s+': 0.80,
            r'(?i);\s*netstat\s+': 0.80,
            r'(?i);\s*wget\s+': 0.90,
            r'(?i);\s*curl\s+': 0.90,
            r'(?i);\s*nc\s+': 0.95,
            r'(?i);\s*ncat\s+': 0.95,
            
            # Windows commands
            r'(?i);\s*dir\s+': 0.85,
            r'(?i);\s*type\s+': 0.85,
            r'(?i);\s*copy\s+': 0.80,
            r'(?i);\s*move\s+': 0.80,
            r'(?i);\s*del\s+': 0.90,
            r'(?i);\s*rmdir\s+': 0.90,
            r'(?i);\s*tasklist\s*': 0.80,
            r'(?i);\s*taskkill\s+': 0.95,
            r'(?i);\s*net\s+': 0.85,
            r'(?i);\s*ipconfig\s*': 0.80,
            
            # Command chaining
            r'(?i)&&\s*\w+': 0.85,
            r'(?i)\|\|\s*\w+': 0.85,
            r'(?i)\|\s*\w+': 0.80,
            r'(?i)`[^`]+`': 0.90,
            r'\$\([^)]+\)': 0.90,
            
            # Dangerous executables
            r'(?i)\bcmd\.exe\b': 0.95,
            r'(?i)\bpowershell\b': 0.95,
            r'(?i)\bbash\b': 0.90,
            r'(?i)\bsh\b': 0.85,
            r'(?i)\bzsh\b': 0.85,
            r'(?i)\bfish\b': 0.80,
            
            # File operations
            r'(?i)/etc/passwd': 0.95,
            r'(?i)/etc/shadow': 0.98,
            r'(?i)\.\.\/': 0.80,
            r'(?i)\.\.\\': 0.80,
        }
        
        # Path traversal patterns
        self.path_traversal_patterns = {
            r'\.\.\/': 0.90,
            r'\.\.\\': 0.90,
            r'%2e%2e%2f': 0.95,
            r'%2e%2e%5c': 0.95,
            r'..%2f': 0.90,
            r'..%5c': 0.90,
            r'%252e%252e%252f': 0.95,
            r'%c0%ae%c0%ae%c0%af': 0.95,
        }
        
        # LDAP injection patterns
        self.ldap_patterns = {
            r'\(\s*\|\s*\(': 0.90,
            r'\(\s*&\s*\(': 0.90,
            r'\*\)\s*\(': 0.85,
            r'\)\s*\(\s*\|': 0.85,
        }
        
        # NoSQL injection patterns
        self.nosql_patterns = {
            r'(?i)\$where\s*:': 0.90,
            r'(?i)\$ne\s*:': 0.85,
            r'(?i)\$gt\s*:': 0.80,
            r'(?i)\$lt\s*:': 0.80,
            r'(?i)\$regex\s*:': 0.85,
            r'(?i)\$or\s*:': 0.85,
            r'(?i)\$and\s*:': 0.80,
        }
        
        # Dangerous file extensions
        self.dangerous_extensions = {
            '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js',
            '.jar', '.php', '.asp', '.aspx', '.jsp', '.py', '.rb', '.pl',
            '.sh', '.bash', '.ps1', '.psm1'
        }
        
        # Allowed characters for different contexts
        self.allowed_chars = {
            'alphanumeric': re.compile(r'^[a-zA-Z0-9]+$'),
            'username': re.compile(r'^[a-zA-Z0-9_.-]+$'),
            'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
            'filename': re.compile(r'^[a-zA-Z0-9._-]+$'),
            'url': re.compile(r'^https?://[a-zA-Z0-9.-]+(/[a-zA-Z0-9._/-]*)?$'),
        }
    
    def validate_input(self, input_data: str, context: str = "general") -> ValidationResult:
        """
        Comprehensive input validation
        
        Args:
            input_data: The input string to validate
            context: The context of the input (general, sql, html, filename, etc.)
        
        Returns:
            ValidationResult with validation details
        """
        if not input_data:
            return ValidationResult(
                is_valid=True,
                threat_level=ThreatLevel.SAFE,
                threats_detected=[],
                sanitized_input="",
                confidence=1.0,
                details={"empty_input": True}
            )
        
        threats_detected = []
        max_confidence = 0.0
        sanitized_input = input_data
        
        # Decode URL encoding multiple times to catch double encoding
        decoded_input = self._multi_decode(input_data)
        
        # Check for SQL injection
        sql_threats, sql_confidence = self._check_sql_injection(decoded_input)
        if sql_threats:
            threats_detected.extend(sql_threats)
            max_confidence = max(max_confidence, sql_confidence)
        
        # Check for XSS
        xss_threats, xss_confidence = self._check_xss(decoded_input)
        if xss_threats:
            threats_detected.extend(xss_threats)
            max_confidence = max(max_confidence, xss_confidence)
        
        # Check for command injection
        cmd_threats, cmd_confidence = self._check_command_injection(decoded_input)
        if cmd_threats:
            threats_detected.extend(cmd_threats)
            max_confidence = max(max_confidence, cmd_confidence)
        
        # Check for path traversal
        path_threats, path_confidence = self._check_path_traversal(decoded_input)
        if path_threats:
            threats_detected.extend(path_threats)
            max_confidence = max(max_confidence, path_confidence)
        
        # Check for LDAP injection
        ldap_threats, ldap_confidence = self._check_ldap_injection(decoded_input)
        if ldap_threats:
            threats_detected.extend(ldap_threats)
            max_confidence = max(max_confidence, ldap_confidence)
        
        # Check for NoSQL injection
        nosql_threats, nosql_confidence = self._check_nosql_injection(decoded_input)
        if nosql_threats:
            threats_detected.extend(nosql_threats)
            max_confidence = max(max_confidence, nosql_confidence)
        
        # Context-specific validation
        context_threats = self._validate_context(input_data, context)
        if context_threats:
            threats_detected.extend(context_threats)
            max_confidence = max(max_confidence, 0.8)
        
        # Sanitize input based on context
        sanitized_input = self._sanitize_input(input_data, context)
        
        # Determine threat level
        threat_level = self._determine_threat_level(max_confidence)
        
        # Determine if input is valid (not blocked)
        is_valid = threat_level in [ThreatLevel.SAFE, ThreatLevel.LOW]
        
        return ValidationResult(
            is_valid=is_valid,
            threat_level=threat_level,
            threats_detected=list(set(threats_detected)),  # Remove duplicates
            sanitized_input=sanitized_input,
            confidence=max_confidence,
            details={
                "original_length": len(input_data),
                "sanitized_length": len(sanitized_input),
                "context": context,
                "encoding_layers": self._count_encoding_layers(input_data)
            }
        )
    
    def _multi_decode(self, input_data: str, max_iterations: int = 5) -> str:
        """Decode URL encoding multiple times to catch evasion attempts"""
        decoded = input_data
        for _ in range(max_iterations):
            try:
                new_decoded = urllib.parse.unquote(decoded)
                if new_decoded == decoded:
                    break
                decoded = new_decoded
            except:
                break
        return decoded
    
    def _count_encoding_layers(self, input_data: str) -> int:
        """Count the number of encoding layers"""
        layers = 0
        decoded = input_data
        for _ in range(10):  # Max 10 layers
            try:
                new_decoded = urllib.parse.unquote(decoded)
                if new_decoded == decoded:
                    break
                decoded = new_decoded
                layers += 1
            except:
                break
        return layers
    
    def _check_sql_injection(self, input_data: str) -> Tuple[List[str], float]:
        """Check for SQL injection patterns"""
        threats = []
        max_confidence = 0.0
        
        for pattern, confidence in self.sql_patterns.items():
            if re.search(pattern, input_data):
                threats.append(f"sql_injection_{pattern[:20]}")
                max_confidence = max(max_confidence, confidence)
        
        return threats, max_confidence
    
    def _check_xss(self, input_data: str) -> Tuple[List[str], float]:
        """Check for XSS patterns"""
        threats = []
        max_confidence = 0.0
        
        for pattern, confidence in self.xss_patterns.items():
            if re.search(pattern, input_data):
                threats.append(f"xss_{pattern[:20]}")
                max_confidence = max(max_confidence, confidence)
        
        return threats, max_confidence
    
    def _check_command_injection(self, input_data: str) -> Tuple[List[str], float]:
        """Check for command injection patterns"""
        threats = []
        max_confidence = 0.0
        
        for pattern, confidence in self.command_patterns.items():
            if re.search(pattern, input_data):
                threats.append(f"command_injection_{pattern[:20]}")
                max_confidence = max(max_confidence, confidence)
        
        return threats, max_confidence
    
    def _check_path_traversal(self, input_data: str) -> Tuple[List[str], float]:
        """Check for path traversal patterns"""
        threats = []
        max_confidence = 0.0
        
        for pattern, confidence in self.path_traversal_patterns.items():
            if re.search(pattern, input_data):
                threats.append(f"path_traversal_{pattern[:20]}")
                max_confidence = max(max_confidence, confidence)
        
        return threats, max_confidence
    
    def _check_ldap_injection(self, input_data: str) -> Tuple[List[str], float]:
        """Check for LDAP injection patterns"""
        threats = []
        max_confidence = 0.0
        
        for pattern, confidence in self.ldap_patterns.items():
            if re.search(pattern, input_data):
                threats.append(f"ldap_injection_{pattern[:20]}")
                max_confidence = max(max_confidence, confidence)
        
        return threats, max_confidence
    
    def _check_nosql_injection(self, input_data: str) -> Tuple[List[str], float]:
        """Check for NoSQL injection patterns"""
        threats = []
        max_confidence = 0.0
        
        for pattern, confidence in self.nosql_patterns.items():
            if re.search(pattern, input_data):
                threats.append(f"nosql_injection_{pattern[:20]}")
                max_confidence = max(max_confidence, confidence)
        
        return threats, max_confidence
    
    def _validate_context(self, input_data: str, context: str) -> List[str]:
        """Validate input based on specific context"""
        threats = []
        
        if context == "filename":
            # Check for dangerous file extensions
            for ext in self.dangerous_extensions:
                if input_data.lower().endswith(ext):
                    threats.append(f"dangerous_file_extension_{ext}")
            
            # Check filename pattern
            if not self.allowed_chars['filename'].match(input_data):
                threats.append("invalid_filename_characters")
        
        elif context == "email":
            if not self.allowed_chars['email'].match(input_data):
                threats.append("invalid_email_format")
        
        elif context == "username":
            if not self.allowed_chars['username'].match(input_data):
                threats.append("invalid_username_characters")
        
        elif context == "url":
            if not self.allowed_chars['url'].match(input_data):
                threats.append("invalid_url_format")
        
        return threats
    
    def _sanitize_input(self, input_data: str, context: str) -> str:
        """Sanitize input based on context"""
        sanitized = input_data
        
        if context == "html":
            # HTML escape
            sanitized = html.escape(sanitized)
        
        elif context == "sql":
            # Basic SQL escaping (should use parameterized queries instead)
            sanitized = sanitized.replace("'", "''")
            sanitized = sanitized.replace('"', '""')
            sanitized = sanitized.replace(';', '')
        
        elif context == "filename":
            # Remove dangerous characters
            sanitized = re.sub(r'[<>:"/\\|?*]', '', sanitized)
            sanitized = sanitized.strip('. ')
        
        elif context == "alphanumeric":
            # Keep only alphanumeric characters
            sanitized = re.sub(r'[^a-zA-Z0-9]', '', sanitized)
        
        return sanitized
    
    def _determine_threat_level(self, confidence: float) -> ThreatLevel:
        """Determine threat level based on confidence"""
        if confidence >= 0.9:
            return ThreatLevel.CRITICAL
        elif confidence >= 0.8:
            return ThreatLevel.HIGH
        elif confidence >= 0.6:
            return ThreatLevel.MEDIUM
        elif confidence >= 0.3:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.SAFE
    
    def validate_file_upload(self, filename: str, content: bytes, 
                           max_size: int = 10 * 1024 * 1024) -> ValidationResult:
        """Validate file upload"""
        threats = []
        
        # Check file size
        if len(content) > max_size:
            threats.append("file_too_large")
        
        # Check filename
        filename_result = self.validate_input(filename, "filename")
        if not filename_result.is_valid:
            threats.extend(filename_result.threats_detected)
        
        # Check for executable content
        if content.startswith(b'MZ') or content.startswith(b'\x7fELF'):
            threats.append("executable_content")
        
        # Check for script content
        script_signatures = [b'<script', b'<?php', b'#!/bin/', b'#!/usr/bin/']
        for sig in script_signatures:
            if sig in content[:1024]:  # Check first 1KB
                threats.append("script_content")
                break
        
        threat_level = ThreatLevel.HIGH if threats else ThreatLevel.SAFE
        
        return ValidationResult(
            is_valid=len(threats) == 0,
            threat_level=threat_level,
            threats_detected=threats,
            sanitized_input=filename_result.sanitized_input,
            confidence=0.9 if threats else 0.0,
            details={
                "file_size": len(content),
                "max_size": max_size,
                "filename": filename
            }
        )

# Global validator instance
input_validator = InputValidator()