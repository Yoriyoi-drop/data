"""
Core Security Engine - Advanced Threat Detection
"""
import hashlib
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

class ThreatLevel(Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class ThreatResult:
    threat_detected: bool
    threat_type: str
    confidence: float
    severity: ThreatLevel
    blocked: bool
    patterns_matched: List[str]
    processing_time_ms: float

class SecurityEngine:
    def __init__(self):
        self.patterns = {
            "sql_injection": [
                "' or '1'='1", "'; drop table", "union select", "admin'--",
                "' or 1=1", "select * from", "insert into", "delete from"
            ],
            "xss": [
                "<script>", "javascript:", "onerror=", "alert(", "<svg onload",
                "document.cookie", "<iframe", "eval(", "onclick="
            ],
            "command_injection": [
                "; dir", "&& whoami", "| type", "; del", "powershell",
                "cmd.exe", "bash", "sh -c", "exec("
            ],
            "path_traversal": [
                "../", "..\\", "%2e%2e%2f", "....//", "/etc/passwd",
                "\\windows\\system32", "boot.ini", "/var/log"
            ]
        }
    
    def analyze(self, payload: str, source_ip: str = "") -> ThreatResult:
        start_time = time.time()
        
        if not payload:
            return ThreatResult(False, "none", 0.0, ThreatLevel.NONE, False, [], 0.0)
        
        normalized = self._normalize_payload(payload)
        max_confidence = 0.0
        primary_threat = "none"
        matched_patterns = []
        
        for threat_type, patterns in self.patterns.items():
            for pattern in patterns:
                if pattern.lower() in normalized:
                    confidence = self._calculate_confidence(pattern, normalized)
                    matched_patterns.append(pattern)
                    
                    if confidence > max_confidence:
                        max_confidence = confidence
                        primary_threat = threat_type
        
        severity = self._get_severity(max_confidence)
        blocked = max_confidence > 0.7
        processing_time = (time.time() - start_time) * 1000
        
        return ThreatResult(
            threat_detected=max_confidence > 0,
            threat_type=primary_threat,
            confidence=max_confidence,
            severity=severity,
            blocked=blocked,
            patterns_matched=matched_patterns,
            processing_time_ms=processing_time
        )
    
    def _normalize_payload(self, payload: str) -> str:
        import urllib.parse
        normalized = payload.lower()
        try:
            normalized = urllib.parse.unquote(normalized)
        except:
            pass
        return normalized
    
    def _calculate_confidence(self, pattern: str, payload: str) -> float:
        base_confidence = 0.6
        pattern_count = payload.count(pattern.lower())
        frequency_bonus = min(pattern_count * 0.1, 0.3)
        
        if "'" in payload and "or" in payload:
            base_confidence += 0.2
        if "<" in payload and ">" in payload:
            base_confidence += 0.2
        if ";" in payload or "|" in payload:
            base_confidence += 0.15
        
        return min(base_confidence + frequency_bonus, 1.0)
    
    def _get_severity(self, confidence: float) -> ThreatLevel:
        if confidence > 0.9:
            return ThreatLevel.CRITICAL
        elif confidence > 0.7:
            return ThreatLevel.HIGH
        elif confidence > 0.5:
            return ThreatLevel.MEDIUM
        elif confidence > 0:
            return ThreatLevel.LOW
        return ThreatLevel.NONE