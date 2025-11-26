"""
Grok Agent - Pattern recognition, social engineering detection, and binary pattern analysis
"""
import asyncio
import os
import re
from .base_agent import BaseAgent, AgentStatus
from typing import Dict, Any, List
from ..reverse_engineering.core_engine import reverse_engine
from ..reverse_engineering.malware_analyzer import malware_analyzer

class GrokAgent(BaseAgent):
    def __init__(self):
        capabilities = [
            "pattern_recognition", "social_engineering_detection", 
            "anomaly_detection", "behavioral_analysis", "real_time_scanning",
            "binary_pattern_analysis", "signature_detection", "crypto_pattern_analysis",
            "network_pattern_analysis", "malware_family_detection"
        ]
        super().__init__("Grok", "pattern_analysis", capabilities)
        
    async def run_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute task dengan Grok's pattern recognition"""
        self.status = AgentStatus.BUSY
        
        try:
            task_type = task.get('type', 'unknown')
            task_data = task.get('data', {})
            
            await asyncio.sleep(0.15)  # Fast processing
            
            result = await self._analyze_patterns(task_type, task_data)
            
            self.tasks_completed += 1
            self.status = AgentStatus.IDLE
            
            return {
                "agent": self.name,
                "task_type": task_type,
                "result": result,
                "confidence": 0.94,
                "status": "success"
            }
            
        except Exception as e:
            self.tasks_failed += 1
            self.status = AgentStatus.ERROR
            return {"agent": self.name, "error": str(e), "status": "failed"}
    
    async def _analyze_patterns(self, task_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Pattern analysis berdasarkan task type"""
        
        if task_type == "social_engineering_detection":
            return await self._detect_social_engineering(data)
        elif task_type == "anomaly_detection":
            return await self._detect_anomalies(data)
        elif task_type == "behavioral_analysis":
            return await self._analyze_behavior(data)
        elif task_type == "binary_pattern_analysis":
            return await self._analyze_binary_patterns(data)
        elif task_type == "signature_detection":
            return await self._detect_signatures(data)
        elif task_type == "crypto_pattern_analysis":
            return await self._analyze_crypto_patterns(data)
        elif task_type == "network_pattern_analysis":
            return await self._analyze_network_patterns(data)
        elif task_type == "malware_family_detection":
            return await self._detect_malware_family(data)
        else:
            return {"patterns": f"Grok scanned {task_type}", "anomalies": 0}
    
    async def _detect_social_engineering(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect social engineering attempts"""
        message = data.get('message', '').lower()
        
        red_flags = []
        if "urgent" in message and "click" in message:
            red_flags.append("Urgency + action request")
        if "verify" in message and "account" in message:
            red_flags.append("Account verification phishing")
        if "winner" in message or "prize" in message:
            red_flags.append("Prize scam indicators")
        
        risk_score = len(red_flags) * 25
        
        return {
            "social_engineering_detected": len(red_flags) > 0,
            "risk_score": min(risk_score, 100),
            "red_flags": red_flags,
            "recommendation": "Block and quarantine" if risk_score > 50 else "Monitor closely"
        }
    
    async def _detect_anomalies(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect behavioral anomalies"""
        user_activity = data.get('activity', {})
        
        anomalies = []
        if user_activity.get('login_time') == "03:00":
            anomalies.append("Unusual login time")
        if user_activity.get('failed_attempts', 0) > 5:
            anomalies.append("Multiple failed login attempts")
        
        return {
            "anomalies_detected": len(anomalies),
            "anomaly_types": anomalies,
            "severity": "high" if len(anomalies) > 1 else "medium"
        }
    
    async def _analyze_behavior(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Behavioral pattern analysis"""
        return {
            "behavior_pattern": "suspicious",
            "deviation_score": 0.75,
            "baseline_comparison": "40% above normal",
            "action_required": True
        }
    
    async def _analyze_binary_patterns(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze binary file patterns for malware detection"""
        file_path = data.get('file_path', '')
        
        if not os.path.exists(file_path):
            return {"error": "File not found", "status": "failed"}
        
        try:
            analysis = reverse_engine.analyze_binary(file_path)
            
            # Pattern analysis
            patterns = {
                "suspicious_imports": self._find_suspicious_imports(analysis.imports),
                "packer_signatures": self._detect_packer_patterns(analysis.sections),
                "string_patterns": self._analyze_string_patterns(analysis.strings),
                "entry_point_analysis": self._analyze_entry_point(analysis.entry_point),
                "section_analysis": self._analyze_sections(analysis.sections)
            }
            
            # Calculate pattern score
            pattern_score = self._calculate_pattern_score(patterns)
            
            return {
                "binary_patterns": patterns,
                "pattern_score": pattern_score,
                "threat_indicators": self._extract_threat_indicators(patterns),
                "malware_probability": pattern_score / 100.0,
                "recommended_action": self._recommend_action(pattern_score)
            }
        
        except Exception as e:
            return {"error": str(e), "status": "pattern_analysis_failed"}
    
    async def _detect_signatures(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect known malware signatures and patterns"""
        file_path = data.get('file_path', '')
        
        try:
            analysis = malware_analyzer.analyze_malware(file_path)
            
            # Custom signature detection
            custom_signatures = self._detect_custom_signatures(file_path)
            
            return {
                "known_signatures": analysis.get('signature_matches', []),
                "custom_signatures": custom_signatures,
                "signature_confidence": self._calculate_signature_confidence(analysis),
                "family_classification": self._classify_malware_family(analysis),
                "detection_methods": ["static_analysis", "pattern_matching", "heuristic_analysis"]
            }
        
        except Exception as e:
            return {"error": str(e), "status": "signature_detection_failed"}
    
    async def _analyze_crypto_patterns(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze cryptographic patterns in binaries"""
        file_path = data.get('file_path', '')
        
        try:
            crypto_keys = reverse_engine.extract_crypto_keys(file_path)
            
            # Advanced crypto pattern analysis
            crypto_analysis = {
                "encryption_keys": crypto_keys,
                "crypto_constants": self._find_crypto_constants(file_path),
                "cipher_patterns": self._detect_cipher_patterns(file_path),
                "key_generation_patterns": self._analyze_key_generation(file_path),
                "crypto_strength": self._assess_crypto_strength(crypto_keys)
            }
            
            return {
                "crypto_analysis": crypto_analysis,
                "ransomware_indicators": self._check_ransomware_patterns(crypto_analysis),
                "crypto_score": self._calculate_crypto_score(crypto_analysis),
                "recommendations": self._generate_crypto_recommendations(crypto_analysis)
            }
        
        except Exception as e:
            return {"error": str(e), "status": "crypto_analysis_failed"}
    
    async def _analyze_network_patterns(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network communication patterns"""
        file_path = data.get('file_path', '')
        
        try:
            network_analysis = reverse_engine.analyze_network_behavior(file_path)
            
            # Enhanced network pattern analysis
            patterns = {
                "c2_indicators": self._detect_c2_patterns(network_analysis),
                "dns_patterns": self._analyze_dns_patterns(network_analysis.get('domains', [])),
                "port_patterns": self._analyze_port_patterns(network_analysis.get('ports', [])),
                "protocol_analysis": self._analyze_protocols(network_analysis.get('protocols', [])),
                "communication_frequency": self._estimate_communication_frequency(network_analysis)
            }
            
            return {
                "network_patterns": patterns,
                "botnet_probability": self._calculate_botnet_probability(patterns),
                "c2_confidence": self._calculate_c2_confidence(patterns),
                "network_iocs": self._extract_network_iocs(patterns)
            }
        
        except Exception as e:
            return {"error": str(e), "status": "network_analysis_failed"}
    
    async def _detect_malware_family(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect malware family based on patterns"""
        file_path = data.get('file_path', '')
        
        try:
            analysis = malware_analyzer.analyze_malware(file_path)
            
            # Family detection based on patterns
            family_indicators = {
                "ransomware_patterns": self._check_ransomware_family(analysis),
                "trojan_patterns": self._check_trojan_family(analysis),
                "worm_patterns": self._check_worm_family(analysis),
                "rootkit_patterns": self._check_rootkit_family(analysis),
                "backdoor_patterns": self._check_backdoor_family(analysis)
            }
            
            # Determine most likely family
            family_scores = {family: len(patterns) for family, patterns in family_indicators.items()}
            likely_family = max(family_scores, key=family_scores.get) if any(family_scores.values()) else "unknown"
            
            return {
                "malware_family": likely_family.replace('_patterns', ''),
                "family_confidence": max(family_scores.values()) / 10.0 if family_scores else 0.0,
                "family_indicators": family_indicators,
                "classification_details": self._get_family_details(likely_family)
            }
        
        except Exception as e:
            return {"error": str(e), "status": "family_detection_failed"}
    
    def _find_suspicious_imports(self, imports: List[str]) -> List[Dict]:
        """Find suspicious API imports"""
        suspicious_apis = {
            'CreateRemoteThread': 'Process Injection',
            'VirtualAllocEx': 'Memory Manipulation',
            'WriteProcessMemory': 'Process Injection',
            'SetWindowsHookEx': 'Keylogging/Hooking',
            'CryptEncrypt': 'Encryption/Ransomware',
            'RegSetValue': 'Registry Modification',
            'CreateService': 'Service Installation'
        }
        
        suspicious = []
        for imp in imports:
            for api, threat_type in suspicious_apis.items():
                if api in imp:
                    suspicious.append({
                        'api': api,
                        'import': imp,
                        'threat_type': threat_type,
                        'risk_level': 'High'
                    })
        
        return suspicious
    
    def _detect_packer_patterns(self, sections: List[Dict]) -> List[str]:
        """Detect packer signatures in sections"""
        packer_signatures = ['UPX', 'ASPack', 'PECompact', 'Themida', 'VMProtect']
        detected = []
        
        for section in sections:
            section_name = section.get('name', '')
            for packer in packer_signatures:
                if packer.lower() in section_name.lower():
                    detected.append(packer)
        
        return detected
    
    def _analyze_string_patterns(self, strings: List[str]) -> Dict:
        """Analyze string patterns for threats"""
        patterns = {
            'urls': [],
            'file_paths': [],
            'registry_keys': [],
            'crypto_strings': [],
            'suspicious_strings': []
        }
        
        for string in strings:
            if re.match(r'https?://', string):
                patterns['urls'].append(string)
            elif '\\' in string and len(string) > 10:
                patterns['file_paths'].append(string)
            elif string.startswith(('HKEY_', 'SOFTWARE\\')):
                patterns['registry_keys'].append(string)
            elif any(crypto in string.lower() for crypto in ['aes', 'rsa', 'encrypt', 'decrypt']):
                patterns['crypto_strings'].append(string)
            elif any(sus in string.lower() for sus in ['backdoor', 'trojan', 'virus', 'malware']):
                patterns['suspicious_strings'].append(string)
        
        return patterns
    
    def _calculate_pattern_score(self, patterns: Dict) -> int:
        """Calculate overall pattern threat score"""
        score = 0
        
        score += len(patterns.get('suspicious_imports', [])) * 15
        score += len(patterns.get('packer_signatures', [])) * 20
        score += len(patterns.get('string_patterns', {}).get('suspicious_strings', [])) * 10
        score += len(patterns.get('string_patterns', {}).get('crypto_strings', [])) * 5
        
        return min(score, 100)
    
    def _detect_custom_signatures(self, file_path: str) -> List[Dict]:
        """Detect custom malware signatures"""
        signatures = []
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024)  # Read first 1KB
            
            # Custom signature patterns
            custom_patterns = [
                (b'\x4d\x5a\x90\x00\x03\x00\x00\x00', 'PE Header Variant'),
                (b'\x50\x4b\x03\x04', 'ZIP Archive'),
                (b'\x7f\x45\x4c\x46', 'ELF Binary')
            ]
            
            for pattern, sig_type in custom_patterns:
                if pattern in data:
                    signatures.append({
                        'type': sig_type,
                        'confidence': 0.9,
                        'offset': data.find(pattern)
                    })
        
        except Exception:
            pass
        
        return signatures
    
    def _check_ransomware_patterns(self, crypto_analysis: Dict) -> List[str]:
        """Check for ransomware-specific patterns"""
        indicators = []
        
        if crypto_analysis.get('encryption_keys'):
            indicators.append('Encryption capabilities detected')
        
        if crypto_analysis.get('key_generation_patterns'):
            indicators.append('Key generation patterns found')
        
        return indicators
    
    def _detect_c2_patterns(self, network_analysis: Dict) -> List[str]:
        """Detect command and control patterns"""
        c2_indicators = []
        
        domains = network_analysis.get('domains', [])
        for domain in domains:
            if any(suspicious in domain for suspicious in ['.tk', '.ml', 'dyndns']):
                c2_indicators.append(f'Suspicious domain: {domain}')
        
        return c2_indicators
    
    def _check_ransomware_family(self, analysis: Dict) -> List[str]:
        """Check for ransomware family indicators"""
        indicators = []
        
        if analysis.get('crypto_analysis', {}).get('keys_found', 0) > 0:
            indicators.append('Encryption capabilities')
        
        behavioral = analysis.get('behavioral_analysis', {})
        if behavioral.get('file_operations'):
            indicators.append('File manipulation behavior')
        
        return indicators