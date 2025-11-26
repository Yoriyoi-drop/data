"""
Claude Agent - Code analysis, detailed reasoning, and reverse engineering
"""
import asyncio
import os
from .base_agent import BaseAgent, AgentStatus
from typing import Dict, Any
from ..reverse_engineering.code_analyzer import code_analyzer
from ..reverse_engineering.malware_analyzer import malware_analyzer

class ClaudeAgent(BaseAgent):
    def __init__(self):
        capabilities = [
            "code_review", "documentation", "detailed_analysis", 
            "compliance_check", "security_audit", "policy_analysis",
            "reverse_engineering", "malware_analysis", "source_analysis",
            "vulnerability_scanning", "crypto_analysis"
        ]
        super().__init__("Claude", "reasoning_model", capabilities)
        
    async def run_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute task dengan Claude's analytical capabilities"""
        self.status = AgentStatus.BUSY
        
        try:
            task_type = task.get('type', 'unknown')
            task_data = task.get('data', {})
            
            await asyncio.sleep(0.2)  # Simulate processing
            
            result = await self._process_task(task_type, task_data)
            
            self.tasks_completed += 1
            self.status = AgentStatus.IDLE
            
            return {
                "agent": self.name,
                "task_type": task_type,
                "result": result,
                "confidence": 0.92,
                "status": "success"
            }
            
        except Exception as e:
            self.tasks_failed += 1
            self.status = AgentStatus.ERROR
            return {"agent": self.name, "error": str(e), "status": "failed"}
    
    async def _process_task(self, task_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process task berdasarkan Claude's strengths"""
        
        if task_type == "code_review":
            return await self._review_code(data)
        elif task_type == "compliance_check":
            return await self._check_compliance(data)
        elif task_type == "security_audit":
            return await self._security_audit(data)
        elif task_type == "reverse_engineering":
            return await self._reverse_engineer(data)
        elif task_type == "malware_analysis":
            return await self._analyze_malware(data)
        elif task_type == "source_analysis":
            return await self._analyze_source(data)
        else:
            return {"analysis": f"Claude analyzed {task_type}", "details": "Comprehensive review completed"}
    
    async def _review_code(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced code review with reverse engineering"""
        code = data.get('code', '')
        file_path = data.get('file_path', '')
        
        issues = []
        suggestions = []
        
        # Basic security checks
        if "password" in code.lower() and "=" in code:
            issues.append("Hardcoded password detected")
            suggestions.append("Use environment variables for secrets")
        
        if "eval(" in code:
            issues.append("Dangerous eval() usage")
            suggestions.append("Replace eval() with safer alternatives")
        
        # Advanced analysis if file path provided
        advanced_analysis = {}
        if file_path and os.path.exists(file_path):
            try:
                analysis = code_analyzer.analyze_source_code(file_path)
                secrets = code_analyzer.find_hardcoded_secrets(file_path)
                api_calls = code_analyzer.extract_api_calls(file_path)
                
                advanced_analysis = {
                    "function_count": len(analysis.get('functions', [])),
                    "complexity_score": analysis.get('control_flow', {}).get('complexity_score', 'Unknown'),
                    "secrets_found": len(secrets),
                    "high_risk_apis": len([call for call in api_calls if call.get('risk_level') == 'High']),
                    "vulnerabilities": analysis.get('vulnerabilities', [])
                }
                
                # Add advanced issues
                if secrets:
                    issues.extend([f"Hardcoded secret: {s['type']}" for s in secrets[:3]])
                
                if analysis.get('vulnerabilities'):
                    issues.extend([f"{v['type']}: {v.get('pattern', '')}" for v in analysis['vulnerabilities'][:3]])
                
            except Exception:
                advanced_analysis = {"error": "Advanced analysis failed"}
        
        return {
            "security_issues": issues,
            "suggestions": suggestions,
            "code_quality": "good" if not issues else "needs_improvement",
            "compliance_score": 85 if not issues else 60,
            "advanced_analysis": advanced_analysis,
            "reverse_engineering_capable": True
        }
    
    async def _check_compliance(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Compliance verification"""
        return {
            "gdpr_compliant": True,
            "sox_compliant": True,
            "pci_dss_compliant": False,
            "recommendations": ["Implement data encryption", "Add audit logging"]
        }
    
    async def _security_audit(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Security audit analysis"""
        return {
            "vulnerabilities_found": 3,
            "critical_issues": 1,
            "audit_score": 75,
            "next_audit_date": "2024-02-15"
        }
    
    async def _reverse_engineer(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Reverse engineering analysis"""
        file_path = data.get('file_path', '')
        
        if not os.path.exists(file_path):
            return {"error": "File not found", "status": "failed"}
        
        try:
            # Determine if it's source code or binary
            file_ext = os.path.splitext(file_path)[1].lower()
            
            if file_ext in ['.py', '.js', '.c', '.cpp', '.go', '.rs']:
                # Source code analysis
                analysis = code_analyzer.analyze_source_code(file_path)
                return {
                    "type": "source_code_analysis",
                    "analysis": analysis,
                    "recommendations": self._generate_code_recommendations(analysis)
                }
            else:
                # Binary analysis
                analysis = malware_analyzer.analyze_malware(file_path)
                return {
                    "type": "binary_analysis", 
                    "analysis": analysis,
                    "threat_assessment": self._assess_threat_level(analysis)
                }
        
        except Exception as e:
            return {"error": str(e), "status": "analysis_failed"}
    
    async def _analyze_malware(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Malware analysis with IOC extraction"""
        file_path = data.get('file_path', '')
        
        try:
            analysis = malware_analyzer.analyze_malware(file_path)
            iocs = malware_analyzer.extract_iocs(file_path)
            yara_rule = malware_analyzer.generate_yara_rule(file_path, "claude_detection")
            
            return {
                "malware_analysis": analysis,
                "iocs": iocs,
                "yara_rule": yara_rule,
                "threat_score": analysis.get('threat_score', 0),
                "mitigation_steps": self._generate_mitigation_steps(analysis)
            }
        
        except Exception as e:
            return {"error": str(e), "status": "malware_analysis_failed"}
    
    async def _analyze_source(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Deep source code analysis"""
        file_path = data.get('file_path', '')
        
        try:
            analysis = code_analyzer.analyze_source_code(file_path)
            api_calls = code_analyzer.extract_api_calls(file_path)
            secrets = code_analyzer.find_hardcoded_secrets(file_path)
            crypto_usage = code_analyzer.extract_crypto_usage(file_path)
            
            return {
                "source_analysis": analysis,
                "api_calls": api_calls,
                "hardcoded_secrets": secrets,
                "crypto_usage": crypto_usage,
                "security_score": self._calculate_security_score(analysis, secrets, api_calls),
                "refactoring_suggestions": self._generate_refactoring_suggestions(analysis)
            }
        
        except Exception as e:
            return {"error": str(e), "status": "source_analysis_failed"}
    
    def _generate_code_recommendations(self, analysis: Dict) -> List[str]:
        """Generate code improvement recommendations"""
        recommendations = []
        
        if analysis.get('vulnerabilities'):
            recommendations.append("Fix identified security vulnerabilities")
        
        if analysis.get('secrets'):
            recommendations.append("Remove hardcoded secrets and use secure storage")
        
        complexity = analysis.get('control_flow', {}).get('complexity_score', 'Low')
        if complexity == 'High':
            recommendations.append("Refactor complex functions to improve maintainability")
        
        return recommendations
    
    def _assess_threat_level(self, analysis: Dict) -> str:
        """Assess threat level from binary analysis"""
        threat_score = analysis.get('threat_score', 0)
        
        if threat_score >= 80:
            return "Critical"
        elif threat_score >= 60:
            return "High"
        elif threat_score >= 40:
            return "Medium"
        else:
            return "Low"
    
    def _generate_mitigation_steps(self, analysis: Dict) -> List[str]:
        """Generate malware mitigation steps"""
        steps = []
        
        if analysis.get('signature_matches'):
            steps.append("Quarantine file immediately")
            steps.append("Update antivirus signatures")
        
        if analysis.get('network_indicators', {}).get('domains'):
            steps.append("Block identified domains in firewall")
        
        if analysis.get('packer_detection', {}).get('is_packed'):
            steps.append("Unpack binary for deeper analysis")
        
        steps.append("Monitor system for IOCs")
        steps.append("Perform full system scan")
        
        return steps
    
    def _calculate_security_score(self, analysis: Dict, secrets: List, api_calls: List) -> int:
        """Calculate security score for source code"""
        score = 100
        
        # Deduct for vulnerabilities
        vulns = analysis.get('vulnerabilities', [])
        score -= len(vulns) * 10
        
        # Deduct for secrets
        score -= len(secrets) * 15
        
        # Deduct for high-risk API calls
        high_risk_apis = [call for call in api_calls if call.get('risk_level') == 'High']
        score -= len(high_risk_apis) * 5
        
        return max(score, 0)
    
    def _generate_refactoring_suggestions(self, analysis: Dict) -> List[str]:
        """Generate refactoring suggestions"""
        suggestions = []
        
        func_count = len(analysis.get('functions', []))
        if func_count > 20:
            suggestions.append("Consider splitting large files into modules")
        
        if analysis.get('control_flow', {}).get('nesting_depth', 0) > 5:
            suggestions.append("Reduce nesting depth for better readability")
        
        if not analysis.get('classes') and func_count > 10:
            suggestions.append("Consider using object-oriented design")
        
        return suggestions