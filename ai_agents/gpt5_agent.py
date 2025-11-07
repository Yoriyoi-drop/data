"""
GPT-5 Agent - Strategic analysis dan complex reasoning
"""
import asyncio
from .base_agent import BaseAgent, AgentStatus
from typing import Dict, Any

class GPT5Agent(BaseAgent):
    def __init__(self):
        capabilities = [
            "threat_analysis", "strategic_planning", "complex_reasoning",
            "code_analysis", "vulnerability_assessment", "incident_response"
        ]
        super().__init__("GPT-5", "large_language_model", capabilities)
        self.max_context = 128000
        
    async def run_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute task dengan GPT-5 capabilities"""
        self.status = AgentStatus.BUSY
        
        try:
            task_type = task.get('type', 'unknown')
            task_data = task.get('data', {})
            
            # Simulate processing time based on complexity
            processing_time = self._calculate_processing_time(task)
            await asyncio.sleep(processing_time)
            
            result = await self._process_by_type(task_type, task_data)
            
            # Store successful task in memory
            await self.store_memory(f"task_{self.tasks_completed}", {
                'type': task_type,
                'result': result,
                'processing_time': processing_time
            })
            
            self.tasks_completed += 1
            self.status = AgentStatus.IDLE
            
            return {
                "agent": self.name,
                "task_type": task_type,
                "result": result,
                "processing_time": processing_time,
                "confidence": 0.95,
                "status": "success"
            }
            
        except Exception as e:
            self.tasks_failed += 1
            self.status = AgentStatus.ERROR
            
            return {
                "agent": self.name,
                "error": str(e),
                "status": "failed"
            }
    
    async def _process_by_type(self, task_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process task berdasarkan type"""
        
        if task_type == "threat_analysis":
            return await self._analyze_threat(data)
        elif task_type == "strategic_planning":
            return await self._create_strategy(data)
        elif task_type == "code_analysis":
            return await self._analyze_code(data)
        elif task_type == "vulnerability_assessment":
            return await self._assess_vulnerability(data)
        else:
            return {"analysis": f"GPT-5 processed {task_type}", "recommendations": []}
    
    async def _analyze_threat(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Advanced threat analysis"""
        threat_source = data.get('source', 'unknown')
        threat_type = data.get('type', 'unknown')
        
        # Check memory for similar threats
        similar_threats = await self.recall_memory(f"threat_pattern_{threat_type}")
        
        analysis = {
            "threat_level": "high" if threat_type in ["sql_injection", "ddos"] else "medium",
            "attack_vector": self._identify_attack_vector(threat_type),
            "potential_impact": self._assess_impact(threat_type),
            "countermeasures": self._generate_countermeasures(threat_type),
            "similar_incidents": similar_threats or 0,
            "confidence": 0.92
        }
        
        return analysis
    
    async def _create_strategy(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Strategic defense planning"""
        return {
            "strategy": "Multi-layered defense with AI coordination",
            "phases": [
                "Immediate containment",
                "Threat neutralization", 
                "System hardening",
                "Continuous monitoring"
            ],
            "timeline": "15-30 minutes",
            "resources_needed": ["All agents", "Labyrinth activation", "Network isolation"]
        }
    
    async def _analyze_code(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Code vulnerability analysis"""
        code = data.get('code', '')
        
        vulnerabilities = []
        if "eval(" in code:
            vulnerabilities.append("Code injection risk")
        if "SELECT * FROM" in code.upper():
            vulnerabilities.append("SQL injection potential")
        
        return {
            "vulnerabilities": vulnerabilities,
            "severity": "high" if vulnerabilities else "low",
            "recommendations": ["Input validation", "Parameterized queries", "Code review"]
        }
    
    async def _assess_vulnerability(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """System vulnerability assessment"""
        return {
            "cvss_score": 7.5,
            "exploitability": "high",
            "impact": "significant",
            "remediation": "Immediate patching required"
        }
    
    def _calculate_processing_time(self, task: Dict[str, Any]) -> float:
        """Calculate processing time based on task complexity"""
        base_time = 0.1
        complexity_multiplier = {
            "threat_analysis": 1.5,
            "strategic_planning": 2.0,
            "code_analysis": 1.2,
            "vulnerability_assessment": 1.8
        }
        
        task_type = task.get('type', 'unknown')
        return base_time * complexity_multiplier.get(task_type, 1.0)
    
    def _identify_attack_vector(self, threat_type: str) -> str:
        """Identify attack vector"""
        vectors = {
            "sql_injection": "Web application input",
            "ddos": "Network flooding",
            "xss": "Client-side injection",
            "phishing": "Social engineering"
        }
        return vectors.get(threat_type, "Unknown vector")
    
    def _assess_impact(self, threat_type: str) -> str:
        """Assess potential impact"""
        impacts = {
            "sql_injection": "Data breach, system compromise",
            "ddos": "Service disruption, availability loss",
            "xss": "Session hijacking, data theft",
            "phishing": "Credential compromise, lateral movement"
        }
        return impacts.get(threat_type, "Moderate impact")
    
    def _generate_countermeasures(self, threat_type: str) -> list:
        """Generate specific countermeasures"""
        measures = {
            "sql_injection": ["Input validation", "WAF deployment", "Database hardening"],
            "ddos": ["Rate limiting", "CDN activation", "Traffic filtering"],
            "xss": ["Output encoding", "CSP headers", "Input sanitization"],
            "phishing": ["Email filtering", "User training", "MFA enforcement"]
        }
        return measures.get(threat_type, ["General monitoring", "System hardening"])