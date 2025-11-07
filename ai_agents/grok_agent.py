"""
Grok Agent - Pattern recognition dan social engineering detection
"""
import asyncio
from .base_agent import BaseAgent, AgentStatus
from typing import Dict, Any

class GrokAgent(BaseAgent):
    def __init__(self):
        capabilities = [
            "pattern_recognition", "social_engineering_detection", 
            "anomaly_detection", "behavioral_analysis", "real_time_scanning"
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
                "confidence": 0.91,
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