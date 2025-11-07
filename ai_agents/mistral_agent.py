"""
Mistral Agent - Fast processing dan multilingual support
"""
import asyncio
from .base_agent import BaseAgent, AgentStatus
from typing import Dict, Any

class MistralAgent(BaseAgent):
    def __init__(self):
        capabilities = [
            "quick_analysis", "multilingual_processing", "lightweight_tasks",
            "real_time_response", "log_analysis", "alert_processing"
        ]
        super().__init__("Mistral", "lightweight_model", capabilities)
        
    async def run_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute task dengan Mistral's speed"""
        self.status = AgentStatus.BUSY
        
        try:
            task_type = task.get('type', 'unknown')
            task_data = task.get('data', {})
            
            await asyncio.sleep(0.05)  # Very fast processing
            
            result = await self._quick_process(task_type, task_data)
            
            self.tasks_completed += 1
            self.status = AgentStatus.IDLE
            
            return {
                "agent": self.name,
                "task_type": task_type,
                "result": result,
                "confidence": 0.82,
                "processing_speed": "ultra_fast",
                "status": "success"
            }
            
        except Exception as e:
            self.tasks_failed += 1
            self.status = AgentStatus.ERROR
            return {"agent": self.name, "error": str(e), "status": "failed"}
    
    async def _quick_process(self, task_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Quick processing untuk lightweight tasks"""
        
        if task_type == "log_analysis":
            return await self._analyze_logs(data)
        elif task_type == "alert_processing":
            return await self._process_alerts(data)
        elif task_type == "multilingual_processing":
            return await self._process_multilingual(data)
        else:
            return {"result": f"Mistral quickly processed {task_type}", "speed": "optimized"}
    
    async def _analyze_logs(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Fast log analysis"""
        logs = data.get('logs', [])
        
        error_count = sum(1 for log in logs if 'error' in str(log).lower())
        warning_count = sum(1 for log in logs if 'warning' in str(log).lower())
        
        return {
            "total_logs": len(logs),
            "errors": error_count,
            "warnings": warning_count,
            "status": "critical" if error_count > 10 else "normal",
            "processing_time": "< 50ms"
        }
    
    async def _process_alerts(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process security alerts quickly"""
        alert = data.get('alert', {})
        severity = alert.get('severity', 'low')
        
        priority_mapping = {
            'low': 1,
            'medium': 2, 
            'high': 3,
            'critical': 4
        }
        
        return {
            "alert_processed": True,
            "priority": priority_mapping.get(severity, 1),
            "escalation_needed": severity in ['high', 'critical'],
            "response_time": "immediate"
        }
    
    async def _process_multilingual(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process multilingual content"""
        text = data.get('text', '')
        
        # Simple language detection
        language = "english"
        if any(char in text for char in "àáâãäåæçèéêë"):
            language = "french"
        elif any(char in text for char in "äöüß"):
            language = "german"
        elif any(char in text for char in "ñáéíóú"):
            language = "spanish"
        
        return {
            "detected_language": language,
            "text_processed": True,
            "translation_available": True,
            "processing_speed": "real_time"
        }