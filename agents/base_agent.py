"""
Base Agent Interface - Template untuk semua AI agents
"""
from abc import ABC, abstractmethod
from typing import Dict, Any
import asyncio

class BaseAgent(ABC):
    def __init__(self, name: str, model: str):
        self.name = name
        self.model = model
        self.status = "idle"
        self.tasks_completed = 0
        
    @abstractmethod
    async def process_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Proses tugas utama agent"""
        pass
        
    @abstractmethod
    async def analyze_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analisis ancaman keamanan"""
        pass
        
    async def emergency_mode(self):
        """Mode darurat - prioritas maksimal"""
        self.status = "emergency"
        return {"status": "emergency_activated", "agent": self.name}
        
    async def health_check(self) -> Dict[str, Any]:
        """Status kesehatan agent"""
        return {
            "name": self.name,
            "model": self.model,
            "status": self.status,
            "tasks_completed": self.tasks_completed
        }
        
    def log_activity(self, activity: str):
        """Log aktivitas agent"""
        print(f"[{self.name}] {activity}")
        
class MockAgent(BaseAgent):
    """Mock agent untuk testing"""
    
    async def process_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        await asyncio.sleep(0.1)  # Simulasi processing
        self.tasks_completed += 1
        return {"result": f"Task processed by {self.name}", "success": True}
        
    async def analyze_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "threat_level": "medium",
            "confidence": 0.85,
            "recommendation": "Monitor closely",
            "agent": self.name
        }