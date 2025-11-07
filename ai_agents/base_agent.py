"""
Base Agent - Blueprint untuk semua AI agents
"""
import asyncio
import time
from abc import ABC, abstractmethod
from typing import Dict, Any, List
from enum import Enum

class TaskPriority(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class AgentStatus(Enum):
    IDLE = "idle"
    BUSY = "busy"
    ERROR = "error"
    MAINTENANCE = "maintenance"

class BaseAgent(ABC):
    def __init__(self, name: str, model_type: str, capabilities: List[str] = None):
        self.name = name
        self.model_type = model_type
        self.capabilities = capabilities or []
        self.status = AgentStatus.IDLE
        self.tasks_completed = 0
        self.tasks_failed = 0
        self.memory = {}
        self.load_score = 0.0
        self.created_at = time.time()
        
    @abstractmethod
    async def run_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute task - must be implemented by each agent"""
        pass
    
    async def can_handle_task(self, task: Dict[str, Any]) -> bool:
        """Check if agent can handle specific task type"""
        task_type = task.get('type', '')
        return task_type in self.capabilities
    
    async def get_load_score(self) -> float:
        """Calculate current load score (0.0 = idle, 1.0 = overloaded)"""
        base_load = min(self.tasks_completed / 100, 0.5)
        status_load = 0.8 if self.status == AgentStatus.BUSY else 0.0
        return min(base_load + status_load, 1.0)
    
    async def store_memory(self, key: str, value: Any):
        """Store information in agent memory"""
        self.memory[key] = {
            'value': value,
            'timestamp': time.time()
        }
    
    async def recall_memory(self, key: str) -> Any:
        """Retrieve information from agent memory"""
        if key in self.memory:
            return self.memory[key]['value']
        return None
    
    async def health_check(self) -> Dict[str, Any]:
        """Agent health and performance metrics"""
        uptime = time.time() - self.created_at
        success_rate = self.tasks_completed / max(self.tasks_completed + self.tasks_failed, 1)
        
        return {
            "name": self.name,
            "model_type": self.model_type,
            "status": self.status.value,
            "capabilities": self.capabilities,
            "tasks_completed": self.tasks_completed,
            "tasks_failed": self.tasks_failed,
            "success_rate": round(success_rate, 3),
            "load_score": await self.get_load_score(),
            "uptime_hours": round(uptime / 3600, 2),
            "memory_items": len(self.memory)
        }