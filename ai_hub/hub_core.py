"""
AI Hub Core - Otak koordinasi semua AI agents
"""
import asyncio
import logging
from typing import Dict, List, Any
from datetime import datetime

class AIHub:
    def __init__(self):
        self.agents = {}
        self.active_tasks = []
        self.threat_queue = asyncio.Queue()
        
    async def register_agent(self, agent_name: str, agent_instance):
        """Register AI agent ke hub"""
        self.agents[agent_name] = agent_instance
        logging.info(f"Agent {agent_name} registered")
        
    async def distribute_task(self, task: Dict[str, Any]):
        """Distribusi tugas ke agent yang tepat"""
        try:
            task_type = task.get('type')
            
            if task_type == 'threat_analysis' and 'gpt5' in self.agents:
                return await self.agents['gpt5'].process_task(task['data'])
            elif task_type == 'code_review' and 'claude' in self.agents:
                return await self.agents['claude'].process_task(task['data'])
            elif task_type == 'pattern_recognition' and 'grok' in self.agents:
                return await self.agents['grok'].process_task(task['data'])
            elif task_type == 'quick_analysis' and 'mistral' in self.agents:
                return await self.agents['mistral'].process_task(task['data'])
            else:
                # Default fallback
                available_agent = next(iter(self.agents.values()), None)
                if available_agent:
                    return await available_agent.process_task(task['data'])
                return {"error": "No agents available", "status": "failed"}
        except Exception as e:
            logging.error(f"Task distribution error: {e}")
            return {"error": str(e), "status": "failed"}
        
    async def emergency_response(self, threat_level: str):
        """Response otomatis untuk ancaman tinggi"""
        if threat_level == 'CRITICAL':
            # Aktivasi semua agent
            tasks = []
            for agent in self.agents.values():
                tasks.append(agent.emergency_mode())
            await asyncio.gather(*tasks)
            
    async def start_monitoring(self):
        """Mulai monitoring real-time"""
        while True:
            if not self.threat_queue.empty():
                threat = await self.threat_queue.get()
                await self.distribute_task(threat)
            await asyncio.sleep(0.1)

# Global hub instance
hub = AIHub()