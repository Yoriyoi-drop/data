"""
Agent Registry - Advanced orchestration dengan load balancing dan task queue
"""
import asyncio
import time
from typing import Dict, Any, List, Optional
from queue import PriorityQueue
from .base_agent import BaseAgent, TaskPriority, AgentStatus
from .gpt5_agent import GPT5Agent
from .claude_agent import ClaudeAgent
from .grok_agent import GrokAgent
from .mistral_agent import MistralAgent
from .smart_dispatcher import SmartDispatcher
from .load_balancer import PredictiveLoadBalancer
from .labyrinth_integration import labyrinth_controller, ThreatEvent

class TaskQueue:
    def __init__(self):
        self.queue = PriorityQueue()
        self.processing = {}
        
    def add_task(self, task: Dict[str, Any], priority: TaskPriority = TaskPriority.MEDIUM):
        """Add task to queue dengan priority"""
        task_id = f"task_{int(time.time() * 1000)}"
        task['id'] = task_id
        task['created_at'] = time.time()
        
        # Priority queue uses negative values for higher priority
        self.queue.put((-priority.value, task_id, task))
        return task_id
    
    def get_next_task(self) -> Optional[Dict[str, Any]]:
        """Get next task from queue"""
        if not self.queue.empty():
            _, task_id, task = self.queue.get()
            self.processing[task_id] = task
            return task
        return None
    
    def complete_task(self, task_id: str):
        """Mark task as completed"""
        if task_id in self.processing:
            del self.processing[task_id]

class AgentRegistry:
    def __init__(self):
        self.agents = {
            "gpt5": GPT5Agent(),
            "claude": ClaudeAgent(), 
            "grok": GrokAgent(),
            "mistral": MistralAgent()
        }
        self.task_queue = TaskQueue()
        self.auto_assignment = True
        self.load_balancing = True
        
        # Advanced features
        self.smart_dispatcher = SmartDispatcher()
        self.load_balancer = PredictiveLoadBalancer()
        self.labyrinth_integration = True
        
        # Background task processor will be started when needed
        self._queue_processor_started = False
    
    async def submit_task(self, task: Dict[str, Any], priority: TaskPriority = TaskPriority.MEDIUM) -> str:
        """Submit task untuk processing"""
        # Start queue processor if not started
        if not self._queue_processor_started:
            asyncio.create_task(self._process_queue())
            self._queue_processor_started = True
            
        task_id = self.task_queue.add_task(task, priority)
        
        if not self.auto_assignment:
            return task_id
            
        # Auto-assign task to best agent
        best_agent = await self._find_best_agent(task)
        if best_agent:
            task['assigned_agent'] = best_agent
            
        return task_id
    
    async def run_task(self, agent_name: str, task: Dict[str, Any]) -> Dict[str, Any]:
        """Run task pada specific agent"""
        if agent_name not in self.agents:
            return {"error": f"Agent {agent_name} not found"}
        
        agent = self.agents[agent_name]
        
        # Check if agent can handle task
        if not await agent.can_handle_task(task):
            return {"error": f"Agent {agent_name} cannot handle task type {task.get('type')}"}
        
        return await agent.run_task(task)
    
    async def _find_best_agent(self, task: Dict[str, Any]) -> Optional[str]:
        """Find best agent untuk task berdasarkan capabilities dan load"""
        task_type = task.get('type', '')
        suitable_agents = []
        
        for name, agent in self.agents.items():
            if await agent.can_handle_task(task):
                load_score = await agent.get_load_score()
                suitable_agents.append((name, agent, load_score))
        
        if not suitable_agents:
            return None
        
        # Sort by load score (ascending) untuk load balancing
        suitable_agents.sort(key=lambda x: x[2])
        
        # Task assignment logic
        if task_type in ["strategic_planning", "complex_reasoning"]:
            # Complex tasks go to GPT-5
            return "gpt5" if "gpt5" in [a[0] for a in suitable_agents] else suitable_agents[0][0]
        elif task_type in ["quick_analysis", "log_analysis"]:
            # Fast tasks go to Mistral
            return "mistral" if "mistral" in [a[0] for a in suitable_agents] else suitable_agents[0][0]
        elif task_type in ["code_review", "compliance_check"]:
            # Code tasks go to Claude
            return "claude" if "claude" in [a[0] for a in suitable_agents] else suitable_agents[0][0]
        elif task_type in ["pattern_recognition", "anomaly_detection"]:
            # Pattern tasks go to Grok
            return "grok" if "grok" in [a[0] for a in suitable_agents] else suitable_agents[0][0]
        else:
            # Default: least loaded agent
            return suitable_agents[0][0]
    
    async def _process_queue(self):
        """Background task processor"""
        while True:
            try:
                task = self.task_queue.get_next_task()
                if task:
                    # Get assigned agent or find best one
                    agent_name = task.get('assigned_agent') or await self._find_best_agent(task)
                    
                    if agent_name and agent_name in self.agents:
                        # Process task
                        result = await self.agents[agent_name].run_task(task)
                        task['result'] = result
                        task['completed_at'] = time.time()
                        
                        # Mark as completed
                        self.task_queue.complete_task(task['id'])
                
                await asyncio.sleep(0.1)  # Prevent busy waiting
                
            except Exception as e:
                print(f"Queue processing error: {e}")
                await asyncio.sleep(1)
    
    async def get_agent_status(self) -> Dict[str, Any]:
        """Get status semua agents"""
        status = {}
        for name, agent in self.agents.items():
            status[name] = await agent.health_check()
        return status
    
    async def get_queue_status(self) -> Dict[str, Any]:
        """Get task queue status"""
        return {
            "queued_tasks": self.task_queue.queue.qsize(),
            "processing_tasks": len(self.task_queue.processing),
            "auto_assignment": self.auto_assignment,
            "load_balancing": self.load_balancing
        }
    
    async def emergency_mode(self) -> Dict[str, Any]:
        """Activate emergency mode - all agents priority processing"""
        results = []
        for name, agent in self.agents.items():
            if agent.status != AgentStatus.MAINTENANCE:
                agent.status = AgentStatus.BUSY  # Emergency activation
                results.append(f"{name} activated")
        
        return {
            "emergency_activated": True,
            "agents_activated": results,
            "priority_processing": True
        }
    
    async def set_agent_maintenance(self, agent_name: str, maintenance: bool = True):
        """Set agent maintenance mode"""
        if agent_name in self.agents:
            status = AgentStatus.MAINTENANCE if maintenance else AgentStatus.IDLE
            self.agents[agent_name].status = status
            return {"agent": agent_name, "maintenance": maintenance}
        return {"error": "Agent not found"}
    
    async def get_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive performance metrics"""
        metrics = {
            "total_agents": len(self.agents),
            "active_agents": 0,
            "total_tasks_completed": 0,
            "total_tasks_failed": 0,
            "average_success_rate": 0.0,
            "agent_details": {}
        }
        
        success_rates = []
        
        for name, agent in self.agents.items():
            health = await agent.health_check()
            metrics["agent_details"][name] = health
            
            if health["status"] != "maintenance":
                metrics["active_agents"] += 1
            
            metrics["total_tasks_completed"] += health["tasks_completed"]
            metrics["total_tasks_failed"] += health["tasks_failed"]
            success_rates.append(health["success_rate"])
        
        if success_rates:
            metrics["average_success_rate"] = sum(success_rates) / len(success_rates)
        
        # Add advanced metrics
        try:
            load_balance_report = await self.load_balancer.get_health_report()
            metrics["load_balancer"] = load_balance_report
        except:
            metrics["load_balancer"] = {"status": "unavailable"}
        
        metrics["smart_dispatcher"] = {
            "assignments_made": len(self.smart_dispatcher.assignment_history),
            "learning_enabled": self.smart_dispatcher.learning_enabled,
            "performance_cache_size": len(self.smart_dispatcher.performance_cache)
        }
        
        if self.labyrinth_integration:
            try:
                labyrinth_status = await labyrinth_controller.get_all_active_traps()
                metrics["labyrinth_defense"] = labyrinth_status
            except:
                metrics["labyrinth_defense"] = {"status": "unavailable"}
        
        return metrics