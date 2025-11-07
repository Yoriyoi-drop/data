"""
Advanced Load Balancer - Predictive scaling dan intelligent distribution
"""
import asyncio
import time
import statistics
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from collections import deque

@dataclass
class LoadMetrics:
    cpu_usage: float
    memory_usage: float
    task_queue_size: int
    response_time: float
    success_rate: float
    timestamp: float

class PredictiveLoadBalancer:
    def __init__(self):
        self.metrics_history = {}  # agent_name -> deque of LoadMetrics
        self.prediction_window = 300  # 5 minutes
        self.scaling_threshold = 0.8
        self.circuit_breakers = {}
        
    async def get_load_distribution(self, agents: Dict) -> Dict[str, float]:
        """Get current load distribution across agents"""
        distribution = {}
        
        for agent_name, agent in agents.items():
            load_score = await agent.get_load_score()
            distribution[agent_name] = load_score
            
            # Update metrics history
            await self._update_metrics(agent_name, agent)
        
        return distribution
    
    async def select_least_loaded_agent(self, agents: Dict, task_requirements: Dict = None) -> Optional[str]:
        """Select agent dengan load terendah yang memenuhi requirements"""
        
        suitable_agents = []
        
        for agent_name, agent in agents.items():
            # Check circuit breaker
            if self._is_circuit_open(agent_name):
                continue
            
            # Check task requirements
            if task_requirements and not await self._meets_requirements(agent, task_requirements):
                continue
            
            load_score = await agent.get_load_score()
            predicted_load = await self._predict_load(agent_name)
            
            # Combine current and predicted load
            combined_score = (load_score * 0.7) + (predicted_load * 0.3)
            
            suitable_agents.append((agent_name, combined_score))
        
        if not suitable_agents:
            return None
        
        # Sort by combined score (lowest first)
        suitable_agents.sort(key=lambda x: x[1])
        
        return suitable_agents[0][0]
    
    async def balance_load(self, agents: Dict) -> Dict[str, Any]:
        """Perform load balancing operations"""
        
        distribution = await self.get_load_distribution(agents)
        
        # Find overloaded and underloaded agents
        overloaded = []
        underloaded = []
        
        for agent_name, load in distribution.items():
            if load > self.scaling_threshold:
                overloaded.append((agent_name, load))
            elif load < 0.3:
                underloaded.append((agent_name, load))
        
        actions = []
        
        # Circuit breaker logic
        for agent_name, load in overloaded:
            if load > 0.95:
                self._open_circuit(agent_name)
                actions.append(f"Circuit breaker opened for {agent_name}")
        
        # Scaling recommendations
        if len(overloaded) > len(underloaded):
            actions.append("Recommend scaling up: add more agent instances")
        elif len(underloaded) > 2:
            actions.append("Recommend scaling down: reduce agent instances")
        
        return {
            "distribution": distribution,
            "overloaded_agents": len(overloaded),
            "underloaded_agents": len(underloaded),
            "actions_taken": actions,
            "recommendations": await self._get_scaling_recommendations(distribution)
        }
    
    async def _update_metrics(self, agent_name: str, agent):
        """Update metrics history for agent"""
        
        if agent_name not in self.metrics_history:
            self.metrics_history[agent_name] = deque(maxlen=100)
        
        # Simulate metrics (in real implementation, get from monitoring)
        load_score = await agent.get_load_score()
        
        metrics = LoadMetrics(
            cpu_usage=load_score * 100,
            memory_usage=min(load_score * 80 + 20, 100),
            task_queue_size=int(load_score * 10),
            response_time=0.1 + (load_score * 0.4),
            success_rate=max(0.8, 1.0 - (load_score * 0.2)),
            timestamp=time.time()
        )
        
        self.metrics_history[agent_name].append(metrics)
    
    async def _predict_load(self, agent_name: str) -> float:
        """Predict future load berdasarkan historical data"""
        
        if agent_name not in self.metrics_history:
            return 0.5
        
        history = list(self.metrics_history[agent_name])
        
        if len(history) < 3:
            return history[-1].cpu_usage / 100 if history else 0.5
        
        # Simple trend analysis
        recent_loads = [m.cpu_usage / 100 for m in history[-10:]]
        
        if len(recent_loads) >= 3:
            # Calculate trend
            trend = (recent_loads[-1] - recent_loads[0]) / len(recent_loads)
            predicted = recent_loads[-1] + (trend * 3)  # Predict 3 steps ahead
            
            return max(0.0, min(1.0, predicted))
        
        return statistics.mean(recent_loads)
    
    async def _meets_requirements(self, agent, requirements: Dict) -> bool:
        """Check if agent meets task requirements"""
        
        required_capabilities = requirements.get('capabilities', [])
        
        for capability in required_capabilities:
            if capability not in agent.capabilities:
                return False
        
        # Check load threshold
        max_load = requirements.get('max_load', 1.0)
        current_load = await agent.get_load_score()
        
        if current_load > max_load:
            return False
        
        return True
    
    def _is_circuit_open(self, agent_name: str) -> bool:
        """Check if circuit breaker is open for agent"""
        
        if agent_name not in self.circuit_breakers:
            return False
        
        breaker = self.circuit_breakers[agent_name]
        
        # Auto-close circuit after timeout
        if time.time() - breaker['opened_at'] > breaker['timeout']:
            del self.circuit_breakers[agent_name]
            return False
        
        return True
    
    def _open_circuit(self, agent_name: str):
        """Open circuit breaker for overloaded agent"""
        
        self.circuit_breakers[agent_name] = {
            'opened_at': time.time(),
            'timeout': 60,  # 1 minute timeout
            'reason': 'overload'
        }
    
    async def _get_scaling_recommendations(self, distribution: Dict) -> List[str]:
        """Get scaling recommendations"""
        
        recommendations = []
        
        avg_load = statistics.mean(distribution.values())
        max_load = max(distribution.values())
        min_load = min(distribution.values())
        
        if avg_load > 0.8:
            recommendations.append("High average load - consider adding more agents")
        
        if max_load > 0.95:
            recommendations.append("Critical load detected - immediate scaling required")
        
        if max_load - min_load > 0.5:
            recommendations.append("Uneven load distribution - optimize task routing")
        
        if avg_load < 0.3:
            recommendations.append("Low utilization - consider reducing agent count")
        
        return recommendations
    
    async def get_health_report(self) -> Dict[str, Any]:
        """Generate comprehensive health report"""
        
        report = {
            "total_agents_monitored": len(self.metrics_history),
            "circuit_breakers_active": len(self.circuit_breakers),
            "prediction_accuracy": await self._calculate_prediction_accuracy(),
            "load_variance": await self._calculate_load_variance(),
            "recommendations": []
        }
        
        # Add circuit breaker details
        if self.circuit_breakers:
            report["circuit_breaker_details"] = {
                agent: {
                    "duration": time.time() - info['opened_at'],
                    "reason": info['reason']
                }
                for agent, info in self.circuit_breakers.items()
            }
        
        return report
    
    async def _calculate_prediction_accuracy(self) -> float:
        """Calculate prediction accuracy (mock implementation)"""
        return 0.85  # 85% accuracy
    
    async def _calculate_load_variance(self) -> float:
        """Calculate load variance across agents"""
        
        if not self.metrics_history:
            return 0.0
        
        recent_loads = []
        for agent_history in self.metrics_history.values():
            if agent_history:
                recent_loads.append(agent_history[-1].cpu_usage / 100)
        
        if len(recent_loads) < 2:
            return 0.0
        
        return statistics.variance(recent_loads)