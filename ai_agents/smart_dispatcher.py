"""
Smart Dispatcher - AI-powered task assignment dengan machine learning
"""
import asyncio
import time
from typing import Dict, Any, List, Tuple
from dataclasses import dataclass
from .base_agent import TaskPriority

@dataclass
class TaskProfile:
    complexity: float  # 0.0-1.0
    urgency: float     # 0.0-1.0
    data_size: int     # bytes
    estimated_time: float  # seconds
    requires_memory: bool
    language: str = "english"

class SmartDispatcher:
    def __init__(self):
        self.assignment_history = []
        self.performance_cache = {}
        self.learning_enabled = True
        
    async def analyze_task(self, task: Dict[str, Any]) -> TaskProfile:
        """Analyze task untuk menentukan profile"""
        task_type = task.get('type', '')
        data = task.get('data', {})
        
        # Calculate complexity
        complexity = self._calculate_complexity(task_type, data)
        
        # Calculate urgency
        urgency = self._calculate_urgency(task.get('priority', 'medium'))
        
        # Estimate data size
        data_size = len(str(data))
        
        # Estimate processing time
        estimated_time = self._estimate_time(task_type, complexity)
        
        # Check if requires memory
        requires_memory = task_type in ['threat_analysis', 'pattern_recognition']
        
        # Detect language
        language = self._detect_language(data)
        
        return TaskProfile(
            complexity=complexity,
            urgency=urgency,
            data_size=data_size,
            estimated_time=estimated_time,
            requires_memory=requires_memory,
            language=language
        )
    
    async def find_optimal_agent(self, task_profile: TaskProfile, available_agents: Dict) -> str:
        """Find optimal agent berdasarkan AI analysis"""
        
        agent_scores = {}
        
        for agent_name, agent in available_agents.items():
            score = await self._calculate_agent_score(agent_name, agent, task_profile)
            agent_scores[agent_name] = score
        
        # Sort by score (highest first)
        sorted_agents = sorted(agent_scores.items(), key=lambda x: x[1], reverse=True)
        
        # Learn from assignment
        if self.learning_enabled and sorted_agents:
            await self._record_assignment(sorted_agents[0][0], task_profile)
        
        return sorted_agents[0][0] if sorted_agents else None
    
    async def _calculate_agent_score(self, agent_name: str, agent, task_profile: TaskProfile) -> float:
        """Calculate agent suitability score"""
        
        base_scores = {
            'gpt5': {'complexity': 0.9, 'reasoning': 0.95, 'speed': 0.7},
            'claude': {'complexity': 0.8, 'reasoning': 0.9, 'speed': 0.75},
            'grok': {'complexity': 0.7, 'reasoning': 0.8, 'speed': 0.9},
            'mistral': {'complexity': 0.6, 'reasoning': 0.7, 'speed': 0.95}
        }
        
        agent_profile = base_scores.get(agent_name, {'complexity': 0.5, 'reasoning': 0.5, 'speed': 0.5})
        
        # Base capability score
        capability_score = 0.0
        if task_profile.complexity > 0.7:
            capability_score = agent_profile['complexity']
        elif task_profile.urgency > 0.8:
            capability_score = agent_profile['speed']
        else:
            capability_score = agent_profile['reasoning']
        
        # Load penalty
        load_score = await agent.get_load_score()
        load_penalty = load_score * 0.3
        
        # Performance bonus from history
        performance_bonus = self.performance_cache.get(agent_name, 0.0) * 0.2
        
        # Language bonus
        language_bonus = 0.1 if agent_name == 'mistral' and task_profile.language != 'english' else 0.0
        
        final_score = capability_score - load_penalty + performance_bonus + language_bonus
        
        return max(0.0, min(1.0, final_score))
    
    def _calculate_complexity(self, task_type: str, data: Dict) -> float:
        """Calculate task complexity"""
        complexity_map = {
            'strategic_planning': 0.9,
            'vulnerability_assessment': 0.8,
            'threat_analysis': 0.7,
            'code_review': 0.6,
            'pattern_recognition': 0.5,
            'log_analysis': 0.3,
            'quick_analysis': 0.2
        }
        
        base_complexity = complexity_map.get(task_type, 0.5)
        
        # Adjust based on data size
        data_complexity = min(len(str(data)) / 1000, 0.3)
        
        return min(1.0, base_complexity + data_complexity)
    
    def _calculate_urgency(self, priority: str) -> float:
        """Calculate task urgency"""
        urgency_map = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.5,
            'low': 0.2
        }
        return urgency_map.get(priority.lower(), 0.5)
    
    def _estimate_time(self, task_type: str, complexity: float) -> float:
        """Estimate processing time"""
        base_times = {
            'strategic_planning': 0.3,
            'vulnerability_assessment': 0.25,
            'threat_analysis': 0.2,
            'code_review': 0.2,
            'pattern_recognition': 0.15,
            'log_analysis': 0.1,
            'quick_analysis': 0.05
        }
        
        base_time = base_times.get(task_type, 0.15)
        return base_time * (1 + complexity)
    
    def _detect_language(self, data: Dict) -> str:
        """Simple language detection"""
        text = str(data).lower()
        
        if any(char in text for char in "àáâãäåæçèéêë"):
            return "french"
        elif any(char in text for char in "äöüß"):
            return "german"
        elif any(char in text for char in "ñáéíóú"):
            return "spanish"
        else:
            return "english"
    
    async def _record_assignment(self, agent_name: str, task_profile: TaskProfile):
        """Record assignment for learning"""
        self.assignment_history.append({
            'agent': agent_name,
            'complexity': task_profile.complexity,
            'urgency': task_profile.urgency,
            'timestamp': time.time()
        })
        
        # Keep only recent history
        if len(self.assignment_history) > 1000:
            self.assignment_history = self.assignment_history[-500:]
    
    async def update_performance(self, agent_name: str, success: bool, processing_time: float):
        """Update agent performance cache"""
        if agent_name not in self.performance_cache:
            self.performance_cache[agent_name] = 0.5
        
        # Update with exponential moving average
        current_score = self.performance_cache[agent_name]
        new_score = 1.0 if success else 0.0
        
        # Time bonus/penalty
        time_factor = max(0.5, min(1.5, 1.0 / processing_time))
        adjusted_score = new_score * time_factor
        
        self.performance_cache[agent_name] = 0.9 * current_score + 0.1 * adjusted_score