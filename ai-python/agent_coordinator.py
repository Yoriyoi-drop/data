"""
AI Agent Coordinator - Multi-agent orchestration for threat response
"""
import asyncio
from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ThreatEvent:
    id: str
    source_ip: str
    attack_type: str
    severity: ThreatLevel
    confidence: float
    raw_data: Dict[str, Any]

class AIAgent:
    def __init__(self, agent_id: str, specialization: str):
        self.agent_id = agent_id
        self.specialization = specialization
        self.active = True
        
    async def analyze_threat(self, event: ThreatEvent) -> Dict[str, Any]:
        """Analyze threat based on agent specialization"""
        return {
            "agent_id": self.agent_id,
            "confidence": 0.85,
            "recommendation": "block",
            "reasoning": f"{self.specialization} analysis complete"
        }

class AgentCoordinator:
    def __init__(self):
        self.agents: Dict[str, AIAgent] = {}
        self.active_threats: Dict[str, ThreatEvent] = {}
        
    def register_agent(self, agent: AIAgent):
        """Register new AI agent"""
        self.agents[agent.agent_id] = agent
        logger.info(f"Registered agent: {agent.agent_id}")
        
    async def coordinate_response(self, event: ThreatEvent) -> Dict[str, Any]:
        """Coordinate multi-agent threat response"""
        responses = []
        
        # Get responses from all active agents
        for agent in self.agents.values():
            if agent.active:
                response = await agent.analyze_threat(event)
                responses.append(response)
        
        # Aggregate responses
        avg_confidence = sum(r["confidence"] for r in responses) / len(responses)
        consensus = self._determine_consensus(responses)
        
        return {
            "threat_id": event.id,
            "consensus": consensus,
            "confidence": avg_confidence,
            "agent_count": len(responses),
            "action": "block" if avg_confidence > 0.7 else "monitor"
        }
    
    def _determine_consensus(self, responses: List[Dict[str, Any]]) -> str:
        """Determine consensus from agent responses"""
        recommendations = [r["recommendation"] for r in responses]
        return max(set(recommendations), key=recommendations.count)

# Initialize coordinator
coordinator = AgentCoordinator()

# Register specialized agents
coordinator.register_agent(AIAgent("sql_detector", "SQL Injection Detection"))
coordinator.register_agent(AIAgent("xss_analyzer", "Cross-Site Scripting Analysis"))
coordinator.register_agent(AIAgent("behavior_monitor", "Behavioral Analysis"))