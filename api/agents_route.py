"""
AI Agents Route - API endpoints untuk AI agents
"""
from fastapi import APIRouter, HTTPException
from typing import Dict, Any
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_hub.hub_core import hub

router = APIRouter(prefix="/api/agents", tags=["agents"])

@router.get("/status")
async def get_agents_status():
    """Get status semua AI agents"""
    status = {}
    for name, agent in hub.agents.items():
        status[name] = await agent.health_check()
    return status

@router.post("/task")
async def submit_task(task: Dict[str, Any]):
    """Submit task ke AI agents"""
    result = await hub.distribute_task(task)
    return result

@router.post("/emergency/{level}")
async def trigger_emergency(level: str):
    """Trigger emergency response"""
    await hub.emergency_response(level)
    return {"status": "emergency_activated", "level": level}

@router.get("/metrics")
async def get_agent_metrics():
    """Get agent performance metrics"""
    metrics = {}
    for name, agent in hub.agents.items():
        metrics[name] = {
            "tasks_completed": agent.tasks_completed,
            "status": agent.status,
            "model": agent.model
        }
    return metrics