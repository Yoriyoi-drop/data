"""
AI Agents API Routes V2 - Pydantic V2 dengan modern validation
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from typing import Dict, Any, Optional
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_agents.agent_registry import AgentRegistry
from ai_agents.base_agent import TaskPriority
from api.models_v2 import (
    TaskRequest, MaintenanceRequest, AgentResponse, 
    ErrorResponse, MetricsResponse
)

router = APIRouter(prefix="/api/agents", tags=["AI Agents V2"])

# Global registry instance
registry = AgentRegistry()

@router.get("/status", response_model=Dict[str, Any])
async def get_agents_status():
    """Get status semua AI agents"""
    try:
        return await registry.get_agent_status()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get agent status: {str(e)}")

@router.get("/performance", response_model=MetricsResponse)
async def get_performance_metrics():
    """Get comprehensive performance metrics"""
    try:
        metrics = await registry.get_performance_metrics()
        return MetricsResponse(**metrics)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get performance metrics: {str(e)}")

@router.get("/queue", response_model=Dict[str, Any])
async def get_queue_status():
    """Get task queue status"""
    try:
        return await registry.get_queue_status()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get queue status: {str(e)}")

@router.post("/task/submit", response_model=Dict[str, Any])
async def submit_task(task_request: TaskRequest):
    """Submit task untuk auto-assignment atau specific agent"""
    
    try:
        # Convert priority string to enum
        priority_map = {
            "low": TaskPriority.LOW,
            "medium": TaskPriority.MEDIUM,
            "high": TaskPriority.HIGH,
            "critical": TaskPriority.CRITICAL
        }
        
        priority = priority_map.get(task_request.priority.value, TaskPriority.MEDIUM)
        
        # Convert to dict using model_dump (Pydantic V2)
        task_dict = task_request.model_dump()
        task = {
            "type": task_dict["task_type"],
            "data": task_dict["data"]
        }
        
        if task_request.agent:
            # Direct assignment
            result = await registry.run_task(task_request.agent, task)
            return result
        else:
            # Auto-assignment via queue
            task_id = await registry.submit_task(task, priority)
            return {
                "task_id": task_id,
                "status": "queued",
                "message": "Task submitted for auto-assignment"
            }
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to submit task: {str(e)}")

@router.post("/task/run", response_model=AgentResponse)
async def run_task_direct(agent: str, task_type: str, data: Dict[str, Any] = {}):
    """Run task directly pada specific agent"""
    
    try:
        if agent not in ["gpt5", "claude", "grok", "mistral"]:
            raise HTTPException(status_code=400, detail="Invalid agent name")
        
        task = {"type": task_type, "data": data}
        result = await registry.run_task(agent, task)
        
        if "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])
        
        # Convert to AgentResponse model
        return AgentResponse(
            agent=result.get("agent", agent),
            task_type=result.get("task_type", task_type),
            result=result,
            confidence=result.get("confidence"),
            processing_time=result.get("processing_time"),
            status=result.get("status", "success")
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to run task: {str(e)}")

@router.post("/emergency", response_model=Dict[str, Any])
async def activate_emergency_mode():
    """Activate emergency mode - all agents priority processing"""
    try:
        result = await registry.emergency_mode()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to activate emergency mode: {str(e)}")

@router.post("/maintenance", response_model=Dict[str, Any])
async def set_maintenance_mode(request: MaintenanceRequest):
    """Set agent maintenance mode"""
    try:
        result = await registry.set_agent_maintenance(request.agent, request.maintenance)
        
        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to set maintenance mode: {str(e)}")

@router.get("/capabilities", response_model=Dict[str, Any])
async def get_agent_capabilities():
    """Get capabilities setiap agent"""
    try:
        capabilities = {}
        
        for name, agent in registry.agents.items():
            capabilities[name] = {
                "name": agent.name,
                "model_type": agent.model_type,
                "capabilities": agent.capabilities,
                "status": agent.status.value
            }
        
        return capabilities
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get capabilities: {str(e)}")

@router.get("/health/{agent_name}", response_model=Dict[str, Any])
async def get_agent_health(agent_name: str):
    """Get detailed health check untuk specific agent"""
    try:
        if agent_name not in registry.agents:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        agent = registry.agents[agent_name]
        return await agent.health_check()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get agent health: {str(e)}")

@router.get("/memory/{agent_name}", response_model=Dict[str, Any])
async def get_agent_memory(agent_name: str):
    """Get agent memory contents"""
    try:
        if agent_name not in registry.agents:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        agent = registry.agents[agent_name]
        return {
            "agent": agent_name,
            "memory_items": len(agent.memory),
            "memory_keys": list(agent.memory.keys())
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get agent memory: {str(e)}")

@router.post("/test/scenario", response_model=Dict[str, Any])
async def run_test_scenario(background_tasks: BackgroundTasks):
    """Run comprehensive test scenario"""
    
    try:
        test_tasks = [
            {"agent": "gpt5", "task_type": "threat_analysis", "data": {"source": "192.168.1.100", "type": "sql_injection"}},
            {"agent": "claude", "task_type": "code_review", "data": {"code": "SELECT * FROM users WHERE id = " + "user_input"}},
            {"agent": "grok", "task_type": "social_engineering_detection", "data": {"message": "URGENT: Click here to verify your account!"}},
            {"agent": "mistral", "task_type": "log_analysis", "data": {"logs": ["ERROR: Failed login", "WARNING: High CPU usage"]}}
        ]
        
        results = []
        
        for task_config in test_tasks:
            agent = task_config["agent"]
            task = {
                "type": task_config["task_type"],
                "data": task_config["data"]
            }
            
            result = await registry.run_task(agent, task)
            results.append({
                "agent": agent,
                "task_type": task_config["task_type"],
                "result": result
            })
        
        return {
            "test_scenario": "comprehensive_agent_test",
            "tasks_executed": len(results),
            "results": results,
            "status": "completed"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to run test scenario: {str(e)}")

# Error handlers
@router.exception_handler(ValueError)
async def value_error_handler(request, exc):
    return ErrorResponse(
        error="Validation Error",
        detail=str(exc)
    ).model_dump()