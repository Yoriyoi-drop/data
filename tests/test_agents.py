"""
Agent Tests - Unit tests untuk AI agents
"""
import pytest
import asyncio
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.base_agent import BaseAgent, MockAgent
from agents.gpt5_agent import GPT5Agent

@pytest.mark.asyncio
async def test_mock_agent():
    """Test mock agent functionality"""
    agent = MockAgent("TestAgent", "test-model")
    
    # Test health check
    health = await agent.health_check()
    assert health["name"] == "TestAgent"
    assert health["status"] == "idle"
    
    # Test task processing
    task = {"type": "test", "data": "sample"}
    result = await agent.process_task(task)
    assert result["success"] is True
    assert agent.tasks_completed == 1

@pytest.mark.asyncio
async def test_gpt5_agent():
    """Test GPT-5 agent functionality"""
    agent = GPT5Agent()
    
    # Test health check
    health = await agent.health_check()
    assert health["name"] == "GPT-5"
    assert health["model"] == "gpt-5-turbo"
    
    # Test threat analysis
    threat_data = {"source": "192.168.1.100", "type": "sql_injection"}
    result = await agent.analyze_threat(threat_data)
    assert "threat_level" in result
    assert "confidence" in result
    
    # Test defense strategy
    strategy = await agent.plan_defense_strategy("ddos")
    assert "strategy" in strategy
    assert "priority" in strategy

@pytest.mark.asyncio
async def test_emergency_mode():
    """Test emergency mode activation"""
    agent = MockAgent("EmergencyTest", "test")
    
    result = await agent.emergency_mode()
    assert result["status"] == "emergency_activated"
    assert agent.status == "emergency"