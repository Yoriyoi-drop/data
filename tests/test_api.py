"""
API Tests - Unit tests untuk FastAPI endpoints
"""
import pytest
from fastapi.testclient import TestClient
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.main import app

client = TestClient(app)

def test_root_endpoint():
    """Test root endpoint"""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"

def test_agents_status():
    """Test agents status endpoint"""
    response = client.get("/api/agents/status")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, dict)

def test_threat_analysis():
    """Test threat analysis endpoint"""
    threat_data = {
        "source": "192.168.1.100",
        "payload": "test payload",
        "severity": "high"
    }
    
    response = client.post("/api/threats/analyze", json=threat_data)
    assert response.status_code == 200
    data = response.json()
    assert "threat_level" in data or "analysis" in data

def test_emergency_trigger():
    """Test emergency response trigger"""
    response = client.post("/api/emergency?level=CRITICAL")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "emergency_activated"

def test_labyrinth_stats():
    """Test labyrinth stats endpoint"""
    response = client.get("/api/labyrinth/stats")
    assert response.status_code == 200
    data = response.json()
    assert "active_nodes" in data
    assert "trapped_intruders" in data

def test_dashboard_data():
    """Test dashboard data endpoint"""
    response = client.get("/api/dashboard/data")
    assert response.status_code == 200
    data = response.json()
    assert "agents" in data
    assert "threats" in data
    assert "labyrinth" in data