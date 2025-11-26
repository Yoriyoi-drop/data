"""
Integration tests for the complete system
"""
import pytest
import asyncio
import requests
from pathlib import Path
import sys

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent.parent))

class TestSystemIntegration:
    """Test complete system integration"""
    
    def test_api_health(self):
        """Test API health endpoint"""
        try:
            response = requests.get("http://localhost:8000/health", timeout=5)
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "healthy"
        except requests.exceptions.ConnectionError:
            pytest.skip("API server not running")
    
    def test_agents_status(self):
        """Test agents status endpoint"""
        try:
            response = requests.get("http://localhost:8000/api/agents/status", timeout=5)
            assert response.status_code == 200
            data = response.json()
            assert "agents" in data
        except requests.exceptions.ConnectionError:
            pytest.skip("API server not running")
    
    def test_threat_analysis(self):
        """Test threat analysis endpoint"""
        try:
            payload = {
                "source": "192.168.1.100",
                "type": "sql_injection", 
                "severity": "high"
            }
            response = requests.post(
                "http://localhost:8000/api/threats/analyze",
                json=payload,
                timeout=10
            )
            assert response.status_code == 200
            data = response.json()
            assert "analysis" in data or "result" in data
        except requests.exceptions.ConnectionError:
            pytest.skip("API server not running")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
