#!/usr/bin/env python3
"""
Demo Runner - Jalankan demo sistem dengan data simulasi
"""
import asyncio
import aiohttp
import json
import time
import random

async def test_api_connection():
    """Test koneksi ke API"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('http://localhost:8000/') as response:
                if response.status == 200:
                    print("✅ API connection successful")
                    return True
    except:
        print("❌ API not running on localhost:8000")
        return False

async def simulate_threats():
    """Simulasi ancaman untuk demo"""
    threats = [
        {"type": "SQL Injection", "severity": "high", "source": "192.168.1.100"},
        {"type": "XSS Attack", "severity": "medium", "source": "10.0.0.50"},
        {"type": "DDoS", "severity": "critical", "source": "203.0.113.1"},
        {"type": "Brute Force", "severity": "high", "source": "198.51.100.1"},
        {"type": "Malware", "severity": "critical", "source": "192.0.2.1"}
    ]
    
    async with aiohttp.ClientSession() as session:
        for i in range(10):
            threat = random.choice(threats)
            threat["timestamp"] = time.time()
            
            try:
                async with session.post(
                    'http://localhost:8000/api/threats/analyze',
                    json=threat
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        print(f"🎯 Threat {i+1}: {threat['type']} - {result.get('result', 'Processed')}")
                    else:
                        print(f"❌ Failed to process threat {i+1}")
            except Exception as e:
                print(f"❌ Error sending threat {i+1}: {e}")
            
            await asyncio.sleep(2)

async def check_agent_status():
    """Check status AI agents"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('http://localhost:8000/api/agents/status') as response:
                if response.status == 200:
                    agents = await response.json()
                    print("\n🤖 AI Agents Status:")
                    for name, status in agents.items():
                        print(f"  - {status['name']}: {status['status']} ({status['tasks_completed']} tasks)")
                else:
                    print("❌ Failed to get agent status")
    except Exception as e:
        print(f"❌ Error checking agents: {e}")

async def main():
    print("🛡️ Infinite AI Security Platform - Demo")
    print("=" * 50)
    
    # Test API connection
    if not await test_api_connection():
        print("💡 Please start the API server first: python api/main.py")
        return
    
    # Check agents
    await check_agent_status()
    
    print("\n🎬 Starting threat simulation...")
    await simulate_threats()
    
    print("\n📊 Final agent status:")
    await check_agent_status()
    
    print("\n🎉 Demo completed!")
    print("📊 Check dashboard at: http://localhost:5173")

if __name__ == "__main__":
    asyncio.run(main())