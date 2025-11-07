#!/usr/bin/env python3
"""
Simulation Script - Jalankan simulasi serangan untuk testing
"""
import asyncio
import aiohttp
import json
import random
from datetime import datetime

class SecuritySimulation:
    def __init__(self, api_base="http://localhost:8000"):
        self.api_base = api_base
        
    async def simulate_attack(self, attack_type: str):
        """Simulasi serangan untuk testing sistem"""
        attacks = {
            "sql_injection": {
                "source": f"192.168.1.{random.randint(100, 200)}",
                "payload": "' OR 1=1 --",
                "target": "/api/login",
                "severity": "high"
            },
            "ddos": {
                "source": f"10.0.0.{random.randint(1, 100)}",
                "requests_per_second": random.randint(1000, 5000),
                "target": "/",
                "severity": "critical"
            },
            "xss": {
                "source": f"172.16.0.{random.randint(1, 50)}",
                "payload": "<script>alert('XSS')</script>",
                "target": "/search",
                "severity": "medium"
            }
        }
        
        return attacks.get(attack_type, attacks["sql_injection"])
    
    async def run_simulation(self, duration_minutes: int = 5):
        """Jalankan simulasi selama durasi tertentu"""
        print(f"🚀 Starting security simulation for {duration_minutes} minutes...")
        
        attack_types = ["sql_injection", "ddos", "xss"]
        end_time = asyncio.get_event_loop().time() + (duration_minutes * 60)
        
        async with aiohttp.ClientSession() as session:
            while asyncio.get_event_loop().time() < end_time:
                # Generate random attack
                attack_type = random.choice(attack_types)
                attack_data = await self.simulate_attack(attack_type)
                
                try:
                    # Send to API for analysis
                    async with session.post(
                        f"{self.api_base}/api/threats/analyze",
                        json=attack_data
                    ) as response:
                        if response.status == 200:
                            result = await response.json()
                            print(f"⚡ Attack simulated: {attack_type} -> {result.get('threat_level', 'unknown')}")
                        else:
                            print(f"❌ API error: {response.status}")
                            
                except Exception as e:
                    print(f"❌ Connection error: {e}")
                
                # Wait before next attack
                await asyncio.sleep(random.uniform(1, 5))
        
        print("✅ Simulation completed!")

async def main():
    sim = SecuritySimulation()
    await sim.run_simulation(duration_minutes=2)

if __name__ == "__main__":
    asyncio.run(main())