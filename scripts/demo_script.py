#!/usr/bin/env python3
"""
Demo Script - Automated demo untuk presentasi
"""
import asyncio
import aiohttp
import json
import time
from datetime import datetime

class DemoOrchestrator:
    def __init__(self):
        self.api_base = "http://localhost:8000"
        self.demo_steps = []
        
    def log_step(self, step, status="✅"):
        """Log demo step dengan timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{status} [{timestamp}] {step}")
        self.demo_steps.append(f"{timestamp}: {step}")
    
    async def check_services(self):
        """Verify semua services running"""
        self.log_step("Checking service health...")
        
        services = {
            "API": "http://localhost:8000/",
            "Dashboard": "http://localhost:3000",
            "Scanner": "http://localhost:8080/health"
        }
        
        async with aiohttp.ClientSession() as session:
            for name, url in services.items():
                try:
                    async with session.get(url, timeout=5) as response:
                        if response.status == 200:
                            self.log_step(f"{name} service online")
                        else:
                            self.log_step(f"{name} service error: {response.status}", "❌")
                except Exception as e:
                    self.log_step(f"{name} service unreachable: {e}", "❌")
    
    async def demo_threat_detection(self):
        """Demo 1: Threat Detection & AI Analysis"""
        self.log_step("=== DEMO 1: AI Threat Detection ===")
        
        # Simulate SQL injection attack
        attack_data = {
            "source": "192.168.1.100",
            "payload": "' OR 1=1 --",
            "target": "/api/login",
            "severity": "high",
            "type": "sql_injection"
        }
        
        async with aiohttp.ClientSession() as session:
            try:
                self.log_step("Simulating SQL injection attack...")
                async with session.post(
                    f"{self.api_base}/api/threats/analyze",
                    json=attack_data
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        self.log_step(f"AI Analysis: {result.get('threat_level', 'unknown')} threat detected")
                        self.log_step(f"Confidence: {result.get('confidence', 0):.1%}")
                    else:
                        self.log_step("Analysis failed", "❌")
            except Exception as e:
                self.log_step(f"Demo 1 failed: {e}", "❌")
    
    async def demo_agent_collaboration(self):
        """Demo 2: Multi-Agent Collaboration"""
        self.log_step("=== DEMO 2: Multi-Agent Collaboration ===")
        
        async with aiohttp.ClientSession() as session:
            try:
                # Check new agent status
                async with session.get(f"{self.api_base}/api/agents/status") as response:
                    if response.status == 200:
                        agents = await response.json()
                        self.log_step(f"Active agents: {len(agents)}")
                        for name, status in agents.items():
                            self.log_step(f"  {name}: {status['status']} - {status['tasks_completed']} tasks completed")
                
                # Run test scenario
                self.log_step("Running comprehensive agent test scenario...")
                async with session.post(f"{self.api_base}/api/agents/test/scenario") as response:
                    if response.status == 200:
                        result = await response.json()
                        self.log_step(f"Test completed: {result['tasks_executed']} tasks executed")
                        
                        # Show individual results
                        for task_result in result['results']:
                            agent = task_result['agent']
                            task_type = task_result['task_type']
                            status = task_result['result'].get('status', 'unknown')
                            self.log_step(f"  {agent}: {task_type} -> {status}")
                
                # Trigger emergency mode
                self.log_step("Activating emergency mode...")
                async with session.post(f"{self.api_base}/api/agents/emergency") as response:
                    if response.status == 200:
                        result = await response.json()
                        activated = result.get('agents_activated', [])
                        self.log_step(f"Emergency mode: {len(activated)} agents activated")
                        
            except Exception as e:
                self.log_step(f"Demo 2 failed: {e}", "❌")
    
    async def demo_labyrinth_defense(self):
        """Demo 3: Infinite Labyrinth Defense"""
        self.log_step("=== DEMO 3: Infinite Labyrinth Defense ===")
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(f"{self.api_base}/api/labyrinth/stats") as response:
                    if response.status == 200:
                        stats = await response.json()
                        self.log_step(f"Labyrinth nodes: {stats['active_nodes']}")
                        self.log_step(f"Trapped intruders: {stats['trapped_intruders']}")
                        self.log_step(f"Success rate: {stats['trap_success_rate']}")
                        
            except Exception as e:
                self.log_step(f"Demo 3 failed: {e}", "❌")
    
    async def demo_real_time_monitoring(self):
        """Demo 4: Real-time Monitoring"""
        self.log_step("=== DEMO 4: Real-time Monitoring ===")
        
        async with aiohttp.ClientSession() as session:
            try:
                # Get performance metrics
                async with session.get(f"{self.api_base}/api/agents/performance") as response:
                    if response.status == 200:
                        metrics = await response.json()
                        self.log_step("Agent Performance Metrics:")
                        self.log_step(f"  Total agents: {metrics['total_agents']}")
                        self.log_step(f"  Active agents: {metrics['active_agents']}")
                        self.log_step(f"  Tasks completed: {metrics['total_tasks_completed']}")
                        self.log_step(f"  Success rate: {metrics['average_success_rate']:.1%}")
                
                # Get queue status
                async with session.get(f"{self.api_base}/api/agents/queue") as response:
                    if response.status == 200:
                        queue = await response.json()
                        self.log_step("Task Queue Status:")
                        self.log_step(f"  Queued tasks: {queue['queued_tasks']}")
                        self.log_step(f"  Processing tasks: {queue['processing_tasks']}")
                        self.log_step(f"  Auto-assignment: {queue['auto_assignment']}")
                
                # Get dashboard data
                async with session.get(f"{self.api_base}/api/dashboard/data") as response:
                    if response.status == 200:
                        data = await response.json()
                        self.log_step("System Overview:")
                        self.log_step(f"  Threats detected: {data['threats']['total']}")
                        self.log_step(f"  Critical threats: {data['threats']['critical']}")
                        self.log_step(f"  Labyrinth nodes: {data['labyrinth']['nodes']}")
                        
            except Exception as e:
                self.log_step(f"Demo 4 failed: {e}", "❌")
    
    async def run_full_demo(self):
        """Run complete demo sequence"""
        print("🎬 Starting Infinite AI Security Demo")
        print("=" * 50)
        
        await self.check_services()
        await asyncio.sleep(2)
        
        await self.demo_threat_detection()
        await asyncio.sleep(3)
        
        await self.demo_agent_collaboration()
        await asyncio.sleep(3)
        
        await self.demo_labyrinth_defense()
        await asyncio.sleep(3)
        
        await self.demo_real_time_monitoring()
        
        print("\n" + "=" * 50)
        print("Demo completed successfully!")
        print(f"Total steps: {len(self.demo_steps)}")
        print("Dashboard: http://localhost:3000")
        print("AI Agents API: http://localhost:8000/api/agents/status")
        print("Performance Metrics: http://localhost:8000/api/agents/performance")
        
        # Save demo log
        with open("demo_log.txt", "w") as f:
            f.write("Infinite AI Security Demo Log\n")
            f.write("=" * 40 + "\n")
            for step in self.demo_steps:
                f.write(step + "\n")
        
        print("Demo log saved to demo_log.txt")

async def main():
    demo = DemoOrchestrator()
    await demo.run_full_demo()

if __name__ == "__main__":
    asyncio.run(main())