#!/usr/bin/env python3
"""
Demo Script V2 - Modern async demo dengan Pydantic V2 validation
"""
import asyncio
import aiohttp
import json
import time
from datetime import datetime
from typing import Dict, Any, List
from pydantic import BaseModel, field_validator

class DemoConfig(BaseModel):
    """Demo configuration dengan Pydantic V2"""
    api_base: str = "http://localhost:8000"
    timeout: int = 10
    retry_attempts: int = 3
    
    @field_validator("api_base")
    @classmethod
    def validate_api_base(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("API base must start with http:// or https://")
        return v.rstrip("/")

class DemoStep(BaseModel):
    """Demo step model"""
    name: str
    description: str
    endpoint: str
    method: str = "GET"
    data: Dict[str, Any] = {}
    expected_status: int = 200

class DemoOrchestrator:
    def __init__(self, config: DemoConfig = None):
        self.config = config or DemoConfig()
        self.demo_steps: List[str] = []
        self.results: List[Dict[str, Any]] = []
        
    def log_step(self, step: str, status: str = "SUCCESS") -> None:
        """Log demo step dengan timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        message = f"[{timestamp}] {status}: {step}"
        print(message)
        self.demo_steps.append(message)
    
    async def execute_request(self, step: DemoStep) -> Dict[str, Any]:
        """Execute HTTP request dengan error handling"""
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.config.timeout)) as session:
            try:
                url = f"{self.config.api_base}{step.endpoint}"
                
                if step.method.upper() == "GET":
                    async with session.get(url) as response:
                        result = await self._process_response(response, step)
                elif step.method.upper() == "POST":
                    async with session.post(url, json=step.data) as response:
                        result = await self._process_response(response, step)
                else:
                    raise ValueError(f"Unsupported method: {step.method}")
                
                return result
                
            except asyncio.TimeoutError:
                return {"error": "Request timeout", "status": "TIMEOUT"}
            except Exception as e:
                return {"error": str(e), "status": "ERROR"}
    
    async def _process_response(self, response: aiohttp.ClientResponse, step: DemoStep) -> Dict[str, Any]:
        """Process HTTP response"""
        
        if response.status == step.expected_status:
            try:
                data = await response.json()
                return {"data": data, "status": "SUCCESS", "response_code": response.status}
            except:
                text = await response.text()
                return {"data": text, "status": "SUCCESS", "response_code": response.status}
        else:
            error_text = await response.text()
            return {
                "error": f"Unexpected status code: {response.status}",
                "response_text": error_text,
                "status": "ERROR",
                "response_code": response.status
            }
    
    async def check_services(self) -> None:
        """Verify semua services running"""
        self.log_step("Checking service health...")
        
        services = [
            DemoStep(name="API", description="Main API health", endpoint="/health"),
            DemoStep(name="Agents", description="Agent status", endpoint="/api/agents/status"),
            DemoStep(name="Performance", description="Performance metrics", endpoint="/api/agents/performance")
        ]
        
        for service in services:
            result = await self.execute_request(service)
            if result["status"] == "SUCCESS":
                self.log_step(f"{service.name} service online")
            else:
                self.log_step(f"{service.name} service error: {result.get('error', 'Unknown')}", "ERROR")
    
    async def demo_threat_detection(self) -> None:
        """Demo 1: Advanced Threat Detection"""
        self.log_step("=== DEMO 1: AI Threat Detection ===")
        
        threat_step = DemoStep(
            name="Threat Analysis",
            description="SQL injection simulation",
            endpoint="/api/threats/analyze",
            method="POST",
            data={
                "source": "192.168.1.100",
                "payload": "' OR 1=1 --",
                "target": "/api/login",
                "severity": "high",
                "type": "sql_injection"
            }
        )
        
        self.log_step("Simulating SQL injection attack...")
        result = await self.execute_request(threat_step)
        
        if result["status"] == "SUCCESS":
            analysis = result["data"]
            threat_level = analysis.get("threat_level", "unknown")
            confidence = analysis.get("confidence", 0)
            self.log_step(f"AI Analysis: {threat_level} threat detected")
            self.log_step(f"Confidence: {confidence:.1%}")
        else:
            self.log_step(f"Analysis failed: {result.get('error')}", "ERROR")
    
    async def demo_agent_collaboration(self) -> None:
        """Demo 2: Multi-Agent Collaboration V2"""
        self.log_step("=== DEMO 2: Multi-Agent Collaboration V2 ===")
        
        # Check agent status
        status_step = DemoStep(
            name="Agent Status",
            description="Get all agent status",
            endpoint="/api/agents/status"
        )
        
        result = await self.execute_request(status_step)
        if result["status"] == "SUCCESS":
            agents = result["data"]
            self.log_step(f"Active agents: {len(agents)}")
            for name, status in agents.items():
                tasks = status.get("tasks_completed", 0)
                agent_status = status.get("status", "unknown")
                self.log_step(f"  {name}: {agent_status} - {tasks} tasks completed")
        
        # Run comprehensive test
        test_step = DemoStep(
            name="Agent Test",
            description="Comprehensive agent test",
            endpoint="/api/agents/test/scenario",
            method="POST"
        )
        
        self.log_step("Running comprehensive agent test scenario...")
        result = await self.execute_request(test_step)
        
        if result["status"] == "SUCCESS":
            test_data = result["data"]
            tasks_executed = test_data.get("tasks_executed", 0)
            self.log_step(f"Test completed: {tasks_executed} tasks executed")
            
            for task_result in test_data.get("results", []):
                agent = task_result.get("agent", "unknown")
                task_type = task_result.get("task_type", "unknown")
                status = task_result.get("result", {}).get("status", "unknown")
                self.log_step(f"  {agent}: {task_type} -> {status}")
        
        # Emergency mode activation
        emergency_step = DemoStep(
            name="Emergency Mode",
            description="Activate emergency response",
            endpoint="/api/agents/emergency",
            method="POST"
        )
        
        self.log_step("Activating emergency mode...")
        result = await self.execute_request(emergency_step)
        
        if result["status"] == "SUCCESS":
            emergency_data = result["data"]
            activated = emergency_data.get("agents_activated", [])
            self.log_step(f"Emergency mode: {len(activated)} agents activated")
    
    async def demo_performance_monitoring(self) -> None:
        """Demo 3: Performance Monitoring V2"""
        self.log_step("=== DEMO 3: Performance Monitoring V2 ===")
        
        # Performance metrics
        perf_step = DemoStep(
            name="Performance Metrics",
            description="Get performance data",
            endpoint="/api/agents/performance"
        )
        
        result = await self.execute_request(perf_step)
        if result["status"] == "SUCCESS":
            metrics = result["data"]
            self.log_step("Agent Performance Metrics:")
            self.log_step(f"  Total agents: {metrics.get('total_agents', 0)}")
            self.log_step(f"  Active agents: {metrics.get('active_agents', 0)}")
            self.log_step(f"  Tasks completed: {metrics.get('total_tasks_completed', 0)}")
            self.log_step(f"  Success rate: {metrics.get('average_success_rate', 0):.1%}")
        
        # Queue status
        queue_step = DemoStep(
            name="Queue Status",
            description="Get task queue status",
            endpoint="/api/agents/queue"
        )
        
        result = await self.execute_request(queue_step)
        if result["status"] == "SUCCESS":
            queue = result["data"]
            self.log_step("Task Queue Status:")
            self.log_step(f"  Queued tasks: {queue.get('queued_tasks', 0)}")
            self.log_step(f"  Processing tasks: {queue.get('processing_tasks', 0)}")
            self.log_step(f"  Auto-assignment: {queue.get('auto_assignment', False)}")
    
    async def run_full_demo(self) -> None:
        """Run complete demo sequence V2"""
        print("Starting Infinite AI Security Demo V2")
        print("=" * 60)
        
        start_time = time.time()
        
        try:
            await self.check_services()
            await asyncio.sleep(2)
            
            await self.demo_threat_detection()
            await asyncio.sleep(3)
            
            await self.demo_agent_collaboration()
            await asyncio.sleep(3)
            
            await self.demo_performance_monitoring()
            
            elapsed_time = time.time() - start_time
            
            print("\n" + "=" * 60)
            print("Demo V2 completed successfully!")
            print(f"Total steps: {len(self.demo_steps)}")
            print(f"Execution time: {elapsed_time:.2f} seconds")
            print("Dashboard: http://localhost:3000")
            print("API V2: http://localhost:8000")
            print("Performance: http://localhost:8000/api/agents/performance")
            
            # Save demo log
            await self._save_demo_log()
            
        except Exception as e:
            self.log_step(f"Demo failed: {str(e)}", "ERROR")
            raise
    
    async def _save_demo_log(self) -> None:
        """Save demo log to file"""
        log_data = {
            "demo_version": "2.0",
            "timestamp": datetime.now().isoformat(),
            "steps": self.demo_steps,
            "results_summary": {
                "total_steps": len(self.demo_steps),
                "success_steps": len([s for s in self.demo_steps if "SUCCESS" in s]),
                "error_steps": len([s for s in self.demo_steps if "ERROR" in s])
            }
        }
        
        with open("demo_log_v2.json", "w") as f:
            json.dump(log_data, f, indent=2)
        
        print("Demo log V2 saved to demo_log_v2.json")

async def main():
    """Main demo function"""
    config = DemoConfig()
    demo = DemoOrchestrator(config)
    await demo.run_full_demo()

if __name__ == "__main__":
    asyncio.run(main())