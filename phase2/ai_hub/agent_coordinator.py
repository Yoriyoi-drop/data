"""
Advanced AI Agent Coordinator for Infinite Labyrinth
Supports GPT-4/5, Claude, Grok, Mistral, Llama with secure task management
"""
import asyncio
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import asyncpg
import aioredis
from cryptography.fernet import Fernet
import logging

logger = logging.getLogger(__name__)

class AgentType(Enum):
    GPT4 = "gpt4"
    GPT5 = "gpt5"
    CLAUDE = "claude"
    GROK = "grok"
    MISTRAL = "mistral"
    LLAMA = "llama"

class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"

@dataclass
class AgentCapability:
    name: str
    description: str
    input_types: List[str]
    output_types: List[str]

@dataclass
class AIAgent:
    id: str
    name: str
    type: AgentType
    endpoint: str
    capabilities: List[AgentCapability]
    status: str = "inactive"
    last_heartbeat: Optional[datetime] = None
    metadata: Dict[str, Any] = None

@dataclass
class Task:
    id: str
    title: str
    task_type: str
    priority: int
    assigned_agent: Optional[str]
    status: TaskStatus
    payload: Dict[str, Any]
    result: Optional[Dict[str, Any]] = None
    created_at: datetime = None
    timeout_at: Optional[datetime] = None

class SecureTaskManager:
    """Handles encrypted task storage and retrieval"""
    
    def __init__(self, db_pool: asyncpg.Pool, encryption_key: bytes):
        self.db_pool = db_pool
        self.cipher = Fernet(encryption_key)
    
    async def encrypt_payload(self, payload: Dict[str, Any]) -> bytes:
        """Encrypt task payload"""
        json_payload = json.dumps(payload).encode()
        return self.cipher.encrypt(json_payload)
    
    async def decrypt_payload(self, encrypted_payload: bytes) -> Dict[str, Any]:
        """Decrypt task payload"""
        decrypted = self.cipher.decrypt(encrypted_payload)
        return json.loads(decrypted.decode())
    
    async def store_task(self, task: Task) -> bool:
        """Store encrypted task in database"""
        try:
            encrypted_payload = await self.encrypt_payload(task.payload)
            
            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO ai_hub.tasks 
                    (id, title, task_type, priority, assigned_agent, status, 
                     payload_encrypted, created_at, timeout_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                """, 
                task.id, task.title, task.task_type, task.priority,
                task.assigned_agent, task.status.value, encrypted_payload,
                task.created_at, task.timeout_at)
            
            return True
        except Exception as e:
            logger.error(f"Failed to store task {task.id}: {e}")
            return False
    
    async def get_task(self, task_id: str) -> Optional[Task]:
        """Retrieve and decrypt task"""
        try:
            async with self.db_pool.acquire() as conn:
                row = await conn.fetchrow("""
                    SELECT * FROM ai_hub.tasks WHERE id = $1
                """, task_id)
            
            if not row:
                return None
            
            payload = await self.decrypt_payload(row['payload_encrypted'])
            
            return Task(
                id=row['id'],
                title=row['title'],
                task_type=row['task_type'],
                priority=row['priority'],
                assigned_agent=row['assigned_agent'],
                status=TaskStatus(row['status']),
                payload=payload,
                result=row['result'],
                created_at=row['created_at'],
                timeout_at=row['timeout_at']
            )
        except Exception as e:
            logger.error(f"Failed to get task {task_id}: {e}")
            return None

class AgentCoordinator:
    """Advanced multi-agent coordination system"""
    
    def __init__(self, db_pool: asyncpg.Pool, redis_pool: aioredis.Redis, encryption_key: bytes):
        self.db_pool = db_pool
        self.redis = redis_pool
        self.task_manager = SecureTaskManager(db_pool, encryption_key)
        self.agents: Dict[str, AIAgent] = {}
        self.active_tasks: Dict[str, Task] = {}
        self.task_queue = asyncio.Queue()
        
    async def register_agent(self, agent: AIAgent) -> bool:
        """Register new AI agent"""
        try:
            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO ai_hub.agents 
                    (id, name, type, endpoint, capabilities, status, metadata)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    ON CONFLICT (id) DO UPDATE SET
                    status = $6, last_heartbeat = NOW()
                """, 
                agent.id, agent.name, agent.type.value, agent.endpoint,
                json.dumps([asdict(cap) for cap in agent.capabilities]),
                agent.status, json.dumps(agent.metadata or {}))
            
            self.agents[agent.id] = agent
            logger.info(f"Registered agent: {agent.name} ({agent.type.value})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register agent {agent.name}: {e}")
            return False
    
    async def create_task(self, title: str, task_type: str, payload: Dict[str, Any], 
                         priority: int = 5, timeout_minutes: int = 30) -> str:
        """Create new task"""
        task_id = str(uuid.uuid4())
        timeout_at = datetime.utcnow() + timedelta(minutes=timeout_minutes)
        
        task = Task(
            id=task_id,
            title=title,
            task_type=task_type,
            priority=priority,
            assigned_agent=None,
            status=TaskStatus.PENDING,
            payload=payload,
            created_at=datetime.utcnow(),
            timeout_at=timeout_at
        )
        
        if await self.task_manager.store_task(task):
            await self.task_queue.put(task)
            logger.info(f"Created task: {title} ({task_id})")
            return task_id
        
        raise Exception(f"Failed to create task: {title}")
    
    async def assign_task(self, task: Task) -> Optional[str]:
        """Assign task to best available agent"""
        suitable_agents = []
        
        for agent_id, agent in self.agents.items():
            if agent.status != "active":
                continue
                
            # Check if agent has required capabilities
            for capability in agent.capabilities:
                if capability.name == task.task_type:
                    suitable_agents.append((agent_id, agent))
                    break
        
        if not suitable_agents:
            logger.warning(f"No suitable agents for task {task.id}")
            return None
        
        # Select agent with lowest current load
        best_agent = min(suitable_agents, 
                        key=lambda x: len([t for t in self.active_tasks.values() 
                                         if t.assigned_agent == x[0]]))
        
        return best_agent[0]
    
    async def execute_task(self, task: Task, agent: AIAgent) -> Dict[str, Any]:
        """Execute task on assigned agent"""
        try:
            # Update task status
            task.status = TaskStatus.RUNNING
            task.assigned_agent = agent.id
            
            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    UPDATE ai_hub.tasks 
                    SET status = $1, assigned_agent = $2, started_at = NOW()
                    WHERE id = $3
                """, task.status.value, agent.id, task.id)
            
            # Execute based on agent type
            if agent.type == AgentType.GPT4:
                result = await self._execute_gpt4_task(task, agent)
            elif agent.type == AgentType.CLAUDE:
                result = await self._execute_claude_task(task, agent)
            elif agent.type == AgentType.GROK:
                result = await self._execute_grok_task(task, agent)
            elif agent.type == AgentType.MISTRAL:
                result = await self._execute_mistral_task(task, agent)
            else:
                raise Exception(f"Unsupported agent type: {agent.type}")
            
            # Update task with result
            task.status = TaskStatus.COMPLETED
            task.result = result
            
            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    UPDATE ai_hub.tasks 
                    SET status = $1, result = $2, finished_at = NOW()
                    WHERE id = $3
                """, task.status.value, json.dumps(result), task.id)
            
            return result
            
        except Exception as e:
            logger.error(f"Task execution failed {task.id}: {e}")
            task.status = TaskStatus.FAILED
            
            async with self.db_pool.acquire() as conn:
                await conn.execute("""
                    UPDATE ai_hub.tasks 
                    SET status = $1, finished_at = NOW()
                    WHERE id = $2
                """, task.status.value, task.id)
            
            raise
    
    async def _execute_gpt4_task(self, task: Task, agent: AIAgent) -> Dict[str, Any]:
        """Execute task on GPT-4 agent"""
        # Implement GPT-4 API call
        return {
            "agent_type": "gpt4",
            "task_id": task.id,
            "result": "GPT-4 analysis completed",
            "confidence": 0.95,
            "execution_time_ms": 1500
        }
    
    async def _execute_claude_task(self, task: Task, agent: AIAgent) -> Dict[str, Any]:
        """Execute task on Claude agent"""
        # Implement Claude API call
        return {
            "agent_type": "claude",
            "task_id": task.id,
            "result": "Claude analysis completed",
            "confidence": 0.92,
            "execution_time_ms": 1200
        }
    
    async def _execute_grok_task(self, task: Task, agent: AIAgent) -> Dict[str, Any]:
        """Execute task on Grok agent"""
        # Implement Grok API call
        return {
            "agent_type": "grok",
            "task_id": task.id,
            "result": "Grok analysis completed",
            "confidence": 0.88,
            "execution_time_ms": 800
        }
    
    async def _execute_mistral_task(self, task: Task, agent: AIAgent) -> Dict[str, Any]:
        """Execute task on Mistral agent"""
        # Implement Mistral API call
        return {
            "agent_type": "mistral",
            "task_id": task.id,
            "result": "Mistral analysis completed",
            "confidence": 0.90,
            "execution_time_ms": 1000
        }
    
    async def coordinate_multi_agent_task(self, title: str, subtasks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Coordinate complex task across multiple agents"""
        task_ids = []
        
        # Create subtasks
        for subtask in subtasks:
            task_id = await self.create_task(
                title=f"{title} - {subtask['type']}",
                task_type=subtask['type'],
                payload=subtask['payload'],
                priority=subtask.get('priority', 5)
            )
            task_ids.append(task_id)
        
        # Wait for all subtasks to complete
        results = []
        for task_id in task_ids:
            while True:
                task = await self.task_manager.get_task(task_id)
                if task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED]:
                    results.append({
                        "task_id": task_id,
                        "status": task.status.value,
                        "result": task.result
                    })
                    break
                await asyncio.sleep(1)
        
        # Aggregate results
        return {
            "coordination_id": str(uuid.uuid4()),
            "title": title,
            "subtask_count": len(subtasks),
            "completed_count": len([r for r in results if r["status"] == "completed"]),
            "results": results,
            "overall_status": "completed" if all(r["status"] == "completed" for r in results) else "partial"
        }
    
    async def start_task_processor(self):
        """Start background task processor"""
        while True:
            try:
                # Get next task from queue
                task = await self.task_queue.get()
                
                # Assign to agent
                agent_id = await self.assign_task(task)
                if not agent_id:
                    # Put back in queue and wait
                    await self.task_queue.put(task)
                    await asyncio.sleep(5)
                    continue
                
                agent = self.agents[agent_id]
                self.active_tasks[task.id] = task
                
                # Execute task
                try:
                    await self.execute_task(task, agent)
                finally:
                    self.active_tasks.pop(task.id, None)
                
            except Exception as e:
                logger.error(f"Task processor error: {e}")
                await asyncio.sleep(1)

# Example usage and initialization
async def initialize_coordinator():
    """Initialize the agent coordinator system"""
    
    # Database connection
    db_pool = await asyncpg.create_pool(
        "postgresql://user:pass@localhost/infinite_labyrinth",
        min_size=5, max_size=20
    )
    
    # Redis connection
    redis_pool = await aioredis.from_url("redis://localhost:6379")
    
    # Encryption key (should be from secure key management)
    encryption_key = Fernet.generate_key()
    
    # Create coordinator
    coordinator = AgentCoordinator(db_pool, redis_pool, encryption_key)
    
    # Register agents
    agents = [
        AIAgent(
            id="gpt4-security",
            name="GPT-4 Security Analyst",
            type=AgentType.GPT4,
            endpoint="https://api.openai.com/v1/chat/completions",
            capabilities=[
                AgentCapability("threat_analysis", "Analyze security threats", ["text"], ["json"]),
                AgentCapability("code_review", "Review code for vulnerabilities", ["code"], ["report"])
            ]
        ),
        AIAgent(
            id="claude-analyst",
            name="Claude Security Analyst",
            type=AgentType.CLAUDE,
            endpoint="https://api.anthropic.com/v1/messages",
            capabilities=[
                AgentCapability("vulnerability_assessment", "Assess vulnerabilities", ["scan_results"], ["assessment"]),
                AgentCapability("risk_analysis", "Analyze security risks", ["asset_data"], ["risk_report"])
            ]
        )
    ]
    
    for agent in agents:
        await coordinator.register_agent(agent)
    
    # Start task processor
    asyncio.create_task(coordinator.start_task_processor())
    
    return coordinator