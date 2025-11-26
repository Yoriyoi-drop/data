"""
Agents routes – expose example AI agents.
"""
from fastapi import APIRouter
from ai_hub.app.agents.example_agent import ExampleAgent

router = APIRouter()

# Instantiate a single example agent (could be extended to a registry)
example_agent = ExampleAgent()

@router.get("/")
async def list_agents():
    """Return a list of available agents (stub)."""
    return {"agents": ["example"]}

@router.post("/process")
async def process_agent(payload: dict):
    """Process a payload through the ExampleAgent and return the result."""
    result = await example_agent.process(payload)
    return result
