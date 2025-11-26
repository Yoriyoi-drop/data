"""
Example Agent for AI Hub
A minimal agent that echoes the received payload.
"""
from typing import Dict, Any

class ExampleAgent:
    def __init__(self, name: str = "example"):
        self.name = name

    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        # Simple echo logic – in real world this would contain AI/ML processing
        return {
            "agent": self.name,
            "input": input_data,
            "output": {"message": f"Processed by {self.name}"}
        }
