"""
Base Agent Class
"""
class BaseAgent:
    def __init__(self, name: str, team: str):
        self.name = name
        self.team = team
        
    async def process(self, input_data: dict) -> dict:
        raise NotImplementedError
