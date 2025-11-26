import httpx
from contextlib import asynccontextmanager

@asynccontextmanager
async def get_client():
    async with httpx.AsyncClient(timeout=10) as client:
        yield client


async def fetch_json(url: str) -> dict:
    async with get_client() as client:
        r = await client.get(url)
        r.raise_for_status()
        return r.json()
