"""Security routes (stub)"""
from fastapi import APIRouter
router = APIRouter()

@router.get("/")
async def list_scans():
    return {"message": "Security endpoint - coming soon", "scans": []}
