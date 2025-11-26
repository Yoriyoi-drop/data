"""Workflow routes (stub)"""
from fastapi import APIRouter
router = APIRouter()

@router.get("/")
async def list_workflows():
    return {"message": "Workflow endpoint - coming soon", "workflows": []}
