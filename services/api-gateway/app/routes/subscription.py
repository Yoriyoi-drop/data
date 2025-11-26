"""Subscription routes (stub)"""
from fastapi import APIRouter
router = APIRouter()

@router.get("/")
async def list_subscriptions():
    return {"message": "Subscription endpoint - coming soon", "subscriptions": []}
