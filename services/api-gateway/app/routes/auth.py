"""Authentication routes (stub)"""
from fastapi import APIRouter
router = APIRouter()

@router.post("/login")
async def login():
    return {"message": "Login endpoint - coming soon"}

@router.post("/register")
async def register():
    return {"message": "Register endpoint - coming soon"}
