"""
API Gateway - Entry point for all requests
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import auth, agents, security, workflow, subscription, health, admin
from app.middleware.logging import LoggingMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.request_size_middleware import RequestSizeMiddleware

app = FastAPI(
    title="AI Security Platform API",
    description="200+ node workflow with 50 level pipeline",
    version="1.0.0"
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(LoggingMiddleware)
app.add_middleware(RateLimitMiddleware)

# Routes
app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(agents.router, prefix="/api/v1/agents", tags=["agents"])
app.include_router(security.router, prefix="/api/v1/security", tags=["security"])
app.include_router(workflow.router, prefix="/api/v1/workflow", tags=["workflow"])
app.include_router(subscription.router, prefix="/api/v1/subscription", tags=["subscription"])
app.include_router(health.router, prefix="/api/v1/health", tags=["health"])

@app.get("/")
async def root():
    return {
        "message": "AI Security Platform API",
        "version": "1.0.0",
        "features": {
            "workflow_nodes": 200,
            "pipeline_levels": 50,
            "teams": ["A (Analysis)", "B (Execution)", "C (Recovery)"]
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
