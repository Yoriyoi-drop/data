"""
AI Hub - LangGraph Orchestration Core
200+ node workflow with 50 level pipeline
"""
from fastapi import FastAPI
from app.orchestrator.graph_builder import GraphBuilder
from app.orchestrator.pipeline_manager import PipelineManager

app = FastAPI(title="AI Hub - Orchestration Core")

# Initialize
graph_builder = GraphBuilder()
pipeline_manager = PipelineManager()

@app.on_event("startup")
async def startup():
    """Initialize 200 node graph and 50 level pipeline"""
    print("🚀 Building 200 node workflow graph...")
    await graph_builder.build_graph()
    
    print("📊 Initializing 50 level pipeline...")
    await pipeline_manager.initialize_pipeline()
    
    print("✅ AI Hub ready!")

@app.get("/")
async def root():
    return {
        "service": "AI Hub",
        "workflow_nodes": 200,
        "pipeline_levels": 50,
        "teams": {
            "team_a": "Analysis",
            "team_b": "Execution",
            "team_c": "Recovery"
        }
    }

@app.post("/orchestrate")
async def orchestrate(task: dict):
    """Orchestrate task through 200 nodes and 50 levels"""
    result = await pipeline_manager.execute(task)
    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
