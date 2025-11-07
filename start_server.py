#!/usr/bin/env python3
"""
Simple startup script untuk Infinite AI Security Platform
"""
import os
import sys

def main():
    print("\n" + "="*60)
    print("🚀 INFINITE AI SECURITY PLATFORM V2")
    print("="*60)
    print("🔄 Starting server...")
    print("📍 Location: http://localhost:8000")
    print("🤖 AI Agents: GPT-5, Claude, Grok, Mistral")
    print("🛡️ Security Engine: Multi-language")
    print("="*60)
    
    # Change to correct directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    print(f"📂 Working directory: {os.getcwd()}")
    print("🚀 Launching FastAPI server...\n")
    
    # Import and run
    try:
        from api.main_v2 import app
        import uvicorn
        
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8000,
            log_level="info"
        )
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        print("💡 Try: python api/main_v2.py")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())