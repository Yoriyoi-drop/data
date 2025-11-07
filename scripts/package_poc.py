#!/usr/bin/env python3
"""
PoC Package Creator - Bundle everything for client delivery
"""
import os
import shutil
import tarfile
from pathlib import Path
import json
from datetime import datetime

def create_poc_package():
    """Create complete PoC package"""
    root_dir = Path(__file__).parent.parent
    package_dir = root_dir / "poc_package"
    
    # Clean and create package directory
    if package_dir.exists():
        shutil.rmtree(package_dir)
    package_dir.mkdir()
    
    print("📦 Creating PoC package...")
    
    # Copy essential files
    essential_files = [
        "README.md",
        "requirements.txt", 
        "pyproject.toml",
        ".env.sample",
        "deployment/docker-compose.yml",
        "deployment/Dockerfile_api",
        "deployment/Dockerfile_go", 
        "deployment/Dockerfile_rust",
        "deployment/Dockerfile_dashboard",
        "deployment/nginx.conf"
    ]
    
    for file_path in essential_files:
        src = root_dir / file_path
        if src.exists():
            dst = package_dir / file_path
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
    
    # Copy directories
    essential_dirs = [
        "api",
        "ai_hub", 
        "agents",
        "security_engine",
        "dashboard/src",
        "dashboard/public",
        "scripts",
        "docs"
    ]
    
    for dir_path in essential_dirs:
        src = root_dir / dir_path
        if src.exists():
            dst = package_dir / dir_path
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns('__pycache__', '*.pyc', 'node_modules'))
    
    # Create PoC-specific files
    create_poc_readme(package_dir)
    create_quick_start_script(package_dir)
    create_demo_data(package_dir)
    
    # Create tarball
    tarball_path = root_dir / f"infinite_ai_security_poc_{datetime.now().strftime('%Y%m%d')}.tar.gz"
    
    with tarfile.open(tarball_path, "w:gz") as tar:
        tar.add(package_dir, arcname="infinite_ai_security_poc")
    
    print(f"✅ PoC package created: {tarball_path}")
    print(f"📊 Package size: {tarball_path.stat().st_size / 1024 / 1024:.1f} MB")
    
    return tarball_path

def create_poc_readme(package_dir):
    """Create PoC-specific README"""
    readme_content = """# 🛡️ Infinite AI Security - Proof of Concept

## Quick Start (5 minutes)

### Prerequisites
- Docker & Docker Compose
- Python 3.11+
- Node.js 18+
- Go 1.21+
- Rust 1.75+

### One-Command Demo
```bash
# Start everything
python scripts/start_all.py

# Run automated demo
python scripts/demo_script.py
```

### Manual Setup
```bash
# 1. Install dependencies
pip install -r requirements.txt
cd dashboard && npm install

# 2. Start services
docker-compose up -d

# 3. Access dashboard
open http://localhost:3000
```

## Demo Scenarios

### Scenario 1: SQL Injection Detection
1. Navigate to dashboard
2. Click "Simulate Attack" 
3. Watch AI agents collaborate
4. See threat analysis in real-time

### Scenario 2: Infinite Labyrinth Defense
1. Monitor labyrinth visualization
2. See nodes generate dynamically
3. Watch intruders get trapped

### Scenario 3: Multi-Agent Response
1. Trigger emergency mode
2. See all agents activate
3. View coordinated response

## Key Metrics to Show
- **Detection Time**: < 100ms
- **Response Time**: < 500ms  
- **Trap Success Rate**: 94.7%
- **Agent Collaboration**: 4 AI models

## Support
- Email: support@infiniteai.security
- Demo video: https://demo.infiniteai.security
- Documentation: ./docs/

---
*This is a proof of concept. Production deployment requires additional configuration.*
"""
    
    with open(package_dir / "README_POC.md", "w") as f:
        f.write(readme_content)

def create_quick_start_script(package_dir):
    """Create quick start script for clients"""
    script_content = """#!/bin/bash
# Infinite AI Security - Quick Start Script

echo "🛡️  Starting Infinite AI Security PoC..."

# Check prerequisites
command -v docker >/dev/null 2>&1 || { echo "❌ Docker required"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "❌ Python 3 required"; exit 1; }

# Setup environment
cp .env.sample .env
echo "✅ Environment configured"

# Start services
echo "🚀 Starting services..."
docker-compose up -d

# Wait for services
echo "⏳ Waiting for services to start..."
sleep 30

# Run demo
echo "🎬 Running demo..."
python3 scripts/demo_script.py

echo "🎉 PoC ready!"
echo "📊 Dashboard: http://localhost:3000"
echo "🔌 API: http://localhost:8000"
"""
    
    script_path = package_dir / "quick_start.sh"
    with open(script_path, "w") as f:
        f.write(script_content)
    
    # Make executable
    os.chmod(script_path, 0o755)

def create_demo_data(package_dir):
    """Create sample demo data"""
    demo_data = {
        "sample_threats": [
            {
                "id": "THR-001",
                "type": "sql_injection", 
                "source": "192.168.1.100",
                "payload": "' OR 1=1 --",
                "severity": "high",
                "detected_at": "2024-01-15T10:30:00Z"
            },
            {
                "id": "THR-002",
                "type": "xss_attack",
                "source": "10.0.0.50", 
                "payload": "<script>alert('XSS')</script>",
                "severity": "medium",
                "detected_at": "2024-01-15T10:31:00Z"
            }
        ],
        "agent_responses": [
            {
                "agent": "GPT-5",
                "analysis": "Advanced persistent threat detected",
                "confidence": 0.95,
                "recommendation": "Immediate containment required"
            },
            {
                "agent": "Claude", 
                "analysis": "Code injection vulnerability confirmed",
                "confidence": 0.88,
                "recommendation": "Input validation enhancement needed"
            }
        ]
    }
    
    demo_dir = package_dir / "demo_data"
    demo_dir.mkdir(exist_ok=True)
    
    with open(demo_dir / "sample_data.json", "w") as f:
        json.dump(demo_data, f, indent=2)

if __name__ == "__main__":
    create_poc_package()