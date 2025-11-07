# 🛡️ Infinite AI Security Platform

Sistem keamanan AI terdistribusi dengan Infinite Labyrinth Defense dan kolaborasi multi-agent.

## 🚀 Quick Start

```bash
# Quick setup dan start (recommended)
python quick_start.py

# Manual setup
pip install -r requirements.txt
cd dashboard && npm install
cd ../security_engine/scanner_go && go mod tidy
cd ../labyrinth_rust && cargo build

# Start all components
python start_system.py

# Or start individually:
python api/main.py                              # API Server
cd dashboard && npm run dev                     # Dashboard  
cd security_engine/scanner_go && go run scanner.go    # Go Scanner
cd security_engine/labyrinth_rust && cargo run        # Rust Labyrinth

# Run demo
python run_demo.py
```

## 🏗️ Architecture

- **AI Hub**: Koordinasi semua AI agents
- **Security Engine**: Go scanner + Rust labyrinth + Python detector
- **Dashboard**: Real-time monitoring
- **API**: FastAPI backend
- **Web3**: Blockchain integration (optional)

## 📊 Components

| Component | Language | Purpose |
|-----------|----------|---------|
| AI Hub | Python | Agent orchestration |
| Security Engine | Go/Rust/Python | Multi-layer defense |
| API | Python (FastAPI) | REST endpoints |
| Dashboard | React/Node.js | Real-time UI |
| Web3 | Solidity/Rust | Blockchain integration |

## 🔧 Deployment

- Docker Compose: `docker-compose up`
- Kubernetes: `kubectl apply -f deployment/k8s/`