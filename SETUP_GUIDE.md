# 🛡️ Infinite AI Security Platform - Setup Guide

## Prerequisites

Pastikan tools berikut sudah terinstall:

- **Python 3.8+** - untuk API dan AI agents
- **Node.js 16+** - untuk dashboard React
- **Go 1.19+** - untuk security scanner
- **Rust 1.70+** - untuk infinite labyrinth

## Quick Setup (Recommended)

```bash
# Clone dan masuk ke directory
cd infinite_ai_security

# Setup otomatis dan start sistem
python quick_start.py
```

## Manual Setup

### 1. Python Dependencies
```bash
pip install -r requirements.txt
```

### 2. Node.js Dependencies  
```bash
cd dashboard
npm install
cd ..
```

### 3. Go Dependencies
```bash
cd security_engine/scanner_go
go mod tidy
cd ../..
```

### 4. Rust Dependencies
```bash
cd security_engine/labyrinth_rust
cargo build
cd ../..
```

## Running the System

### Option 1: Start All Components
```bash
python start_system.py
```

### Option 2: Start Individually

**Terminal 1 - API Server:**
```bash
python api/main.py
```

**Terminal 2 - Dashboard:**
```bash
cd dashboard
npm run dev
```

**Terminal 3 - Go Scanner:**
```bash
cd security_engine/scanner_go
go run scanner.go
```

**Terminal 4 - Rust Labyrinth:**
```bash
cd security_engine/labyrinth_rust
cargo run
```

## Testing

### System Test
```bash
python test_system.py
```

### Demo dengan Data Simulasi
```bash
python run_demo.py
```

## Access Points

- **Dashboard**: http://localhost:5173
- **API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Go Scanner**: http://localhost:8080
- **Metrics**: http://localhost:8000/metrics

## Troubleshooting

### Port Conflicts
Jika ada konflik port, edit file berikut:
- API: `api/main.py` (line terakhir)
- Dashboard: `dashboard/vite.config.js`
- Go Scanner: `security_engine/scanner_go/scanner.go`

### Dependencies Issues
```bash
# Update Python packages
pip install --upgrade -r requirements.txt

# Update Node packages
cd dashboard && npm update

# Update Go modules
cd security_engine/scanner_go && go mod tidy

# Rebuild Rust
cd security_engine/labyrinth_rust && cargo clean && cargo build
```

### Common Errors

**"Module not found"**
```bash
# Pastikan di root directory
pwd
# Should show: .../infinite_ai_security

# Install ulang dependencies
python quick_start.py
```

**"Port already in use"**
```bash
# Windows
netstat -ano | findstr :8000
taskkill /PID <PID> /F

# Linux/Mac  
lsof -ti:8000 | xargs kill -9
```

## Development Mode

Untuk development, jalankan dengan auto-reload:

```bash
# API dengan auto-reload
cd api && uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Dashboard dengan hot-reload
cd dashboard && npm run dev
```

## Production Deployment

Lihat `deployment/` folder untuk:
- Docker Compose setup
- Kubernetes manifests
- Nginx configuration

```bash
# Docker deployment
docker-compose up -d

# Kubernetes deployment  
kubectl apply -f deployment/k8s/
```