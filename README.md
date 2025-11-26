# 🛡️ Infinite AI Security Platform

> Platform keamanan AI yang komprehensif dengan multi-agent system, security scanning, dan labyrinth defense mechanism.

## 🌟 Features

- 🤖 **Multi-Agent AI System** - Orchestrated AI agents untuk security analysis
- 🔍 **Security Scanner** - Code scanning dengan Go untuk performa tinggi
- 🌀 **Labyrinth Defense** - Dynamic defense mechanism dengan Rust
- 📊 **Real-time Dashboard** - React-based dashboard dengan visualisasi real-time
- 🔐 **Advanced Security** - JWT, encryption, rate limiting, dan RBAC
- 📈 **Monitoring** - Prometheus & Grafana integration
- 🚀 **Production Ready** - Docker, Kubernetes, dan CI/CD ready

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    React Dashboard                       │
│                  (TypeScript + Vite)                     │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│                   FastAPI Backend                        │
│                    (Python 3.11+)                        │
└──┬──────────────┬──────────────┬────────────────────────┘
   │              │              │
   ▼              ▼              ▼
┌──────┐    ┌──────────┐   ┌────────────┐
│ AI   │    │ Scanner  │   │ Labyrinth  │
│ Hub  │    │   (Go)   │   │  (Rust)    │
└──────┘    └──────────┘   └────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- Go 1.21+
- Rust 1.70+
- Docker & Docker Compose
- PostgreSQL 15+
- Redis 7+

### Installation

```bash
# Clone repository
git clone <repository-url>
cd infinite_ai_security

# Install dependencies
make install

# Setup environment
cp .env.example .env
# Edit .env dengan konfigurasi Anda

# Run database migrations
make migrate

# Seed database (optional)
make seed
```

### Development

```bash
# Start development environment
make dev

# Atau manual:
# Terminal 1 - API
cd apps/api
uvicorn src.main:app --reload

# Terminal 2 - Dashboard
cd apps/dashboard
npm run dev

# Terminal 3 - Scanner
cd packages/security-engine/scanner_go
go run cmd/scanner/main.go

# Terminal 4 - Labyrinth
cd packages/security-engine/labyrinth_rust
cargo run
```

### Production

```bash
# Build all services
make build

# Start production environment
make prod
```

## 📁 Project Structure

```
data/
├── apps/                    # Applications
│   ├── api/                # FastAPI backend
│   ├── dashboard/          # React frontend
│   └── web3/               # Web3 integration (optional)
├── packages/               # Shared packages
│   ├── ai-hub/            # AI orchestration
│   ├── security-engine/   # Security components
│   └── shared/            # Shared utilities
├── infrastructure/        # Infrastructure as Code
│   ├── docker/           # Docker configs
│   ├── kubernetes/       # K8s manifests
│   ├── terraform/        # Terraform configs
│   └── monitoring/       # Monitoring stack
├── scripts/              # Automation scripts
├── docs/                 # Documentation
└── tests/                # Integration tests
```

## 🧪 Testing

```bash
# Run all tests
make test

# Run specific tests
cd apps/api && pytest
cd apps/dashboard && npm test
cd packages/security-engine/scanner_go && go test ./...
cd packages/security-engine/labyrinth_rust && cargo test
```

## 📚 Documentation

- [Architecture Overview](docs/architecture/overview.md)
- [API Documentation](docs/api/endpoints.md)
- [Deployment Guide](docs/deployment/kubernetes-deployment.md)
- [Contributing Guide](CONTRIBUTING.md)

## 🔒 Security

Untuk melaporkan security vulnerabilities, silakan lihat [SECURITY.md](SECURITY.md).

## 📝 License

[MIT License](LICENSE)

## 👥 Contributors

- Your Name - Initial work

## 🙏 Acknowledgments

- FastAPI
- React
- Go
- Rust
- OpenAI
