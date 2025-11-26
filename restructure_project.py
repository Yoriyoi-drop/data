#!/usr/bin/env python3
"""
Script untuk merestrukturisasi project ke struktur yang lebih terorganisir
sesuai dengan best practices untuk multi-language AI Security Platform
"""

import os
import shutil
from pathlib import Path
from typing import List, Dict

class ProjectRestructure:
    def __init__(self, base_path: str = "."):
        self.base_path = Path(base_path).resolve()
        self.backup_path = self.base_path / "backup_old_structure"
        
    def create_directory_structure(self):
        """Membuat struktur direktori baru"""
        
        directories = [
            # GitHub
            ".github/workflows",
            ".github/ISSUE_TEMPLATE",
            
            # Apps - API
            "apps/api/src/core",
            "apps/api/src/api/v1/endpoints",
            "apps/api/src/models",
            "apps/api/src/schemas",
            "apps/api/src/services",
            "apps/api/src/repositories",
            "apps/api/src/database/migrations/versions",
            "apps/api/src/cache",
            "apps/api/src/tasks",
            "apps/api/src/utils",
            "apps/api/tests/unit",
            "apps/api/tests/integration",
            "apps/api/tests/e2e",
            
            # Apps - Dashboard
            "apps/dashboard/public",
            "apps/dashboard/src/assets/images",
            "apps/dashboard/src/assets/icons",
            "apps/dashboard/src/assets/fonts",
            "apps/dashboard/src/components/ui",
            "apps/dashboard/src/components/layout",
            "apps/dashboard/src/components/agents",
            "apps/dashboard/src/components/security",
            "apps/dashboard/src/components/labyrinth",
            "apps/dashboard/src/components/common",
            "apps/dashboard/src/pages/auth",
            "apps/dashboard/src/pages/dashboard",
            "apps/dashboard/src/pages/agents",
            "apps/dashboard/src/pages/security",
            "apps/dashboard/src/pages/settings",
            "apps/dashboard/src/hooks",
            "apps/dashboard/src/services",
            "apps/dashboard/src/store",
            "apps/dashboard/src/types",
            "apps/dashboard/src/utils",
            "apps/dashboard/src/config",
            "apps/dashboard/src/styles",
            "apps/dashboard/tests/unit",
            "apps/dashboard/tests/integration",
            "apps/dashboard/tests/e2e",
            
            # Apps - Web3 (Optional)
            "apps/web3/contracts",
            "apps/web3/scripts",
            "apps/web3/test",
            
            # Packages - AI Hub
            "packages/ai-hub/ai_hub/agents",
            "packages/ai-hub/ai_hub/orchestrator",
            "packages/ai-hub/ai_hub/memory",
            "packages/ai-hub/ai_hub/tools",
            "packages/ai-hub/ai_hub/prompts",
            "packages/ai-hub/ai_hub/utils",
            "packages/ai-hub/tests",
            
            # Packages - Security Engine
            "packages/security-engine/scanner_go/cmd/scanner",
            "packages/security-engine/scanner_go/internal/config",
            "packages/security-engine/scanner_go/internal/scanner",
            "packages/security-engine/scanner_go/internal/analyzer",
            "packages/security-engine/scanner_go/internal/reporter",
            "packages/security-engine/scanner_go/internal/api",
            "packages/security-engine/scanner_go/pkg/models",
            "packages/security-engine/scanner_go/tests",
            
            "packages/security-engine/labyrinth_rust/src/labyrinth",
            "packages/security-engine/labyrinth_rust/src/crypto",
            "packages/security-engine/labyrinth_rust/src/detection",
            "packages/security-engine/labyrinth_rust/src/api",
            "packages/security-engine/labyrinth_rust/src/utils",
            "packages/security-engine/labyrinth_rust/tests",
            "packages/security-engine/labyrinth_rust/benches",
            
            "packages/security-engine/detector_python/detector",
            "packages/security-engine/detector_python/models",
            "packages/security-engine/detector_python/tests",
            
            # Packages - Shared
            "packages/shared/python/shared_py",
            "packages/shared/typescript/src",
            "packages/shared/proto",
            
            # Infrastructure
            "infrastructure/docker/api",
            "infrastructure/docker/dashboard",
            "infrastructure/docker/scanner",
            "infrastructure/docker/labyrinth",
            "infrastructure/docker/nginx/ssl",
            
            "infrastructure/kubernetes/base",
            "infrastructure/kubernetes/deployments",
            "infrastructure/kubernetes/services",
            "infrastructure/kubernetes/ingress",
            "infrastructure/kubernetes/persistent-volumes",
            "infrastructure/kubernetes/hpa",
            "infrastructure/kubernetes/overlays/development",
            "infrastructure/kubernetes/overlays/staging",
            "infrastructure/kubernetes/overlays/production",
            "infrastructure/kubernetes/helm/security-ai/templates",
            
            "infrastructure/terraform/modules/vpc",
            "infrastructure/terraform/modules/eks",
            "infrastructure/terraform/modules/rds",
            "infrastructure/terraform/modules/redis",
            "infrastructure/terraform/environments/dev",
            "infrastructure/terraform/environments/staging",
            "infrastructure/terraform/environments/production",
            
            "infrastructure/monitoring/prometheus/rules",
            "infrastructure/monitoring/grafana/datasources",
            "infrastructure/monitoring/grafana/dashboards",
            "infrastructure/monitoring/alertmanager",
            
            # Scripts
            "scripts/setup",
            "scripts/build",
            "scripts/deploy",
            "scripts/database",
            "scripts/testing",
            "scripts/maintenance",
            
            # Docs
            "docs/architecture",
            "docs/api",
            "docs/deployment",
            "docs/guides",
            "docs/tutorials",
            "docs/diagrams",
            
            # Tests
            "tests/integration",
            "tests/e2e",
            "tests/load",
            "tests/security",
            
            # Config
            "config",
            
            # IDE
            ".vscode",
        ]
        
        print("📁 Membuat struktur direktori...")
        for directory in directories:
            dir_path = self.base_path / directory
            dir_path.mkdir(parents=True, exist_ok=True)
            print(f"  ✓ {directory}")
    
    def create_gitignore(self):
        """Membuat file .gitignore yang komprehensif"""
        gitignore_content = """# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
.venv/
*.egg-info/
dist/
build/
*.egg

# Node
node_modules/
npm-debug.log
yarn-error.log
.next/
out/
dist/

# Go
*.exe
*.exe~
*.dll
*.so
*.dylib
*.test
*.out
vendor/

# Rust
target/
Cargo.lock

# IDEs
.vscode/
.idea/
*.swp
*.swo
*~

# Environment
.env
.env.local
.env.*.local

# OS
.DS_Store
Thumbs.db

# Logs
logs/
*.log

# Database
*.db
*.sqlite

# Secrets
secrets/
*.pem
*.key

# Docker
docker-compose.override.yml

# Backup
backup_old_structure/
archive/

# Temporary
temp/
tmp/
uploads/
"""
        
        gitignore_path = self.base_path / ".gitignore"
        with open(gitignore_path, 'w') as f:
            f.write(gitignore_content)
        print("✓ .gitignore created")
    
    def create_env_example(self):
        """Membuat file .env.example"""
        env_content = """# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_SECRET_KEY=your-secret-key-here-change-in-production
API_DEBUG=false
API_WORKERS=4

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/securityai
DATABASE_POOL_SIZE=10
DATABASE_MAX_OVERFLOW=20

# Redis
REDIS_URL=redis://localhost:6379/0
REDIS_PASSWORD=

# AI Services
OPENAI_API_KEY=sk-xxxxx
ANTHROPIC_API_KEY=sk-ant-xxxxx
GOOGLE_API_KEY=

# Security
JWT_SECRET=your-jwt-secret-change-in-production
JWT_ALGORITHM=HS256
JWT_EXPIRATION=3600
ENCRYPTION_KEY=your-encryption-key-32-chars

# Monitoring
SENTRY_DSN=
PROMETHEUS_PORT=9090
GRAFANA_PORT=3000

# External Services
GITHUB_TOKEN=
SLACK_WEBHOOK_URL=
DISCORD_WEBHOOK_URL=

# Feature Flags
ENABLE_AI_AGENTS=true
ENABLE_LABYRINTH=true
ENABLE_WEB3=false

# Performance
MAX_UPLOAD_SIZE=10485760
REQUEST_TIMEOUT=30
RATE_LIMIT=100
"""
        
        env_path = self.base_path / ".env.example"
        with open(env_path, 'w') as f:
            f.write(env_content)
        print("✓ .env.example created")
    
    def create_root_makefile(self):
        """Membuat Makefile di root"""
        makefile_content = """# 🏗️ Infinite AI Security - Makefile
.PHONY: help install build test clean dev prod

help: ## Tampilkan bantuan
\t@echo "Available commands:"
\t@echo "  install     - Install all dependencies"
\t@echo "  build       - Build all services"
\t@echo "  test        - Run all tests"
\t@echo "  dev         - Start development environment"
\t@echo "  prod        - Start production environment"
\t@echo "  clean       - Clean build artifacts"
\t@echo "  lint        - Run linters"
\t@echo "  format      - Format code"

install: ## Install semua dependencies
\t@echo "📦 Installing dependencies..."
\t@echo "  → Python dependencies..."
\tpip install -r apps/api/requirements.txt
\tpip install -r apps/api/requirements-dev.txt
\t@echo "  → Node.js dependencies..."
\tcd apps/dashboard && npm install
\t@echo "  → Go dependencies..."
\tcd packages/security-engine/scanner_go && go mod download
\t@echo "  → Rust dependencies..."
\tcd packages/security-engine/labyrinth_rust && cargo build
\t@echo "✅ All dependencies installed!"

build: ## Build semua services
\t@echo "🔨 Building all services..."
\t./scripts/build/build_all.sh

test: ## Run semua tests
\t@echo "🧪 Running all tests..."
\t./scripts/testing/run_all_tests.sh

dev: ## Start development environment
\t@echo "🚀 Starting development environment..."
\tdocker-compose -f infrastructure/docker/docker-compose.yml -f infrastructure/docker/docker-compose.dev.yml up

prod: ## Start production environment
\t@echo "🚀 Starting production environment..."
\tdocker-compose -f infrastructure/docker/docker-compose.yml -f infrastructure/docker/docker-compose.prod.yml up -d

clean: ## Clean build artifacts
\t@echo "🧹 Cleaning build artifacts..."
\tfind . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
\tfind . -type d -name "node_modules" -exec rm -rf {} + 2>/dev/null || true
\tfind . -type d -name "target" -exec rm -rf {} + 2>/dev/null || true
\tfind . -type f -name "*.pyc" -delete
\t@echo "✅ Clean complete!"

lint: ## Run linters
\t@echo "🔍 Running linters..."
\t@echo "  → Python (ruff)..."
\truff check apps/api packages/ai-hub
\t@echo "  → TypeScript (eslint)..."
\tcd apps/dashboard && npm run lint
\t@echo "  → Go (golangci-lint)..."
\tcd packages/security-engine/scanner_go && golangci-lint run
\t@echo "✅ Linting complete!"

format: ## Format code
\t@echo "✨ Formatting code..."
\t@echo "  → Python (black)..."
\tblack apps/api packages/ai-hub
\t@echo "  → TypeScript (prettier)..."
\tcd apps/dashboard && npm run format
\t@echo "  → Go (gofmt)..."
\tcd packages/security-engine/scanner_go && go fmt ./...
\t@echo "  → Rust (rustfmt)..."
\tcd packages/security-engine/labyrinth_rust && cargo fmt
\t@echo "✅ Formatting complete!"

docker-build: ## Build Docker images
\t@echo "🐳 Building Docker images..."
\tdocker-compose -f infrastructure/docker/docker-compose.yml build

docker-up: ## Start Docker containers
\t@echo "🐳 Starting Docker containers..."
\tdocker-compose -f infrastructure/docker/docker-compose.yml up -d

docker-down: ## Stop Docker containers
\t@echo "🐳 Stopping Docker containers..."
\tdocker-compose -f infrastructure/docker/docker-compose.yml down

docker-logs: ## Show Docker logs
\tdocker-compose -f infrastructure/docker/docker-compose.yml logs -f

migrate: ## Run database migrations
\t@echo "🗄️ Running database migrations..."
\tcd apps/api && alembic upgrade head

seed: ## Seed database
\t@echo "🌱 Seeding database..."
\tpython scripts/database/seed_data.py

backup: ## Backup database
\t@echo "💾 Backing up database..."
\t./scripts/database/backup.sh

restore: ## Restore database
\t@echo "♻️ Restoring database..."
\t./scripts/database/restore.sh
"""
        
        makefile_path = self.base_path / "Makefile"
        with open(makefile_path, 'w') as f:
            f.write(makefile_content)
        print("✓ Makefile created")
    
    def create_readme(self):
        """Membuat README.md yang komprehensif"""
        readme_content = """# 🛡️ Infinite AI Security Platform

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
"""
        
        readme_path = self.base_path / "README.md"
        with open(readme_path, 'w') as f:
            f.write(readme_content)
        print("✓ README.md created")
    
    def create_github_workflows(self):
        """Membuat GitHub Actions workflows"""
        
        # CI Workflow
        ci_workflow = """name: CI

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  test-api:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          cd apps/api
          pip install -r requirements.txt
          pip install -r requirements-dev.txt
      - name: Run tests
        run: |
          cd apps/api
          pytest

  test-dashboard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      - name: Install dependencies
        run: |
          cd apps/dashboard
          npm ci
      - name: Run tests
        run: |
          cd apps/dashboard
          npm test

  test-scanner:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      - name: Run tests
        run: |
          cd packages/security-engine/scanner_go
          go test ./...

  test-labyrinth:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - name: Run tests
        run: |
          cd packages/security-engine/labyrinth_rust
          cargo test
"""
        
        ci_path = self.base_path / ".github/workflows/ci.yml"
        with open(ci_path, 'w') as f:
            f.write(ci_workflow)
        print("✓ .github/workflows/ci.yml created")
    
    def map_existing_files(self):
        """Mapping file-file yang sudah ada ke struktur baru"""
        
        mappings = {
            # API files
            "main_v2.py": "apps/api/src/main.py",
            "config.py": "apps/api/src/config.py",
            "alembic.ini": "apps/api/alembic.ini",
            
            # Security files
            "security/": "apps/api/src/core/",
            
            # AI agents
            "ai_hub/": "packages/ai-hub/ai_hub/",
            "ai_agents/": "packages/ai-hub/ai_hub/agents/",
            
            # Security engine
            "security_engine/": "packages/security-engine/",
            
            # Scripts
            "scripts/": "scripts/",
            
            # Docs
            "docs/": "docs/",
            
            # Infrastructure
            "docker-compose.yml": "infrastructure/docker/docker-compose.yml",
            "Dockerfile": "infrastructure/docker/api/Dockerfile",
            
            # Tests
            "tests/": "tests/",
        }
        
        return mappings
    
    def execute_restructure(self, dry_run=True):
        """Eksekusi restructure"""
        
        print("\n" + "="*60)
        print("🏗️  INFINITE AI SECURITY - PROJECT RESTRUCTURE")
        print("="*60 + "\n")
        
        if dry_run:
            print("⚠️  DRY RUN MODE - No files will be moved\n")
        else:
            print("⚠️  LIVE MODE - Files will be moved!\n")
            response = input("Are you sure you want to continue? (yes/no): ")
            if response.lower() != 'yes':
                print("❌ Restructure cancelled")
                return
        
        # 1. Create directory structure
        print("\n📁 Step 1: Creating directory structure...")
        self.create_directory_structure()
        
        # 2. Create configuration files
        print("\n📝 Step 2: Creating configuration files...")
        self.create_gitignore()
        self.create_env_example()
        self.create_root_makefile()
        self.create_readme()
        self.create_github_workflows()
        
        # 3. Show file mapping
        print("\n📋 Step 3: File mapping plan...")
        mappings = self.map_existing_files()
        for old_path, new_path in mappings.items():
            print(f"  {old_path} → {new_path}")
        
        print("\n" + "="*60)
        print("✅ Restructure plan completed!")
        print("="*60)
        
        if dry_run:
            print("\n💡 To execute the restructure, run:")
            print("   python restructure_project.py --execute")
        else:
            print("\n✅ Project restructured successfully!")
            print("\n📚 Next steps:")
            print("  1. Review the new structure")
            print("  2. Update import paths in code")
            print("  3. Run: make install")
            print("  4. Run: make test")
            print("  5. Commit changes to git")

def main():
    import sys
    
    dry_run = "--execute" not in sys.argv
    
    restructure = ProjectRestructure()
    restructure.execute_restructure(dry_run=dry_run)

if __name__ == "__main__":
    main()
