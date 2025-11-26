# 🚀 Quick Reference Guide

> Panduan cepat untuk navigasi dan penggunaan Infinite AI Security Platform

---

## 📚 Documentation Index

| Document | Purpose | When to Read |
|----------|---------|--------------|
| **README.md** | Project overview & quick start | First time setup |
| **PROJECT_STRUCTURE.md** | Complete folder structure | Understanding organization |
| **ROADMAP.md** | Implementation plan (6 phases) | Planning development |
| **CONTRIBUTING.md** | How to contribute | Before contributing |
| **SECURITY.md** | Security policy | Reporting vulnerabilities |
| **CODE_OF_CONDUCT.md** | Community guidelines | Joining community |
| **CHANGELOG.md** | Version history | Checking updates |
| **RESTRUCTURE_SUMMARY.md** | Restructure report | Understanding changes |

---

## ⚡ Quick Commands

### Development

```bash
# Install all dependencies
make install

# Start development environment
make dev

# Run all tests
make test

# Run linters
make lint

# Format code
make format
```

### Docker

```bash
# Build Docker images
make docker-build

# Start containers
make docker-up

# Stop containers
make docker-down

# View logs
make docker-logs
```

### Database

```bash
# Run migrations
make migrate

# Seed database
make seed

# Backup database
make backup

# Restore database
make restore
```

---

## 📁 Key Directories

### Applications

```
apps/api/          → FastAPI Backend
apps/dashboard/    → React Frontend
apps/web3/         → Blockchain (Optional)
```

### Packages

```
packages/ai-hub/              → AI Orchestration
packages/security-engine/     → Security Components
  ├── scanner_go/             → Go Scanner
  ├── labyrinth_rust/         → Rust Labyrinth
  └── detector_python/        → Python ML Detector
packages/shared/              → Shared Utilities
```

### Infrastructure

```
infrastructure/docker/        → Docker configs
infrastructure/kubernetes/    → K8s manifests
infrastructure/terraform/     → Terraform IaC
infrastructure/monitoring/    → Monitoring stack
```

### Scripts

```
scripts/setup/        → Setup scripts
scripts/build/        → Build scripts
scripts/deploy/       → Deployment scripts
scripts/database/     → Database scripts
scripts/testing/      → Test scripts
scripts/maintenance/  → Maintenance scripts
```

---

## 🔧 Common Tasks

### Starting a New Feature

```bash
# 1. Create branch
git checkout -b feature/your-feature

# 2. Make changes
# ... edit files ...

# 3. Test
make test
make lint

# 4. Commit
git add .
git commit -m "feat: add your feature"

# 5. Push
git push origin feature/your-feature

# 6. Create PR on GitHub
```

### Running API Locally

```bash
# Terminal 1 - Start API
cd apps/api
source ../.venv/bin/activate  # or your venv
uvicorn src.main:app --reload --port 8000

# Terminal 2 - Start Dashboard
cd apps/dashboard
npm run dev

# Terminal 3 - Start Redis (if needed)
docker run -p 6379:6379 redis:alpine

# Terminal 4 - Start PostgreSQL (if needed)
docker run -p 5432:5432 -e POSTGRES_PASSWORD=password postgres:15
```

### Running Tests

```bash
# All tests
make test

# API tests only
cd apps/api && pytest

# Dashboard tests only
cd apps/dashboard && npm test

# Go scanner tests
cd packages/security-engine/scanner_go && go test ./...

# Rust labyrinth tests
cd packages/security-engine/labyrinth_rust && cargo test
```

### Building for Production

```bash
# Build all services
make build

# Or individually:
cd apps/api && docker build -t api:latest .
cd apps/dashboard && npm run build
cd packages/security-engine/scanner_go && go build
cd packages/security-engine/labyrinth_rust && cargo build --release
```

---

## 🐛 Troubleshooting

### Common Issues

#### Import Errors After Restructure

**Problem**: `ModuleNotFoundError` or import errors

**Solution**:
```bash
# Update import paths
# Old: from security.logger import Logger
# New: from apps.api.src.core.logging import Logger

# Reinstall packages
pip install -e apps/api
```

#### Docker Build Fails

**Problem**: Docker build errors

**Solution**:
```bash
# Clear Docker cache
docker system prune -a

# Rebuild without cache
docker-compose build --no-cache
```

#### Database Connection Issues

**Problem**: Can't connect to database

**Solution**:
```bash
# Check .env file
cat .env | grep DATABASE_URL

# Test connection
psql $DATABASE_URL

# Reset database
make migrate
```

#### Port Already in Use

**Problem**: `Address already in use`

**Solution**:
```bash
# Find process using port
lsof -i :8000

# Kill process
kill -9 <PID>

# Or use different port
uvicorn src.main:app --port 8001
```

---

## 📊 Project Structure Quick View

```
data/
├── apps/                    # Applications
│   ├── api/                # Backend (Python/FastAPI)
│   ├── dashboard/          # Frontend (React/TypeScript)
│   └── web3/               # Blockchain (Optional)
│
├── packages/               # Shared Packages
│   ├── ai-hub/            # AI Orchestration
│   ├── security-engine/   # Security Components
│   └── shared/            # Shared Utilities
│
├── infrastructure/        # DevOps
│   ├── docker/           # Containers
│   ├── kubernetes/       # K8s
│   ├── terraform/        # IaC
│   └── monitoring/       # Observability
│
├── scripts/              # Automation
├── docs/                 # Documentation
├── tests/                # Integration Tests
└── config/               # Configuration
```

---

## 🎯 Phase Progress

| Phase | Status | Progress |
|-------|--------|----------|
| Phase 1: Core Structure | ✅ Complete | 100% |
| Phase 2: API & Database | 🔄 Next | 0% |
| Phase 3: Frontend | ⏳ Pending | 0% |
| Phase 4: Security Engine | ⏳ Pending | 0% |
| Phase 5: DevOps | ⏳ Pending | 0% |
| Phase 6: Documentation | ⏳ Pending | 0% |

---

## 🔗 Important Links

### Documentation
- [Architecture Overview](docs/architecture/overview.md)
- [API Documentation](docs/api/endpoints.md)
- [Deployment Guide](docs/deployment/kubernetes-deployment.md)

### External Resources
- [FastAPI Docs](https://fastapi.tiangolo.com/)
- [React Docs](https://react.dev/)
- [Go Docs](https://go.dev/doc/)
- [Rust Docs](https://doc.rust-lang.org/)

---

## 💡 Tips & Best Practices

### Code Quality

✅ **DO**:
- Write tests for new features
- Follow coding standards
- Document complex logic
- Use type hints (Python) / types (TypeScript)
- Keep functions small and focused

❌ **DON'T**:
- Commit directly to main
- Skip tests
- Hardcode secrets
- Ignore linter warnings
- Write unclear commit messages

### Git Workflow

```bash
# Good commit messages
git commit -m "feat: add user authentication"
git commit -m "fix: resolve memory leak in agent list"
git commit -m "docs: update API documentation"

# Bad commit messages
git commit -m "update"
git commit -m "fix bug"
git commit -m "changes"
```

### Security

- Never commit `.env` files
- Use environment variables for secrets
- Keep dependencies updated
- Run security scans regularly
- Follow principle of least privilege

---

## 📞 Getting Help

### Documentation
1. Check this Quick Reference
2. Read relevant docs in `docs/`
3. Check ROADMAP.md for plans
4. Review CONTRIBUTING.md

### Community
- 💬 Discord: https://discord.gg/example
- 📧 Email: support@example.com
- 🐛 Issues: GitHub Issues
- 💡 Discussions: GitHub Discussions

### Reporting Issues

```markdown
**Bug Report Template**

**Description**: Clear description of the issue

**Steps to Reproduce**:
1. Step 1
2. Step 2
3. Step 3

**Expected Behavior**: What should happen

**Actual Behavior**: What actually happens

**Environment**:
- OS: Linux/Mac/Windows
- Python: 3.11
- Node: 18.x
- Docker: 24.x

**Screenshots**: If applicable
```

---

## 🎓 Learning Path

### For New Contributors

1. **Week 1**: Setup & Familiarization
   - Setup development environment
   - Read documentation
   - Explore codebase
   - Run project locally

2. **Week 2**: First Contribution
   - Pick a "good first issue"
   - Make changes
   - Write tests
   - Submit PR

3. **Week 3+**: Regular Contributions
   - Take on bigger features
   - Help review PRs
   - Improve documentation
   - Mentor newcomers

### For Developers

1. **Backend** (Python/FastAPI)
   - Learn FastAPI framework
   - Understand SQLAlchemy ORM
   - Study authentication flow
   - Explore background tasks

2. **Frontend** (React/TypeScript)
   - Learn React hooks
   - Understand state management
   - Study component patterns
   - Explore real-time updates

3. **Security** (Go/Rust/Python)
   - Learn security scanning
   - Understand threat detection
   - Study ML models
   - Explore defense mechanisms

---

## ✅ Checklist for New Setup

```bash
# 1. Clone repository
[ ] git clone <repo-url>
[ ] cd infinite_ai_security

# 2. Install dependencies
[ ] make install

# 3. Setup environment
[ ] cp .env.example .env
[ ] Edit .env with your configs

# 4. Setup database
[ ] Start PostgreSQL
[ ] make migrate
[ ] make seed (optional)

# 5. Start services
[ ] make dev

# 6. Verify
[ ] Open http://localhost:8000/docs (API)
[ ] Open http://localhost:5173 (Dashboard)
[ ] Run make test

# 7. Start developing!
[ ] Create feature branch
[ ] Make changes
[ ] Write tests
[ ] Submit PR
```

---

## 🎉 You're Ready!

Sekarang Anda siap untuk mulai mengembangkan Infinite AI Security Platform!

**Next Steps**:
1. ✅ Review this guide
2. ✅ Setup development environment
3. ✅ Read ROADMAP.md for Phase 2
4. ✅ Start coding!

**Happy Coding!** 🚀

---

**Last Updated**: 2025-11-26  
**Version**: 1.0
