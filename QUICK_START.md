# 🚀 QUICK START GUIDE - AI Multi-Service Platform

**Last Updated**: 2025-11-26  
**Status**: ✅ Fase 1 - Infrastructure Ready & Running

---

## ✅ WHAT'S WORKING NOW

### Infrastructure (Running on `aisec_v4`)
- ✅ **PostgreSQL** - Port 5436 (healthy)
- ✅ **Redis** - Port 6383 (healthy)
- ✅ **n8n** - Port 5681 (running)

### Services (Running)
- ✅ **API Gateway** - Port 8030 (healthy)
- ✅ **AI Hub** - Port 8031 (healthy)

---

## 🎯 HOW TO START

### Step 1: Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit .env and add your API keys
nano .env  # or use your favorite editor
```

### Step 2: Start Services

We use project name `aisec_v4` to avoid conflicts with stuck containers.

```bash
cd infrastructure/docker
docker-compose -p aisec_v4 up -d
```

### Step 3: Verify Services

```bash
# Check status
docker-compose -p aisec_v4 ps

# Test API Gateway
curl -L http://localhost:8030/api/v1/health/

# Test AI Hub
curl -L http://localhost:8031/
```

### Step 4: Access Interfaces

- **API Gateway Docs**: http://localhost:8030/docs
- **AI Hub Docs**: http://localhost:8031/docs
- **n8n Workflow**: http://localhost:5681

---

## 🐛 TROUBLESHOOTING

### Docker Permission Denied

If you see "permission denied" when stopping containers, simply use a new project name:

```bash
docker-compose -p aisec_v5 up -d
```

And update ports in `docker-compose.yml` if needed.

### Port Conflicts

If ports are taken, edit `docker-compose.yml` and change the host ports (left side):

```yaml
ports:
  - "8040:8000"  # Change 8030 to 8040
```

---

## 📚 DOCUMENTATION

- **IMPLEMENTATION_ROADMAP.md** - Development plan
- **PROJECT_STRUCTURE.md** - Folder structure
- **QUICK_REFERENCE.md** - Commands

---

**Ready for Phase 2!** 🚀
