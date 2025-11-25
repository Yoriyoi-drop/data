# 🚀 QUICK START - Infinite AI Security V2.0

**Setelah Security Fixes**  
**Updated:** 25 November 2025

---

## ⚡ QUICK START (5 Menit)

### 1. Generate Secrets (WAJIB)
```bash
cd /home/whale-d/Unduhan/backup/ai-p/infinite_ai_security
python scripts/generate_secrets.py
```

Ikuti instruksi untuk membuat `.env` file dengan secrets yang aman.

### 2. Install Dependencies
```bash
# Core dependencies (sudah ada)
pip install -r requirements.txt

# Additional untuk security fixes
pip install email-validator

# RECOMMENDED: Redis untuk distributed rate limiting
pip install redis
```

### 3. Setup Redis (Optional tapi Recommended)
```bash
# Ubuntu/Debian:
sudo apt-get update
sudo apt-get install redis-server
sudo systemctl start redis
sudo systemctl enable redis

# Verify Redis running:
redis-cli ping
# Should return: PONG
```

### 4. Verify .env File
```bash
# Check .env exists dan tidak di-commit
ls -la .env
git status .env  # Should be in .gitignore

# Verify secrets are set
grep "JWT_SECRET_KEY" .env
grep "SESSION_SECRET" .env
```

### 5. Run Application
```bash
python main_v2.py
```

Expected output:
```
✅ Connected to Redis for distributed rate limiting
INFINITE AI SECURITY PLATFORM V2.0
============================================================
Enhanced Authentication: Active
Advanced Input Validation: Active
Enhanced Rate Limiting: Active
Security Headers: Active
Session Management: Enhanced
============================================================
```

---

## 🔧 CONFIGURATION

### Environment Variables (.env)

**Required:**
```bash
JWT_SECRET_KEY=<generated_secret>
JWT_REFRESH_SECRET=<generated_secret>
SESSION_SECRET=<generated_secret>
API_SECRET_KEY=<generated_secret>
```

**Database:**
```bash
DB_BACKEND=postgres  # or sqlite
PG_HOST=127.0.0.1
PG_PORT=5432
PG_USER=postgres
PG_PASSWORD=<your_password>
PG_DATABASE=infinite_ai
```

**Redis (Recommended):**
```bash
REDIS_URL=redis://localhost:6379/0
REDIS_PASSWORD=  # if required
```

**Security:**
```bash
ENVIRONMENT=development  # or production
SESSION_HTTPS_ONLY=false  # true in production
ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
```

---

## 🧪 TESTING

### 1. Test Health Endpoint
```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "healthy",
  "version": "2.0.0",
  "enhanced_security": true,
  "rate_limiting": "enabled"
}
```

### 2. Test CSRF Token
```bash
# Get CSRF token
curl http://localhost:8000/auth/csrf-token

# Response:
{
  "csrf_token": "...",
  "expires_in": 300,
  "message": "..."
}
```

### 3. Test Login (with CSRF)
```bash
# First get CSRF token, then:
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "<your_password>",
    "csrf_token": "<csrf_token_from_step_2>"
  }'
```

### 4. Test WebSocket (New Method)
```javascript
const ws = new WebSocket('ws://localhost:8000/ws');

ws.onopen = () => {
    // Send auth message
    ws.send(JSON.stringify({
        type: 'auth',
        token: 'your_jwt_token_here'
    }));
};

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log('Received:', data);
    
    if (data.type === 'auth_success') {
        console.log('✅ Authenticated!');
        // Now you can send messages
        ws.send('Hello, secure WebSocket!');
    }
};
```

---

## 📋 CHECKLIST SEBELUM PRODUCTION

### Security:
- [ ] Semua secrets di-generate dengan `generate_secrets.py`
- [ ] `.env` file TIDAK di-commit ke git
- [ ] `ENVIRONMENT=production` di `.env`
- [ ] `SESSION_HTTPS_ONLY=true` di `.env`
- [ ] HTTPS enabled dengan valid SSL certificate
- [ ] Redis running dan configured
- [ ] Database credentials strong dan rotated

### Application:
- [ ] All dependencies installed
- [ ] Database migrations run
- [ ] Admin user created
- [ ] WebSocket clients updated
- [ ] Rate limiting tested
- [ ] CSRF protection tested
- [ ] Session management tested

### Monitoring:
- [ ] Logging configured
- [ ] Monitoring setup (Prometheus, etc.)
- [ ] Alerting configured
- [ ] Backup system tested

---

## 🚨 TROUBLESHOOTING

### "Redis connection failed"
```bash
# Check if Redis is running
sudo systemctl status redis

# Start Redis
sudo systemctl start redis

# Or use in-memory fallback (not recommended for production)
# Application will automatically fallback if Redis unavailable
```

### "CSRF token expired"
```bash
# Token expires in 5 minutes
# Frontend must request new token from /auth/csrf-token
```

### "Session invalid"
```bash
# This happens if:
# 1. Session fingerprint mismatch (possible session hijacking)
# 2. Session expired
# Solution: Login again
```

### "WebSocket authentication failed"
```bash
# Make sure you're using NEW method:
# 1. Connect to ws://localhost:8000/ws (NO token in URL)
# 2. Send auth message: {type: 'auth', token: '...'}
# 3. Wait for auth_success response
```

### "Validation error"
```bash
# Pydantic validation is strict
# Check:
# - Password meets complexity requirements (12+ chars, uppercase, lowercase, digit, special)
# - Username format (alphanumeric, dots, hyphens, underscores only)
# - Input lengths within limits
```

---

## 📚 DOCUMENTATION

### Main Docs:
- `LAPORAN_AUDIT_KEAMANAN.md` - Full security audit
- `CRITICAL_FIXES_COMPLETE.md` - All fixes summary
- `SECURITY_FIX_PROGRESS.md` - Progress tracking

### Specific Guides:
- `docs/WEBSOCKET_CLIENT_GUIDE.md` - WebSocket client migration
- `.env.example` - Environment variables template

### API Docs:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

---

## 🆘 SUPPORT

### Issues:
1. Check troubleshooting section above
2. Review security logs: `logs/security.log`
3. Check application logs
4. Review documentation

### Security Issues:
- Email: security@yourdomain.com
- Report vulnerabilities responsibly

---

## 🎯 NEXT STEPS

### After Quick Start:
1. ✅ Review `CRITICAL_FIXES_COMPLETE.md`
2. ✅ Update WebSocket clients (if any)
3. ✅ Test all endpoints
4. ✅ Setup monitoring
5. ✅ Plan for HIGH priority fixes

### Production Deployment:
1. ✅ Complete pre-production checklist
2. ✅ Security audit by third-party
3. ✅ Load testing
4. ✅ Disaster recovery testing
5. ✅ Incident response plan

---

**Last Updated:** 2025-11-25 19:35 WIB  
**Version:** 2.0.0  
**Security Level:** ENHANCED ✅
