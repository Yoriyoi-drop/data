# Infinite AI Security Platform V2.0 — Dokumentasi Lengkap

## Ringkasan
- **Tujuan**: Platform keamanan dengan autentikasi ditingkatkan, validasi input, rate limiting, dan deteksi ancaman.
- **Runtime DB**: PostgreSQL (driver `pg8000`). Opsi mirror audit ke MongoDB.
- **Aplikasi**: FastAPI + Uvicorn.
- **Mode jalan**: Containerized (Docker Compose) atau lokal (Python host).

## Struktur Proyek Penting
- `main_v2.py`
- `config/settings.py`
- `requirements.txt`
- `requirements_production.txt`
- `deployment/docker-compose.db.yml`
- `sql/00_schema_setup.sql`
- `docs/dokumentasi_lengkap.md`

## Prasyarat
- Docker Desktop (disarankan untuk cepat jalan end-to-end).
- Alternatif lokal (host): Python 3.11+ (atau 3.14 dengan penyesuaian), Postgres, MongoDB.

## Environment Variables
- Postgres (wajib):
  - `DB_BACKEND=postgres`
  - `PG_HOST`, `PG_PORT`, `PG_USER`, `PG_PASSWORD`, `PG_DATABASE`
- Mongo (opsional, untuk audit mirror):
  - `MONGO_URI`, `MONGO_DB`
- Lainnya (opsional): lihat `config/settings.py` dan `.env.example`.

## Menjalankan via Docker Compose (Direkomendasikan)
1. Jalankan stack:
   ```bash
   docker compose -f infinite_ai_security/deployment/docker-compose.db.yml up -d
   docker ps
   ```
2. Layanan:
   - App (API): `http://localhost:8000`
   - PGAdmin: `http://localhost:5050` (EMAIL: `admin@local`, PASS: `admin123` — bisa diubah di compose)
   - Mongo Express: `http://localhost:8081`
3. Terapkan skema Postgres:
   - Melalui PGAdmin (Query Tool) jalankan `sql/00_schema_setup.sql`
   - Atau:
     ```bash
     docker cp infinite_ai_security/sql/00_schema_setup.sql infinite-ai-postgres:/tmp/00_schema_setup.sql
     docker exec infinite-ai-postgres psql -U postgres -d infinite_ai -f /tmp/00_schema_setup.sql
     ```

## Menjalankan Secara Lokal (Tanpa Docker)
1. Pastikan Postgres aktif dan env diset.
2. Python dan deps:
   ```bash
   python -m pip install --upgrade pip
   pip install -r infinite_ai_security/requirements.txt
   ```
3. Jalankan aplikasi:
   ```bash
   python infinite_ai_security/main_v2.py
   ```
4. Terapkan skema Postgres via psql/PGAdmin: `sql/00_schema_setup.sql`.

Catatan Python 3.14:
- Beberapa paket belum memiliki wheel 3.14. Solusi yang dipakai: gunakan `pg8000` (pure-Python) dan hilangkan `aiohttp` yang tidak digunakan. Alternatif: install MSVC + Rust agar build native berhasil.

## Skema Database & RLS
- File: `sql/00_schema_setup.sql`
- Schema: `ai_hub` dan `asm`.
- Tabel inti:
  - `ai_hub.tenants`, `ai_hub.users`, `ai_hub.tasks`, `ai_hub.audit_log`
  - `asm.assets`, `asm.scans`, `asm.vulnerabilities`, `asm.attack_graph`
- RLS diaktifkan untuk:
  - `ai_hub.tasks`, `asm.assets`, `asm.attack_graph`, `ai_hub.audit_log`
- Set tenant context per request:
  ```sql
  SELECT set_config('app.tenant_id', '<TENANT-UUID>', false);
  ```

## Konfigurasi Koneksi DB
- `main_v2.py` menggunakan kelas `PostgresEnhancedDatabase` dengan driver `pg8000`.
- Env yang dipakai: `PG_HOST`, `PG_PORT`, `PG_USER`, `PG_PASSWORD`, `PG_DATABASE`.
- Opsional: mirror log ke Mongo jika `MONGO_URI` diset.

## Endpoint Utama
- `GET /health` — status sistem.
- `GET /dashboard` — dashboard HTML sederhana.
- `POST /auth/login` — login user; admin default dibuat otomatis (`admin`/`admin123`).
- `POST /api/analyze` — analisis ancaman (butuh Bearer token).
- `POST /api/test-attack` — simulasi serangan (butuh Bearer token).
- `GET /api/security-status` — ringkasan status keamanan (butuh Bearer token).
- `WS /ws` — kanal WebSocket untuk notifikasi.

## Contoh Uji Cepat
- Health:
  ```bash
  curl.exe http://localhost:8000/health
  ```
- Login admin:
  ```bash
  curl.exe -X POST http://localhost:8000/auth/login ^
    -H "Content-Type: application/json" ^
    -d "{\"username\":\"admin\",\"password\":\"admin123\"}"
  ```
- Analyze (butuh token):
  ```bash
  TOKEN="<ACCESS_TOKEN>"
  curl.exe -X POST http://localhost:8000/api/analyze ^
    -H "Authorization: Bearer %TOKEN%" ^
    -H "Content-Type: application/json" ^
    -d "{\"input\":\"<script>alert('xss')</script>\",\"context\":\"general\"}"
  ```

## Keamanan
- Middleware header keamanan diaktifkan.
- Rate limiting diferensiasi endpoint (login vs api vs general).
- Autentikasi enhanced (JWT), MFA (opsional jika modul tersedia), validasi input.

## Observability & Ops
- Prometheus client tersedia (`/metrics` dapat ditambahkan bila diperlukan).
- File monitoring & dashboards contoh tersedia (jika disertakan di repo Anda).
- Artefak infra/ops (GitOps, Terraform, K8s) disediakan sebagai baseline — sesuaikan secrets/URL/region.

## Troubleshooting
- **Docker tidak ditemukan**: install Docker Desktop dan ulang `docker compose up -d`.
- **PGAdmin restarting**: cek `docker logs infinite-ai-pgadmin`, pastikan env `PGADMIN_DEFAULT_EMAIL/PASSWORD` benar.
- **Tidak bisa konek DB**: verifikasi env PG_*, port 5432 tidak diblok, dan database `infinite_ai` ada.
- **Error RLS/tenant**: pastikan `set_config('app.tenant_id', ...)` diset sebelum query yang terproteksi RLS.
- **Python 3.14 error build**: gunakan container (Python 3.11) atau pasang MSVC + Rust.

## Roadmap Opsional
- Middleware untuk set `app.tenant_id` dari header/claim token per request.
- Alembic migrations untuk versioning skema DB.
- Seed `ai_hub.tenants` dan binding user-tenant.
- Observability full (Prometheus/Alertmanager/Grafana) dan alert rules.
- GitOps (ArgoCD) & Terraform provisioning per environment.

## Lisensi & Catatan
- Gunakan kredensial kuat di produksi (JWT secret, DB password) dan rotasi berkala.
- Jangan commit isi `.env.production` ke VCS.
