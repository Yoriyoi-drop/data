-- Multi-tenant + ASM schema + RLS (PostgreSQL)
-- Requires: pgcrypto or uuid-ossp for gen_random_uuid(), and appropriate current_setting('app.tenant_id')

CREATE SCHEMA IF NOT EXISTS ai_hub;
CREATE SCHEMA IF NOT EXISTS asm;

-- Tenants
CREATE TABLE IF NOT EXISTS ai_hub.tenants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  region TEXT NOT NULL,
  owner_id UUID,
  isolation_level TEXT DEFAULT 'schema',
  created_at timestamptz DEFAULT now()
);

-- Users (minimal stub for FK)
CREATE TABLE IF NOT EXISTS ai_hub.users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT UNIQUE NOT NULL,
  role TEXT DEFAULT 'user',
  created_at timestamptz DEFAULT now()
);

-- Tasks example table with tenant context
CREATE TABLE IF NOT EXISTS ai_hub.tasks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID REFERENCES ai_hub.tenants(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  status TEXT DEFAULT 'pending',
  meta JSONB,
  created_at timestamptz DEFAULT now()
);

-- ASM core tables
CREATE TABLE IF NOT EXISTS asm.assets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID REFERENCES ai_hub.tenants(id) ON DELETE CASCADE,
  type TEXT,
  value TEXT,
  owner TEXT,
  risk_score NUMERIC DEFAULT 0,
  meta JSONB,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS asm.scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id UUID REFERENCES asm.assets(id) ON DELETE CASCADE,
  scan_type TEXT,
  raw_output JSONB,
  processed_output JSONB,
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS asm.vulnerabilities (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id UUID REFERENCES asm.assets(id) ON DELETE CASCADE,
  cve_id TEXT,
  severity TEXT,
  description TEXT,
  metadata JSONB,
  discovered_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS asm.attack_graph (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID REFERENCES ai_hub.tenants(id) ON DELETE CASCADE,
  path JSONB,
  risk_factor NUMERIC,
  created_at timestamptz DEFAULT now()
);

-- Audit log with optional on-chain anchor flag
CREATE TABLE IF NOT EXISTS ai_hub.audit_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID REFERENCES ai_hub.tenants(id) ON DELETE CASCADE,
  actor UUID,
  action TEXT,
  details JSONB,
  event_hash TEXT,
  on_chain_anchor BOOLEAN DEFAULT FALSE,
  created_at timestamptz DEFAULT now()
);

-- Row Level Security
ALTER TABLE ai_hub.tasks ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_tasks ON ai_hub.tasks;
CREATE POLICY tenant_isolation_tasks ON ai_hub.tasks
  USING (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE asm.assets ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_assets ON asm.assets;
CREATE POLICY tenant_isolation_assets ON asm.assets
  USING (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE asm.attack_graph ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_attack_graph ON asm.attack_graph;
CREATE POLICY tenant_isolation_attack_graph ON asm.attack_graph
  USING (tenant_id = current_setting('app.tenant_id')::uuid);

ALTER TABLE ai_hub.audit_log ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_audit ON ai_hub.audit_log;
CREATE POLICY tenant_isolation_audit ON ai_hub.audit_log
  USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- Helper function stub: set tenant context
-- SELECT set_config('app.tenant_id', '<tenant-uuid>', false);
