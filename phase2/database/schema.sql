-- Infinite Labyrinth Database Schema
-- PostgreSQL 14+ with advanced security features

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- Create schemas
CREATE SCHEMA IF NOT EXISTS ai_hub;
CREATE SCHEMA IF NOT EXISTS security;
CREATE SCHEMA IF NOT EXISTS asm;

-- Set search path
SET search_path = ai_hub, security, public;

-- ============================================================================
-- AI HUB SCHEMA
-- ============================================================================

-- Users table with RBAC
CREATE TABLE ai_hub.users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    role_name VARCHAR(50) NOT NULL,
    password_hash TEXT NOT NULL,
    disabled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret TEXT
);

-- Roles table
CREATE TABLE ai_hub.roles (
    role_name VARCHAR(50) PRIMARY KEY,
    description TEXT NOT NULL,
    permissions JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- AI Agents table
CREATE TABLE ai_hub.agents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    type VARCHAR(50) NOT NULL, -- 'gpt4', 'claude', 'grok', 'mistral', 'llama'
    endpoint TEXT,
    api_key_vault_path TEXT, -- Path in Vault for API key
    status VARCHAR(20) DEFAULT 'inactive', -- 'active', 'inactive', 'error'
    capabilities JSONB DEFAULT '[]',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_heartbeat TIMESTAMP WITH TIME ZONE
);

-- Tasks table with encrypted payloads
CREATE TABLE ai_hub.tasks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(200) NOT NULL,
    task_type VARCHAR(50) NOT NULL,
    priority INTEGER DEFAULT 5, -- 1=highest, 10=lowest
    assigned_agent UUID REFERENCES ai_hub.agents(id),
    status VARCHAR(20) DEFAULT 'pending', -- 'pending', 'running', 'completed', 'failed'
    payload_encrypted BYTEA, -- AES-256-GCM encrypted
    payload_key_id TEXT, -- Key ID in KMS
    result JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    started_at TIMESTAMP WITH TIME ZONE,
    finished_at TIMESTAMP WITH TIME ZONE,
    timeout_at TIMESTAMP WITH TIME ZONE
);

-- Playbooks for automated responses
CREATE TABLE ai_hub.playbooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    steps JSONB NOT NULL, -- Array of step definitions
    owner UUID REFERENCES ai_hub.users(id),
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Executed playbooks with HSM signatures
CREATE TABLE ai_hub.executed_playbooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    playbook_id UUID REFERENCES ai_hub.playbooks(id),
    executor_agent UUID REFERENCES ai_hub.agents(id),
    incident_id TEXT,
    parameters JSONB,
    result JSONB,
    signature TEXT, -- HSM-signed execution proof
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    execution_time_ms INTEGER
);

-- Real-time telemetry
CREATE TABLE ai_hub.telemetry (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    source VARCHAR(100) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    data JSONB NOT NULL,
    severity VARCHAR(20) DEFAULT 'info' -- 'debug', 'info', 'warn', 'error', 'critical'
);

-- ============================================================================
-- SECURITY SCHEMA
-- ============================================================================

-- Audit log with hash chaining
CREATE TABLE security.audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    actor VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(200),
    details JSONB,
    prev_hash TEXT,
    event_hash TEXT NOT NULL,
    signature TEXT -- HSM signature
);

-- Decoy objects (honeypots/honeytokens)
CREATE TABLE security.decoy_objects (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    object_type VARCHAR(50) NOT NULL, -- 'table', 'credential', 'file', 'api_key'
    location TEXT,
    seed_info JSONB,
    active BOOLEAN DEFAULT TRUE,
    access_count INTEGER DEFAULT 0,
    last_accessed TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Secrets metadata (actual secrets in Vault)
CREATE TABLE security.secrets_meta (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    vault_path TEXT NOT NULL,
    owner UUID REFERENCES ai_hub.users(id),
    secret_type VARCHAR(50), -- 'api_key', 'database', 'certificate'
    rotation_days INTEGER DEFAULT 30,
    last_rotated TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Database integrity snapshots
CREATE TABLE security.db_integrity_chain (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    snapshot_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    snapshot_location TEXT NOT NULL,
    snapshot_hash TEXT NOT NULL,
    prev_snapshot_hash TEXT,
    notes TEXT,
    verified BOOLEAN DEFAULT FALSE
);

-- ============================================================================
-- ASM SCHEMA (Phase 3)
-- ============================================================================

-- Assets under management
CREATE TABLE asm.assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    type VARCHAR(50) NOT NULL, -- 'ip', 'domain', 'api', 'server', 'container', 'database'
    value TEXT NOT NULL,
    owner VARCHAR(100),
    environment VARCHAR(50), -- 'production', 'staging', 'development'
    risk_score INTEGER DEFAULT 0, -- 0-100
    last_scanned TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Scan results
CREATE TABLE asm.scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID REFERENCES asm.assets(id),
    scan_type VARCHAR(50) NOT NULL, -- 'nmap', 'nuclei', 'subfinder'
    scanner_version VARCHAR(50),
    raw_output TEXT,
    processed_output JSONB,
    findings_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Vulnerabilities
CREATE TABLE asm.vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID REFERENCES asm.assets(id),
    cve_id VARCHAR(50),
    severity VARCHAR(20), -- 'low', 'medium', 'high', 'critical'
    title VARCHAR(200),
    description TEXT,
    cvss_score DECIMAL(3,1),
    exploitable BOOLEAN DEFAULT FALSE,
    metadata JSONB DEFAULT '{}',
    status VARCHAR(20) DEFAULT 'open', -- 'open', 'mitigated', 'false_positive'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Attack graph relationships
CREATE TABLE asm.attack_graph (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_asset UUID REFERENCES asm.assets(id),
    target_asset UUID REFERENCES asm.assets(id),
    attack_path JSONB, -- Array of attack steps
    risk_factor DECIMAL(3,2), -- 0.00-1.00
    exploitability_score INTEGER, -- 1-10
    impact_score INTEGER, -- 1-10
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- AI Hub indexes
CREATE INDEX idx_tasks_status ON ai_hub.tasks(status);
CREATE INDEX idx_tasks_priority ON ai_hub.tasks(priority);
CREATE INDEX idx_tasks_assigned_agent ON ai_hub.tasks(assigned_agent);
CREATE INDEX idx_telemetry_event_time ON ai_hub.telemetry(event_time);
CREATE INDEX idx_telemetry_source ON ai_hub.telemetry(source);

-- Security indexes
CREATE INDEX idx_audit_log_event_time ON security.audit_log(event_time);
CREATE INDEX idx_audit_log_actor ON security.audit_log(actor);
CREATE INDEX idx_decoy_objects_active ON security.decoy_objects(active);

-- ASM indexes
CREATE INDEX idx_assets_type ON asm.assets(type);
CREATE INDEX idx_assets_risk_score ON asm.assets(risk_score);
CREATE INDEX idx_vulnerabilities_severity ON asm.vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_status ON asm.vulnerabilities(status);

-- ============================================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================================

-- Enable RLS on sensitive tables
ALTER TABLE ai_hub.tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.secrets_meta ENABLE ROW LEVEL SECURITY;

-- RLS policies (examples)
CREATE POLICY task_owner_policy ON ai_hub.tasks
    FOR ALL TO app_user
    USING (assigned_agent IN (
        SELECT id FROM ai_hub.agents WHERE name = current_user
    ));

-- ============================================================================
-- FUNCTIONS AND TRIGGERS
-- ============================================================================

-- Function to update audit chain hash
CREATE OR REPLACE FUNCTION security.update_audit_hash()
RETURNS TRIGGER AS $$
DECLARE
    prev_hash_val TEXT;
BEGIN
    -- Get previous hash
    SELECT event_hash INTO prev_hash_val
    FROM security.audit_log
    ORDER BY event_time DESC
    LIMIT 1;
    
    -- Set previous hash
    NEW.prev_hash := COALESCE(prev_hash_val, 'genesis');
    
    -- Calculate new hash
    NEW.event_hash := encode(
        digest(
            NEW.event_time::TEXT || NEW.actor || NEW.action || 
            COALESCE(NEW.resource, '') || COALESCE(NEW.details::TEXT, '') || 
            NEW.prev_hash,
            'sha512'
        ),
        'hex'
    );
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for audit hash chaining
CREATE TRIGGER audit_hash_trigger
    BEFORE INSERT ON security.audit_log
    FOR EACH ROW
    EXECUTE FUNCTION security.update_audit_hash();

-- Function to detect decoy access
CREATE OR REPLACE FUNCTION security.decoy_accessed()
RETURNS TRIGGER AS $$
BEGIN
    -- Update access count
    UPDATE security.decoy_objects
    SET access_count = access_count + 1,
        last_accessed = NOW()
    WHERE name = TG_TABLE_NAME;
    
    -- Insert critical alert
    INSERT INTO ai_hub.telemetry (source, event_type, data, severity)
    VALUES (
        'decoy_system',
        'decoy_accessed',
        jsonb_build_object(
            'table', TG_TABLE_NAME,
            'operation', TG_OP,
            'timestamp', NOW()
        ),
        'critical'
    );
    
    RETURN NULL; -- Prevent actual operation
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- INITIAL DATA
-- ============================================================================

-- Insert default roles
INSERT INTO ai_hub.roles (role_name, description, permissions) VALUES
('admin', 'System Administrator', '["*"]'),
('agent_operator', 'AI Agent Operator', '["agents:read", "agents:write", "tasks:read", "tasks:write"]'),
('security_analyst', 'Security Analyst', '["audit:read", "decoy:read", "asm:read"]'),
('readonly', 'Read Only Access', '["*:read"]');

-- Insert system agents
INSERT INTO ai_hub.agents (name, type, capabilities) VALUES
('gpt4-security', 'gpt4', '["threat_analysis", "code_review", "incident_response"]'),
('claude-analyst', 'claude', '["vulnerability_assessment", "risk_analysis"]'),
('grok-scanner', 'grok', '["asset_discovery", "reconnaissance"]'),
('mistral-coordinator', 'mistral', '["multi_agent_coordination", "task_scheduling"]');

-- Insert default playbooks
INSERT INTO ai_hub.playbooks (name, description, steps) VALUES
('sql_injection_response', 'Automated SQL injection incident response', 
 '[{"step": "block_ip", "params": {"duration": "1h"}}, 
   {"step": "analyze_payload", "agent": "gpt4-security"}, 
   {"step": "update_waf_rules", "params": {"auto_approve": false}}]'),
('vulnerability_discovered', 'Response to new vulnerability discovery',
 '[{"step": "assess_impact", "agent": "claude-analyst"}, 
   {"step": "create_ticket", "params": {"priority": "high"}}, 
   {"step": "notify_team", "params": {"channel": "security"}}]');

-- Create decoy tables
CREATE TABLE security.fake_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50),
    password VARCHAR(100),
    email VARCHAR(100)
);

-- Add decoy trigger
CREATE TRIGGER fake_users_accessed
    BEFORE SELECT OR INSERT OR UPDATE OR DELETE ON security.fake_users
    FOR EACH STATEMENT
    EXECUTE FUNCTION security.decoy_accessed();

-- Register decoy object
INSERT INTO security.decoy_objects (name, object_type, location, seed_info) VALUES
('fake_users', 'table', 'security.fake_users', '{"purpose": "credential_honeypot"}');

-- ============================================================================
-- SECURITY HARDENING
-- ============================================================================

-- Revoke public access
REVOKE ALL ON SCHEMA ai_hub FROM PUBLIC;
REVOKE ALL ON SCHEMA security FROM PUBLIC;
REVOKE ALL ON SCHEMA asm FROM PUBLIC;

-- Create application roles
CREATE ROLE app_reader;
CREATE ROLE app_writer;
CREATE ROLE agent_executor;
CREATE ROLE audit_writer;
CREATE ROLE decoy_manager;

-- Grant appropriate permissions
GRANT USAGE ON SCHEMA ai_hub TO app_reader, app_writer, agent_executor;
GRANT SELECT ON ALL TABLES IN SCHEMA ai_hub TO app_reader;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA ai_hub TO app_writer;
GRANT ALL ON ALL TABLES IN SCHEMA ai_hub TO agent_executor;

GRANT USAGE ON SCHEMA security TO audit_writer, decoy_manager;
GRANT INSERT ON security.audit_log TO audit_writer;
GRANT ALL ON security.decoy_objects TO decoy_manager;

-- Enable logging
ALTER SYSTEM SET log_statement = 'all';
ALTER SYSTEM SET log_min_duration_statement = 1000;

-- Reload configuration
SELECT pg_reload_conf();