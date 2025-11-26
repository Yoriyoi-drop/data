-- AI Multi-Service Security & Automation Platform
-- Database Schema v1.0

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- USERS & AUTHENTICATION
-- ============================================================================

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    is_active BOOLEAN DEFAULT true,
    is_superuser BOOLEAN DEFAULT false,
    email_verified BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);

-- ============================================================================
-- SUBSCRIPTIONS & BILLING
-- ============================================================================

CREATE TABLE subscriptions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    plan VARCHAR(50) NOT NULL, -- starter, professional, enterprise
    billing_cycle VARCHAR(20) NOT NULL, -- monthly, quarterly, yearly
    status VARCHAR(50) DEFAULT 'active', -- active, cancelled, expired, suspended
    region VARCHAR(50) NOT NULL, -- asia, europe, americas, africa, australia
    price_amount DECIMAL(10, 2) NOT NULL,
    currency VARCHAR(10) DEFAULT 'USD',
    stripe_subscription_id VARCHAR(255),
    stripe_customer_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    cancelled_at TIMESTAMP
);

CREATE INDEX idx_subscriptions_user_id ON subscriptions(user_id);
CREATE INDEX idx_subscriptions_status ON subscriptions(status);

-- ============================================================================
-- WORKFLOW EXECUTIONS
-- ============================================================================

CREATE TABLE workflow_executions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    workflow_name VARCHAR(255),
    status VARCHAR(50) DEFAULT 'pending', -- pending, running, completed, failed, cancelled
    nodes_executed INTEGER DEFAULT 0,
    total_nodes INTEGER DEFAULT 0,
    current_level INTEGER DEFAULT 0,
    total_levels INTEGER DEFAULT 0,
    input_data JSONB,
    output_data JSONB,
    error_message TEXT,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INTEGER
);

CREATE INDEX idx_workflow_executions_user_id ON workflow_executions(user_id);
CREATE INDEX idx_workflow_executions_status ON workflow_executions(status);
CREATE INDEX idx_workflow_executions_started_at ON workflow_executions(started_at DESC);

-- ============================================================================
-- AGENT ACTIVITIES
-- ============================================================================

CREATE TABLE agent_activities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workflow_execution_id UUID REFERENCES workflow_executions(id) ON DELETE CASCADE,
    agent_name VARCHAR(100) NOT NULL, -- team_a_analyzer, team_b_executor, team_c_recovery
    team VARCHAR(10) NOT NULL, -- A, B, C
    action VARCHAR(100) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    input_data JSONB,
    output_data JSONB,
    confidence_score DECIMAL(5, 4), -- 0.0000 to 1.0000
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    duration_ms INTEGER
);

CREATE INDEX idx_agent_activities_workflow_id ON agent_activities(workflow_execution_id);
CREATE INDEX idx_agent_activities_team ON agent_activities(team);
CREATE INDEX idx_agent_activities_status ON agent_activities(status);

-- ============================================================================
-- SECURITY SCANS
-- ============================================================================

CREATE TABLE security_scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    workflow_execution_id UUID REFERENCES workflow_executions(id) ON DELETE SET NULL,
    scan_type VARCHAR(50) NOT NULL, -- code, secret, dependency, vulnerability
    target VARCHAR(500) NOT NULL, -- file path, repository URL, etc
    status VARCHAR(50) DEFAULT 'pending',
    vulnerabilities_found INTEGER DEFAULT 0,
    severity_critical INTEGER DEFAULT 0,
    severity_high INTEGER DEFAULT 0,
    severity_medium INTEGER DEFAULT 0,
    severity_low INTEGER DEFAULT 0,
    scan_results JSONB,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INTEGER
);

CREATE INDEX idx_security_scans_user_id ON security_scans(user_id);
CREATE INDEX idx_security_scans_status ON security_scans(status);
CREATE INDEX idx_security_scans_started_at ON security_scans(started_at DESC);

-- ============================================================================
-- LABYRINTH DEFENSE LOGS
-- ============================================================================

CREATE TABLE labyrinth_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    request_id VARCHAR(255) UNIQUE NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    route_path VARCHAR(500),
    defense_level INTEGER DEFAULT 1,
    is_threat_detected BOOLEAN DEFAULT false,
    threat_type VARCHAR(100),
    action_taken VARCHAR(100), -- allowed, blocked, challenged
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_labyrinth_logs_user_id ON labyrinth_logs(user_id);
CREATE INDEX idx_labyrinth_logs_is_threat ON labyrinth_logs(is_threat_detected);
CREATE INDEX idx_labyrinth_logs_created_at ON labyrinth_logs(created_at DESC);

-- ============================================================================
-- USAGE TRACKING
-- ============================================================================

CREATE TABLE usage_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    subscription_id UUID REFERENCES subscriptions(id) ON DELETE SET NULL,
    resource_type VARCHAR(50) NOT NULL, -- workflow, scan, agent_call, api_request
    resource_id UUID,
    quantity INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_usage_logs_user_id ON usage_logs(user_id);
CREATE INDEX idx_usage_logs_subscription_id ON usage_logs(subscription_id);
CREATE INDEX idx_usage_logs_created_at ON usage_logs(created_at DESC);

-- ============================================================================
-- API KEYS
-- ============================================================================

CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    key_name VARCHAR(100) NOT NULL,
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    key_prefix VARCHAR(20) NOT NULL, -- First few chars for identification
    is_active BOOLEAN DEFAULT true,
    last_used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);

-- ============================================================================
-- AUDIT LOGS
-- ============================================================================

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    ip_address INET,
    user_agent TEXT,
    changes JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);

-- ============================================================================
-- TRIGGERS FOR UPDATED_AT
-- ============================================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_subscriptions_updated_at BEFORE UPDATE ON subscriptions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- INITIAL DATA (Optional)
-- ============================================================================

-- Create admin user (password: admin123)
INSERT INTO users (email, username, hashed_password, full_name, is_superuser, email_verified)
VALUES (
    'admin@aisecurity.com',
    'admin',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYzS8qub/jy', -- admin123
    'System Administrator',
    true,
    true
);

-- Create demo user (password: demo123)
INSERT INTO users (email, username, hashed_password, full_name, email_verified)
VALUES (
    'demo@aisecurity.com',
    'demo',
    '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', -- demo123
    'Demo User',
    true
);
