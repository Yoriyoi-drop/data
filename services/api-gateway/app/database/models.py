"""
Database models for AI Multi-Service Security Platform
"""
from datetime import datetime
from typing import Optional
from sqlalchemy import Boolean, Column, DateTime, String, Integer, Numeric, Text, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB
from sqlalchemy.orm import relationship
import uuid

from .session import Base


class User(Base):
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    email_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    subscriptions = relationship("Subscription", back_populates="user", cascade="all, delete-orphan")
    workflow_executions = relationship("WorkflowExecution", back_populates="user", cascade="all, delete-orphan")
    security_scans = relationship("SecurityScan", back_populates="user", cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    usage_logs = relationship("UsageLog", back_populates="user", cascade="all, delete-orphan")


class Subscription(Base):
    __tablename__ = "subscriptions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    plan = Column(String(50), nullable=False)  # starter, professional, enterprise
    billing_cycle = Column(String(20), nullable=False)  # monthly, quarterly, yearly
    status = Column(String(50), default="active", index=True)
    region = Column(String(50), nullable=False)
    price_amount = Column(Numeric(10, 2), nullable=False)
    currency = Column(String(10), default="USD")
    stripe_subscription_id = Column(String(255))
    stripe_customer_id = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    cancelled_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="subscriptions")
    usage_logs = relationship("UsageLog", back_populates="subscription")


class WorkflowExecution(Base):
    __tablename__ = "workflow_executions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    workflow_name = Column(String(255))
    status = Column(String(50), default="pending", index=True)
    nodes_executed = Column(Integer, default=0)
    total_nodes = Column(Integer, default=0)
    current_level = Column(Integer, default=0)
    total_levels = Column(Integer, default=0)
    input_data = Column(JSONB)
    output_data = Column(JSONB)
    error_message = Column(Text)
    started_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer)
    
    # Relationships
    user = relationship("User", back_populates="workflow_executions")
    agent_activities = relationship("AgentActivity", back_populates="workflow_execution", cascade="all, delete-orphan")
    security_scans = relationship("SecurityScan", back_populates="workflow_execution")


class AgentActivity(Base):
    __tablename__ = "agent_activities"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workflow_execution_id = Column(UUID(as_uuid=True), ForeignKey("workflow_executions.id", ondelete="CASCADE"), nullable=False)
    agent_name = Column(String(100), nullable=False)
    team = Column(String(10), nullable=False, index=True)  # A, B, C
    action = Column(String(100), nullable=False)
    status = Column(String(50), default="pending", index=True)
    input_data = Column(JSONB)
    output_data = Column(JSONB)
    confidence_score = Column(Numeric(5, 4))  # 0.0000 to 1.0000
    error_message = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    duration_ms = Column(Integer)
    
    # Relationships
    workflow_execution = relationship("WorkflowExecution", back_populates="agent_activities")


class SecurityScan(Base):
    __tablename__ = "security_scans"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    workflow_execution_id = Column(UUID(as_uuid=True), ForeignKey("workflow_executions.id", ondelete="SET NULL"), nullable=True)
    scan_type = Column(String(50), nullable=False)  # code, secret, dependency, vulnerability
    target = Column(String(500), nullable=False)
    status = Column(String(50), default="pending", index=True)
    vulnerabilities_found = Column(Integer, default=0)
    severity_critical = Column(Integer, default=0)
    severity_high = Column(Integer, default=0)
    severity_medium = Column(Integer, default=0)
    severity_low = Column(Integer, default=0)
    scan_results = Column(JSONB)
    started_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer)
    
    # Relationships
    user = relationship("User", back_populates="security_scans")
    workflow_execution = relationship("WorkflowExecution", back_populates="security_scans")


class LabyrinthLog(Base):
    __tablename__ = "labyrinth_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    request_id = Column(String(255), unique=True, nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    route_path = Column(String(500))
    defense_level = Column(Integer, default=1)
    is_threat_detected = Column(Boolean, default=False, index=True)
    threat_type = Column(String(100))
    action_taken = Column(String(100))  # allowed, blocked, challenged
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class UsageLog(Base):
    __tablename__ = "usage_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    subscription_id = Column(UUID(as_uuid=True), ForeignKey("subscriptions.id", ondelete="SET NULL"), nullable=True)
    resource_type = Column(String(50), nullable=False)  # workflow, scan, agent_call, api_request
    resource_id = Column(UUID(as_uuid=True))
    quantity = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    user = relationship("User", back_populates="usage_logs")
    subscription = relationship("Subscription", back_populates="usage_logs")


class APIKey(Base):
    __tablename__ = "api_keys"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    key_name = Column(String(100), nullable=False)
    key_hash = Column(String(255), unique=True, nullable=False, index=True)
    key_prefix = Column(String(20), nullable=False)
    is_active = Column(Boolean, default=True)
    last_used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="api_keys")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50))
    resource_id = Column(UUID(as_uuid=True))
    ip_address = Column(INET)
    user_agent = Column(Text)
    changes = Column(JSONB)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
