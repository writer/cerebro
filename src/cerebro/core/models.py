"""SQLAlchemy models for Cerebro database schema."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID, uuid4

from sqlalchemy import (
    String, Text, Boolean, DateTime, LargeBinary, Integer, 
    ForeignKey, UniqueConstraint, CheckConstraint, Index, ARRAY
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from .database import Base


class Organization(Base):
    """Organizations table - top-level tenants."""
    __tablename__ = "orgs"
    
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    
    # Relationships
    accounts: Mapped[List["Account"]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    policies: Mapped[List["Policy"]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    findings: Mapped[List["Finding"]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    suppressions: Mapped[List["Suppression"]] = relationship(back_populates="organization", cascade="all, delete-orphan")


class Account(Base):
    """Accounts table - provider-specific accounts."""
    __tablename__ = "accounts"
    
    account_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("orgs.org_id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String, nullable=False)
    external_id: Mapped[str] = mapped_column(String, nullable=False)
    display_name: Mapped[Optional[str]] = mapped_column(String)
    
    __table_args__ = (
        UniqueConstraint("org_id", "provider", "external_id"),
        CheckConstraint("provider IN ('github','google_workspace','aws','gcp')"),
    )
    
    # Relationships
    organization: Mapped["Organization"] = relationship(back_populates="accounts")
    principals: Mapped[List["Principal"]] = relationship(back_populates="account", cascade="all, delete-orphan")
    resources: Mapped[List["Resource"]] = relationship(back_populates="account", cascade="all, delete-orphan")
    iam_edges: Mapped[List["IamEdge"]] = relationship(back_populates="account", cascade="all, delete-orphan")
    audit_events: Mapped[List["AuditEvent"]] = relationship(back_populates="account", cascade="all, delete-orphan")
    findings: Mapped[List["Finding"]] = relationship(back_populates="account", cascade="all, delete-orphan")


class Principal(Base):
    """Principals table - users, groups, service accounts, apps."""
    __tablename__ = "principals"
    
    principal_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    account_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("accounts.account_id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String, nullable=False)
    principal_type: Mapped[str] = mapped_column(String, nullable=False)
    external_id: Mapped[str] = mapped_column(String, nullable=False)
    email: Mapped[Optional[str]] = mapped_column(String)
    display_name: Mapped[Optional[str]] = mapped_column(String)
    is_human: Mapped[Optional[bool]] = mapped_column(Boolean)
    
    __table_args__ = (
        UniqueConstraint("account_id", "provider", "external_id"),
        CheckConstraint("principal_type IN ('user','group','service_account','app','role')"),
    )
    
    # Relationships
    account: Mapped["Account"] = relationship(back_populates="principals")
    iam_edges: Mapped[List["IamEdge"]] = relationship(back_populates="principal", cascade="all, delete-orphan")
    findings: Mapped[List["Finding"]] = relationship(back_populates="principal")


class Resource(Base):
    """Resources table - cloud/SaaS objects."""
    __tablename__ = "resources"
    
    resource_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    account_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("accounts.account_id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String, nullable=False)
    resource_type: Mapped[str] = mapped_column(String, nullable=False)
    external_id: Mapped[str] = mapped_column(String, nullable=False)
    name: Mapped[Optional[str]] = mapped_column(String)
    parent_external_id: Mapped[Optional[str]] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    
    __table_args__ = (
        UniqueConstraint("account_id", "provider", "resource_type", "external_id"),
    )
    
    # Relationships
    account: Mapped["Account"] = relationship(back_populates="resources")
    config_snapshots: Mapped[List["ConfigSnapshot"]] = relationship(back_populates="resource", cascade="all, delete-orphan")
    iam_edges: Mapped[List["IamEdge"]] = relationship(back_populates="resource")
    findings: Mapped[List["Finding"]] = relationship(back_populates="resource")


class ConfigSnapshot(Base):
    """Config snapshots table - append-only configuration captures."""
    __tablename__ = "config_snapshots"
    
    snapshot_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    resource_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("resources.resource_id", ondelete="CASCADE"))
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    config_sha: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    normalized_config: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    collector_version: Mapped[str] = mapped_column(String, nullable=False)
    
    __table_args__ = (
        UniqueConstraint("resource_id", "config_sha"),
        Index("ix_config_snapshots_resource_captured", "resource_id", "captured_at"),
        Index("ix_config_snapshots_normalized_config", "normalized_config", postgresql_using="gin"),
    )
    
    # Relationships
    resource: Mapped["Resource"] = relationship(back_populates="config_snapshots")


class IamEdge(Base):
    """IAM edges table - append-only effective permissions."""
    __tablename__ = "iam_edges"
    
    edge_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    account_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("accounts.account_id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String, nullable=False)
    principal_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("principals.principal_id", ondelete="CASCADE"))
    resource_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), ForeignKey("resources.resource_id", ondelete="CASCADE"))
    permission: Mapped[str] = mapped_column(String, nullable=False)
    via: Mapped[Optional[str]] = mapped_column(String)
    effective_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    
    __table_args__ = (
        UniqueConstraint("account_id", "provider", "principal_id", "resource_id", "permission", "effective_at", "via"),
        Index("ix_iam_edges_principal", "principal_id"),
        Index("ix_iam_edges_resource", "resource_id"),
        Index("ix_iam_edges_is_admin", "is_admin"),
        Index("ix_iam_edges_effective_at", "effective_at"),
    )
    
    # Relationships
    account: Mapped["Account"] = relationship(back_populates="iam_edges")
    principal: Mapped["Principal"] = relationship(back_populates="iam_edges")
    resource: Mapped[Optional["Resource"]] = relationship(back_populates="iam_edges")


class Policy(Base):
    """Policies table - policy frameworks."""
    __tablename__ = "policies"
    
    policy_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("orgs.org_id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    framework: Mapped[Optional[str]] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    
    # Relationships
    organization: Mapped["Organization"] = relationship(back_populates="policies")
    rules: Mapped[List["Rule"]] = relationship(back_populates="policy")


class Rule(Base):
    """Rules table - CEL/SQL/Rego rule expressions."""
    __tablename__ = "rules"
    
    rule_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    policy_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), ForeignKey("policies.policy_id", ondelete="SET NULL"))
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    provider: Mapped[List[str]] = mapped_column(ARRAY(String), nullable=False)
    resource_types: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String))
    expression_lang: Mapped[str] = mapped_column(String, nullable=False)
    expression: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    cwe: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String))
    cis: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String))
    nist_800_53: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String))
    mitre_attack: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String))
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    
    __table_args__ = (
        CheckConstraint("expression_lang IN ('sql','rego','cel')"),
        CheckConstraint("severity IN ('critical','high','medium','low','info')"),
        Index("ix_rules_is_active", "is_active"),
        Index("ix_rules_provider", "provider", postgresql_using="gin"),
        Index("ix_rules_resource_types", "resource_types", postgresql_using="gin"),
    )
    
    # Relationships
    policy: Mapped[Optional["Policy"]] = relationship(back_populates="rules")
    findings: Mapped[List["Finding"]] = relationship(back_populates="rule")


class Finding(Base):
    """Findings table - materialized misconfigurations or violations."""
    __tablename__ = "findings"
    
    finding_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("orgs.org_id", ondelete="CASCADE"))
    account_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("accounts.account_id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String, nullable=False)
    rule_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("rules.rule_id"))
    rule_version: Mapped[int] = mapped_column(Integer, nullable=False)
    resource_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), ForeignKey("resources.resource_id"))
    principal_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), ForeignKey("principals.principal_id"))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    summary: Mapped[Optional[str]] = mapped_column(Text)
    evidence: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    
    __table_args__ = (
        UniqueConstraint("org_id", "fingerprint"),
        CheckConstraint("status IN ('open','suppressed','accepted_risk','fixed')"),
        Index("ix_findings_status", "status"),
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_last_seen", "last_seen"),
    )
    
    # Relationships
    organization: Mapped["Organization"] = relationship(back_populates="findings")
    account: Mapped["Account"] = relationship(back_populates="findings")
    rule: Mapped["Rule"] = relationship(back_populates="findings")
    resource: Mapped[Optional["Resource"]] = relationship(back_populates="findings")
    principal: Mapped[Optional["Principal"]] = relationship(back_populates="findings")
    evidence_artifacts: Mapped[List["EvidenceArtifact"]] = relationship(back_populates="finding", cascade="all, delete-orphan")


class EvidenceArtifact(Base):
    """Evidence artifacts table - evidence blobs for findings."""
    __tablename__ = "evidence_artifacts"
    
    artifact_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    finding_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("findings.finding_id", ondelete="CASCADE"))
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    kind: Mapped[str] = mapped_column(String, nullable=False)
    uri: Mapped[Optional[str]] = mapped_column(String)
    blob: Mapped[Optional[bytes]] = mapped_column(LargeBinary)
    artifact_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    
    # Relationships
    finding: Mapped["Finding"] = relationship(back_populates="evidence_artifacts")


class AuditEvent(Base):
    """Audit events table - optional append-only audit logs."""
    __tablename__ = "audit_events"
    
    event_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    account_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("accounts.account_id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor_external_id: Mapped[Optional[str]] = mapped_column(String)
    action: Mapped[str] = mapped_column(String, nullable=False)
    resource_external_id: Mapped[Optional[str]] = mapped_column(String)
    raw: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    
    __table_args__ = (
        Index("ix_audit_events_occurred_at", "occurred_at"),
        Index("ix_audit_events_provider_action", "provider", "action"),
        Index("ix_audit_events_raw", "raw", postgresql_using="gin"),
    )
    
    # Relationships
    account: Mapped["Account"] = relationship(back_populates="audit_events")


class Suppression(Base):
    """Suppressions table - scoped suppressions or risk acceptances."""
    __tablename__ = "suppressions"
    
    suppression_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    org_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("orgs.org_id", ondelete="CASCADE"))
    rule_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), ForeignKey("rules.rule_id"))
    resource_pattern: Mapped[Optional[str]] = mapped_column(String)
    principal_pattern: Mapped[Optional[str]] = mapped_column(String)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    
    # Relationships
    organization: Mapped["Organization"] = relationship(back_populates="suppressions")
