"""SQLAlchemy models for Cerebro database schema."""

from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from .database import Base
from .database_types import ArrayType, JSONType

if TYPE_CHECKING:  # pragma: no cover
    from cerebro.core.user_models import User


class Organization(Base):
    """Organizations table - top-level tenants."""

    __tablename__ = "orgs"

    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    name: Mapped[str] = mapped_column(String, nullable=False)
    slack_config: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONType, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )

    # Relationships
    accounts: Mapped[List["Account"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    policies: Mapped[List["Policy"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    findings: Mapped[List["Finding"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    suppressions: Mapped[List["Suppression"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    slack_webhooks: Mapped[List["SlackWebhook"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    remediation_actions: Mapped[List["IdentityRemediationAction"]] = relationship(
        "IdentityRemediationAction",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    frontend_observations: Mapped[List["FrontendObservationEvent"]] = relationship(
        "FrontendObservationEvent",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    serval_integration: Mapped[Optional["ServalIntegration"]] = relationship(
        "ServalIntegration",
        back_populates="organization",
        cascade="all, delete-orphan",
        uselist=False,
    )


class Account(Base):
    """Accounts table - provider-specific accounts."""

    __tablename__ = "accounts"

    account_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("orgs.org_id", ondelete="CASCADE")
    )
    provider: Mapped[str] = mapped_column(String, nullable=False)
    external_id: Mapped[str] = mapped_column(String, nullable=False)
    display_name: Mapped[Optional[str]] = mapped_column(String)

    __table_args__ = (
        UniqueConstraint("org_id", "provider", "external_id"),
        CheckConstraint(
            "provider IN ('github','google_workspace','aws','gcp','runtime','endpoint')"
        ),
    )

    # Relationships
    organization: Mapped["Organization"] = relationship(back_populates="accounts")
    principals: Mapped[List["Principal"]] = relationship(
        back_populates="account", cascade="all, delete-orphan"
    )
    resources: Mapped[List["Resource"]] = relationship(
        back_populates="account", cascade="all, delete-orphan"
    )
    iam_edges: Mapped[List["IamEdge"]] = relationship(
        back_populates="account", cascade="all, delete-orphan"
    )
    audit_events: Mapped[List["AuditEvent"]] = relationship(
        back_populates="account", cascade="all, delete-orphan"
    )
    findings: Mapped[List["Finding"]] = relationship(
        back_populates="account", cascade="all, delete-orphan"
    )


class Principal(Base):
    """Principals table - users, groups, service accounts, apps."""

    __tablename__ = "principals"

    principal_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    account_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("accounts.account_id", ondelete="CASCADE")
    )
    provider: Mapped[str] = mapped_column(String, nullable=False)
    principal_type: Mapped[str] = mapped_column(String, nullable=False)
    external_id: Mapped[str] = mapped_column(String, nullable=False)
    email: Mapped[Optional[str]] = mapped_column(String)
    display_name: Mapped[Optional[str]] = mapped_column(String)
    is_human: Mapped[Optional[bool]] = mapped_column(Boolean)

    __table_args__ = (
        UniqueConstraint("account_id", "provider", "external_id"),
        CheckConstraint(
            "principal_type IN ('user','group','service_account','app','role')"
        ),
    )

    # Relationships
    account: Mapped["Account"] = relationship(back_populates="principals")
    iam_edges: Mapped[List["IamEdge"]] = relationship(
        back_populates="principal", cascade="all, delete-orphan"
    )
    findings: Mapped[List["Finding"]] = relationship(back_populates="principal")
    remediation_actions: Mapped[List["IdentityRemediationAction"]] = relationship(
        "IdentityRemediationAction",
        back_populates="principal",
        cascade="all, delete-orphan",
    )


class Resource(Base):
    """Resources table - cloud/SaaS objects."""

    __tablename__ = "resources"

    resource_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    account_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("accounts.account_id", ondelete="CASCADE")
    )
    provider: Mapped[str] = mapped_column(String, nullable=False)
    resource_type: Mapped[str] = mapped_column(String, nullable=False)
    external_id: Mapped[str] = mapped_column(String, nullable=False)
    name: Mapped[Optional[str]] = mapped_column(String)
    parent_external_id: Mapped[Optional[str]] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("account_id", "provider", "resource_type", "external_id"),
    )

    # Relationships
    account: Mapped["Account"] = relationship(back_populates="resources")
    config_snapshots: Mapped[List["ConfigSnapshot"]] = relationship(
        back_populates="resource", cascade="all, delete-orphan"
    )
    iam_edges: Mapped[List["IamEdge"]] = relationship(back_populates="resource")
    findings: Mapped[List["Finding"]] = relationship(back_populates="resource")


class ConfigSnapshot(Base):
    """Config snapshots table - append-only configuration captures."""

    __tablename__ = "config_snapshots"

    snapshot_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    resource_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("resources.resource_id", ondelete="CASCADE")
    )
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    config_sha: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    normalized_config: Mapped[Dict[str, Any]] = mapped_column(JSONType, nullable=False)
    collector_version: Mapped[str] = mapped_column(String, nullable=False)

    __table_args__ = (
        UniqueConstraint("resource_id", "config_sha"),
        Index("ix_config_snapshots_resource_captured", "resource_id", "captured_at"),
        Index(
            "ix_config_snapshots_normalized_config",
            "normalized_config",
            postgresql_using="gin",
        ),
    )

    # Relationships
    resource: Mapped["Resource"] = relationship(back_populates="config_snapshots")


class IamEdge(Base):
    """IAM edges table - append-only effective permissions."""

    __tablename__ = "iam_edges"

    edge_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    account_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("accounts.account_id", ondelete="CASCADE")
    )
    provider: Mapped[str] = mapped_column(String, nullable=False)
    principal_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("principals.principal_id", ondelete="CASCADE")
    )
    resource_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("resources.resource_id", ondelete="CASCADE")
    )
    permission: Mapped[str] = mapped_column(String, nullable=False)
    via: Mapped[Optional[str]] = mapped_column(String)
    effective_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "account_id",
            "provider",
            "principal_id",
            "resource_id",
            "permission",
            "effective_at",
            "via",
        ),
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

    policy_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("orgs.org_id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    framework: Mapped[Optional[str]] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )

    # Relationships
    organization: Mapped["Organization"] = relationship(back_populates="policies")
    rules: Mapped[List["Rule"]] = relationship(back_populates="policy")


class ServalIntegration(Base):
    """Configuration for Serval custom app integration per organization."""

    __tablename__ = "serval_integrations"

    integration_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=func.gen_random_uuid(),
    )
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("orgs.org_id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    api_base_url: Mapped[str] = mapped_column(
        String,
        nullable=False,
        default="https://public.api.serval.com",
    )
    team_id: Mapped[str] = mapped_column(String, nullable=False)
    default_status_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    default_priority_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    default_created_by_user_id: Mapped[str] = mapped_column(String, nullable=False)
    default_requester_user_id: Mapped[Optional[str]] = mapped_column(
        String, nullable=True
    )
    default_assigned_user_id: Mapped[Optional[str]] = mapped_column(
        String, nullable=True
    )
    settings: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONType, nullable=True, default=dict
    )
    encrypted_client_id: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encrypted_client_id_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encrypted_client_secret: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encrypted_client_secret_dek: Mapped[bytes] = mapped_column(
        LargeBinary, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    organization: Mapped[Organization] = relationship(
        "Organization", back_populates="serval_integration"
    )


class Rule(Base):
    """Rules table - CEL/SQL/Rego rule expressions."""

    __tablename__ = "rules"

    rule_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    policy_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("policies.policy_id", ondelete="SET NULL")
    )
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    provider: Mapped[List[str]] = mapped_column(ArrayType(String), nullable=False)
    resource_types: Mapped[Optional[List[str]]] = mapped_column(ArrayType(String))
    expression_lang: Mapped[str] = mapped_column(String, nullable=False)
    expression: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    cwe: Mapped[Optional[List[str]]] = mapped_column(ArrayType(String))
    cis: Mapped[Optional[List[str]]] = mapped_column(ArrayType(String))
    nist_800_53: Mapped[Optional[List[str]]] = mapped_column(ArrayType(String))
    mitre_attack: Mapped[Optional[List[str]]] = mapped_column(ArrayType(String))
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )

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

    finding_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("orgs.org_id", ondelete="CASCADE")
    )
    account_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("accounts.account_id", ondelete="CASCADE")
    )
    provider: Mapped[str] = mapped_column(String, nullable=False)
    rule_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("rules.rule_id")
    )
    rule_version: Mapped[int] = mapped_column(Integer, nullable=False)
    resource_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("resources.resource_id")
    )
    principal_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("principals.principal_id")
    )
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    summary: Mapped[Optional[str]] = mapped_column(Text)
    evidence: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType)

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
    evidence_artifacts: Mapped[List["EvidenceArtifact"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class EvidenceArtifact(Base):
    """Evidence artifacts table - evidence blobs for findings."""

    __tablename__ = "evidence_artifacts"

    artifact_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    finding_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("findings.finding_id", ondelete="CASCADE")
    )
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )
    kind: Mapped[str] = mapped_column(String, nullable=False)
    uri: Mapped[Optional[str]] = mapped_column(String)
    blob: Mapped[Optional[bytes]] = mapped_column(LargeBinary)
    artifact_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType)

    # Relationships
    finding: Mapped["Finding"] = relationship(back_populates="evidence_artifacts")


class IdentityRemediationAction(Base):
    """Persistent state for identity remediation queue actions."""

    __tablename__ = "identity_remediation_actions"

    action_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("orgs.org_id", ondelete="CASCADE")
    )
    principal_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("principals.principal_id", ondelete="CASCADE")
    )

    summary: Mapped[str] = mapped_column(String(255), nullable=False)
    recommended_action: Mapped[str] = mapped_column(Text, nullable=False)
    priority: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")

    evidence: Mapped[List[str]] = mapped_column(JSONType, nullable=False, default=list)
    notes: Mapped[List[Dict[str, Any]]] = mapped_column(
        JSONType, nullable=False, default=list
    )

    accepted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    accepted_by: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.user_id", ondelete="SET NULL")
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_by: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.user_id", ondelete="SET NULL")
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), onupdate=func.now()
    )
    created_by: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.user_id", ondelete="SET NULL")
    )
    updated_by: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.user_id", ondelete="SET NULL")
    )

    organization: Mapped["Organization"] = relationship(
        back_populates="remediation_actions"
    )
    principal: Mapped["Principal"] = relationship(back_populates="remediation_actions")
    accepted_user: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[accepted_by]
    )
    completed_user: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[completed_by]
    )
    creator: Mapped[Optional["User"]] = relationship("User", foreign_keys=[created_by])
    updater: Mapped[Optional["User"]] = relationship("User", foreign_keys=[updated_by])

    __table_args__ = (
        CheckConstraint("priority IN ('low','medium','high')"),
        CheckConstraint("status IN ('pending','accepted','completed')"),
        UniqueConstraint(
            "org_id", "principal_id", "recommended_action", name="uq_remediation_rec"
        ),
        Index("ix_remediation_actions_org", "org_id"),
        Index("ix_remediation_actions_principal", "principal_id"),
        Index("ix_remediation_actions_status", "status"),
    )


class AuditEvent(Base):
    """Audit events table - optional append-only audit logs."""

    __tablename__ = "audit_events"

    event_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    account_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("accounts.account_id", ondelete="CASCADE")
    )
    provider: Mapped[str] = mapped_column(String, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    actor_external_id: Mapped[Optional[str]] = mapped_column(String)
    action: Mapped[str] = mapped_column(String, nullable=False)
    resource_external_id: Mapped[Optional[str]] = mapped_column(String)
    raw: Mapped[Dict[str, Any]] = mapped_column(JSONType, nullable=False)

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

    suppression_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("orgs.org_id", ondelete="CASCADE")
    )
    rule_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("rules.rule_id")
    )
    resource_pattern: Mapped[Optional[str]] = mapped_column(String)
    principal_pattern: Mapped[Optional[str]] = mapped_column(String)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )

    # Relationships
    organization: Mapped["Organization"] = relationship(back_populates="suppressions")


class SlackWebhook(Base):
    """Slack webhook configurations for organizations."""

    __tablename__ = "slack_webhooks"

    webhook_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("orgs.org_id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Encrypted webhook URL fields (envelope encryption)
    webhook_url: Mapped[Optional[bytes]] = mapped_column(LargeBinary)  # Encrypted data
    webhook_url_dek: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary
    )  # Encrypted DEK

    channel: Mapped[Optional[str]] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    severity_filter: Mapped[Optional[List[str]]] = mapped_column(ArrayType)
    finding_type_filter: Mapped[Optional[List[str]]] = mapped_column(ArrayType)
    event_types: Mapped[List[str]] = mapped_column(ArrayType, nullable=False)
    webhook_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        "metadata", JSONType
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), onupdate=func.now()
    )
    created_by: Mapped[Optional[str]] = mapped_column(String(255))

    # Relationships
    organization: Mapped["Organization"] = relationship(back_populates="slack_webhooks")
    notifications: Mapped[List["SlackNotification"]] = relationship(
        back_populates="webhook", cascade="all, delete-orphan"
    )

    async def get_webhook_url(self) -> Optional[str]:
        """Decrypt webhook URL.

        Returns:
            Decrypted webhook URL or None
        """
        if not self.webhook_url or not self.webhook_url_dek:
            return None

        from cerebro.core.encryption import get_encryption_service

        service = get_encryption_service()
        return await service.decrypt_secret(self.webhook_url, self.webhook_url_dek)

    async def set_webhook_url(self, url: str) -> None:
        """Encrypt and set webhook URL.

        Args:
            url: Plaintext webhook URL to encrypt
        """
        from cerebro.core.encryption import get_encryption_service

        service = get_encryption_service()
        self.webhook_url, self.webhook_url_dek = await service.encrypt_secret(url)


class SlackNotification(Base):
    """Audit log of Slack notifications sent."""

    __tablename__ = "slack_notifications"

    notification_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    webhook_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("slack_webhooks.webhook_id", ondelete="CASCADE"),
    )
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("orgs.org_id", ondelete="CASCADE")
    )
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    finding_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True))
    severity: Mapped[Optional[str]] = mapped_column(String(50))
    payload: Mapped[Dict[str, Any]] = mapped_column(JSONType, nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    status_code: Mapped[Optional[int]] = mapped_column(Integer)
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )

    # Relationships
    webhook: Mapped["SlackWebhook"] = relationship(back_populates="notifications")


class IntegrationSyncState(Base):
    """Checkpoint tracking for incremental third-party integrations."""

    __tablename__ = "integration_sync_state"

    state_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=func.gen_random_uuid(),
    )
    integration: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    scope: Mapped[str] = mapped_column(String(128), nullable=False, default="default")
    last_cursor: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    last_timestamp: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    state_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONType, nullable=True, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=func.now(),
        onupdate=func.now(),
    )

    __table_args__ = (
        UniqueConstraint("integration", "scope"),
        Index("ix_integration_sync_state_scope", "scope"),
    )


class IntegrationSyncIssueEvent(Base):
    """Append-only history of integration sync issues for observability."""

    __tablename__ = "integration_sync_issue_events"

    issue_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=func.gen_random_uuid(),
    )
    integration: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    scope: Mapped[str] = mapped_column(String(128), nullable=False, default="default")
    issue_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_timestamp: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    age_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    issue_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONType, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=func.now()
    )

    __table_args__ = (
        Index("ix_integration_issue_events_scope", "scope"),
        Index("ix_integration_issue_events_observed", "observed_at"),
    )


class EmailConfig(Base):
    """Email notification configurations for organizations."""

    __tablename__ = "email_configs"

    config_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("orgs.org_id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    smtp_host: Mapped[str] = mapped_column(String(255), nullable=False)
    smtp_port: Mapped[int] = mapped_column(Integer, default=587, nullable=False)
    smtp_username: Mapped[Optional[str]] = mapped_column(String(255))

    # Encrypted password fields (envelope encryption)
    smtp_password: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary
    )  # Encrypted data
    smtp_password_dek: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary
    )  # Encrypted DEK

    from_email: Mapped[str] = mapped_column(String(255), nullable=False)
    from_name: Mapped[Optional[str]] = mapped_column(String(255))
    to_emails: Mapped[List[str]] = mapped_column(ArrayType, nullable=False)
    cc_emails: Mapped[Optional[List[str]]] = mapped_column(ArrayType)
    use_tls: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    severity_filter: Mapped[Optional[List[str]]] = mapped_column(ArrayType)
    event_types: Mapped[List[str]] = mapped_column(ArrayType, nullable=False)
    digest_mode: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    digest_frequency: Mapped[Optional[str]] = mapped_column(String(50))
    email_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        "email_metadata", JSONType
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), onupdate=func.now()
    )
    created_by: Mapped[Optional[str]] = mapped_column(String(255))

    # Relationships
    notifications: Mapped[List["EmailNotification"]] = relationship(
        back_populates="config", cascade="all, delete-orphan"
    )

    async def get_smtp_password(self) -> Optional[str]:
        """Decrypt SMTP password.

        Returns:
            Decrypted password or None
        """
        if not self.smtp_password or not self.smtp_password_dek:
            return None

        from cerebro.core.encryption import get_encryption_service

        service = get_encryption_service()
        return await service.decrypt_secret(self.smtp_password, self.smtp_password_dek)

    async def set_smtp_password(self, password: Optional[str]) -> None:
        """Encrypt and set SMTP password.

        Args:
            password: Plaintext password to encrypt
        """
        if password is None:
            self.smtp_password = None
            self.smtp_password_dek = None
            return

        from cerebro.core.encryption import get_encryption_service

        service = get_encryption_service()
        self.smtp_password, self.smtp_password_dek = await service.encrypt_secret(
            password
        )


class EmailNotification(Base):
    """Audit log of email notifications sent."""

    __tablename__ = "email_notifications"

    notification_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    config_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("email_configs.config_id", ondelete="CASCADE")
    )
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("orgs.org_id", ondelete="CASCADE")
    )
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    finding_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True))
    severity: Mapped[Optional[str]] = mapped_column(String(50))
    subject: Mapped[str] = mapped_column(String(500), nullable=False)
    body_html: Mapped[str] = mapped_column(Text, nullable=False)
    body_text: Mapped[Optional[str]] = mapped_column(Text)
    to_emails: Mapped[List[str]] = mapped_column(ArrayType, nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    status_code: Mapped[Optional[int]] = mapped_column(Integer)
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )

    # Relationships
    config: Mapped["EmailConfig"] = relationship(back_populates="notifications")


class WebhookConfig(Base):
    """Generic webhook configurations for organizations."""

    __tablename__ = "webhook_configs"

    config_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("orgs.org_id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    http_method: Mapped[str] = mapped_column(String(10), default="POST", nullable=False)
    headers: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType)
    payload_template: Mapped[Dict[str, Any]] = mapped_column(JSONType, nullable=False)
    authentication: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONType)
    use_hmac_signature: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    # Encrypted HMAC secret fields (envelope encryption)
    hmac_secret: Mapped[Optional[bytes]] = mapped_column(LargeBinary)  # Encrypted data
    hmac_secret_dek: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary
    )  # Encrypted DEK
    # Note: authentication_dek also exists but authentication field stores encrypted data directly

    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    severity_filter: Mapped[Optional[List[str]]] = mapped_column(ArrayType)
    event_types: Mapped[List[str]] = mapped_column(ArrayType, nullable=False)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    webhook_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        "webhook_metadata", JSONType
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), onupdate=func.now()
    )
    created_by: Mapped[Optional[str]] = mapped_column(String(255))

    # Relationships
    notifications: Mapped[List["WebhookNotification"]] = relationship(
        back_populates="config", cascade="all, delete-orphan"
    )

    async def get_hmac_secret(self) -> Optional[str]:
        """Decrypt HMAC secret.

        Returns:
            Decrypted secret or None
        """
        if not self.hmac_secret or not self.hmac_secret_dek:
            return None

        from cerebro.core.encryption import get_encryption_service

        service = get_encryption_service()
        return await service.decrypt_secret(self.hmac_secret, self.hmac_secret_dek)

    async def set_hmac_secret(self, secret: Optional[str]) -> None:
        """Encrypt and set HMAC secret.

        Args:
            secret: Plaintext secret to encrypt
        """
        if secret is None:
            self.hmac_secret = None
            self.hmac_secret_dek = None
            return

        from cerebro.core.encryption import get_encryption_service

        service = get_encryption_service()
        self.hmac_secret, self.hmac_secret_dek = await service.encrypt_secret(secret)


class WebhookNotification(Base):
    """Audit log of webhook notifications sent."""

    __tablename__ = "webhook_notifications"

    notification_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid4
    )
    config_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("webhook_configs.config_id", ondelete="CASCADE"),
    )
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("orgs.org_id", ondelete="CASCADE")
    )
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    finding_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True))
    severity: Mapped[Optional[str]] = mapped_column(String(50))
    payload: Mapped[Dict[str, Any]] = mapped_column(JSONType, nullable=False)
    response_status: Mapped[Optional[int]] = mapped_column(Integer)
    response_body: Mapped[Optional[str]] = mapped_column(Text)
    response_time_ms: Mapped[Optional[int]] = mapped_column(
        Integer
    )  # Response time in milliseconds
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )

    # Relationships
    config: Mapped["WebhookConfig"] = relationship(back_populates="notifications")


class FrontendObservationEvent(Base):
    """Captured frontend analyst interaction telemetry events."""

    __tablename__ = "frontend_observation_events"

    event_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=func.gen_random_uuid(),
    )
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("orgs.org_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.user_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    agent_session_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=True,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String(150), nullable=False)
    component: Mapped[Optional[str]] = mapped_column(String(200))
    context_data: Mapped[Dict[str, Any]] = mapped_column(
        JSONType, nullable=False, default=dict
    )
    event_metadata: Mapped[Dict[str, Any]] = mapped_column(
        "metadata",
        JSONType,
        nullable=False,
        default=dict,
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    organization: Mapped["Organization"] = relationship(
        "Organization",
        back_populates="frontend_observations",
    )
    user: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys=[user_id],
    )


# Import identity models to make them available
