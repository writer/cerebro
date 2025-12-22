"""Pydantic models for DynamoDB entities.

These models replace SQLAlchemy ORM models with Pydantic models that include
DynamoDB serialization/deserialization methods following single-table design.

Entity Types and Key Patterns:
    Core Table (cerebro-core):
        - ORG: PK=ORG#{org_id}, SK=ORG#{org_id}
        - ACCOUNT: PK=ORG#{org_id}, SK=ACCOUNT#{account_id}
        - PRINCIPAL: PK=ORG#{org_id}, SK=PRINCIPAL#{principal_id}
        - RESOURCE: PK=ORG#{org_id}, SK=RESOURCE#{resource_id}
        - FINDING: PK=ORG#{org_id}, SK=FINDING#{finding_id}
        - RULE: PK=RULE#{rule_id}, SK=RULE#{rule_id} (global, not org-scoped)
        - POLICY: PK=ORG#{org_id}, SK=POLICY#{policy_id}

    GSI1 (by provider/type):
        - GSI1PK=PROVIDER#{provider}, GSI1SK=ACCOUNT#{account_id}
        - GSI1PK=ACCOUNT#{account_id}, GSI1SK=PRINCIPAL#{principal_id}
        - GSI1PK=ACCOUNT#{account_id}, GSI1SK=RESOURCE#{resource_id}
        - GSI1PK=RULE#{rule_id}, GSI1SK=FINDING#{finding_id}

    GSI2 (by status/severity):
        - GSI2PK=ORG#{org_id}#STATUS#{status}, GSI2SK=SEVERITY#{severity}#{finding_id}

    GSI3 (by timestamp):
        - GSI3PK=ORG#{org_id}, GSI3SK=CREATED#{iso_timestamp}
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from cerebro.core.dynamodb import (
    build_gsi1_pk,
    build_gsi1_sk,
    build_pk,
    build_sk,
)


class EntityType(str, Enum):
    """Entity type prefixes for DynamoDB keys."""

    ORG = "ORG"
    ACCOUNT = "ACCOUNT"
    PRINCIPAL = "PRINCIPAL"
    RESOURCE = "RESOURCE"
    FINDING = "FINDING"
    RULE = "RULE"
    POLICY = "POLICY"
    CONFIG_SNAPSHOT = "CONFIG_SNAPSHOT"
    IAM_EDGE = "IAM_EDGE"
    SUPPRESSION = "SUPPRESSION"
    AUDIT_EVENT = "AUDIT_EVENT"


class Provider(str, Enum):
    """Supported cloud/SaaS providers."""

    GITHUB = "github"
    GOOGLE_WORKSPACE = "google_workspace"
    AWS = "aws"
    GCP = "gcp"
    RUNTIME = "runtime"
    ENDPOINT = "endpoint"


class PrincipalType(str, Enum):
    """Types of principals."""

    USER = "user"
    GROUP = "group"
    SERVICE_ACCOUNT = "service_account"
    APP = "app"
    ROLE = "role"


class FindingStatus(str, Enum):
    """Finding lifecycle states."""

    OPEN = "open"
    SUPPRESSED = "suppressed"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"


class Severity(str, Enum):
    """Severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ExpressionLang(str, Enum):
    """Rule expression languages."""

    SQL = "sql"
    REGO = "rego"
    CEL = "cel"


class DynamoDBModel(BaseModel):
    """Base model for DynamoDB entities with serialization helpers."""

    class Config:
        populate_by_name = True
        use_enum_values = True

    def to_dynamodb_item(self) -> Dict[str, Any]:
        """Convert model to DynamoDB item format with keys."""
        raise NotImplementedError("Subclasses must implement to_dynamodb_item")

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> "DynamoDBModel":
        """Create model instance from DynamoDB item."""
        raise NotImplementedError("Subclasses must implement from_dynamodb_item")

    def get_pk(self) -> str:
        """Get partition key for this entity."""
        raise NotImplementedError("Subclasses must implement get_pk")

    def get_sk(self) -> str:
        """Get sort key for this entity."""
        raise NotImplementedError("Subclasses must implement get_sk")


class Organization(DynamoDBModel):
    """Organization entity - top-level tenant."""

    org_id: UUID = Field(default_factory=uuid4)
    name: str
    slack_config: Optional[Dict[str, Any]] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def get_pk(self) -> str:
        return build_pk(EntityType.ORG.value, self.org_id)

    def get_sk(self) -> str:
        return build_sk(EntityType.ORG.value, self.org_id)

    def to_dynamodb_item(self) -> Dict[str, Any]:
        return {
            "PK": self.get_pk(),
            "SK": self.get_sk(),
            "entity_type": EntityType.ORG.value,
            "org_id": str(self.org_id),
            "name": self.name,
            "slack_config": self.slack_config,
            "created_at": self.created_at.isoformat(),
            # GSI3 for listing by creation time
            "GSI3PK": build_pk(EntityType.ORG.value, "ALL"),
            "GSI3SK": f"CREATED#{self.created_at.isoformat()}",
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> "Organization":
        return cls(
            org_id=UUID(item["org_id"]),
            name=item["name"],
            slack_config=item.get("slack_config"),
            created_at=datetime.fromisoformat(item["created_at"]),
        )


class Account(DynamoDBModel):
    """Account entity - provider-specific account within an org."""

    account_id: UUID = Field(default_factory=uuid4)
    org_id: UUID
    provider: Provider
    external_id: str
    display_name: Optional[str] = None

    def get_pk(self) -> str:
        return build_pk(EntityType.ORG.value, self.org_id)

    def get_sk(self) -> str:
        return build_sk(EntityType.ACCOUNT.value, self.account_id)

    def to_dynamodb_item(self) -> Dict[str, Any]:
        return {
            "PK": self.get_pk(),
            "SK": self.get_sk(),
            "entity_type": EntityType.ACCOUNT.value,
            "account_id": str(self.account_id),
            "org_id": str(self.org_id),
            "provider": (
                self.provider.value
                if isinstance(self.provider, Enum)
                else self.provider
            ),
            "external_id": self.external_id,
            "display_name": self.display_name,
            # GSI1 for querying by provider
            "GSI1PK": build_gsi1_pk(
                "PROVIDER",
                (
                    self.provider.value
                    if isinstance(self.provider, Enum)
                    else self.provider
                ),
            ),
            "GSI1SK": build_gsi1_sk(EntityType.ACCOUNT.value, self.account_id),
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> "Account":
        return cls(
            account_id=UUID(item["account_id"]),
            org_id=UUID(item["org_id"]),
            provider=Provider(item["provider"]),
            external_id=item["external_id"],
            display_name=item.get("display_name"),
        )


class Principal(DynamoDBModel):
    """Principal entity - users, groups, service accounts."""

    principal_id: UUID = Field(default_factory=uuid4)
    account_id: UUID
    org_id: UUID
    provider: Provider
    principal_type: PrincipalType
    external_id: str
    email: Optional[str] = None
    display_name: Optional[str] = None
    is_human: Optional[bool] = None

    def get_pk(self) -> str:
        return build_pk(EntityType.ORG.value, self.org_id)

    def get_sk(self) -> str:
        return build_sk(EntityType.PRINCIPAL.value, self.principal_id)

    def to_dynamodb_item(self) -> Dict[str, Any]:
        return {
            "PK": self.get_pk(),
            "SK": self.get_sk(),
            "entity_type": EntityType.PRINCIPAL.value,
            "principal_id": str(self.principal_id),
            "account_id": str(self.account_id),
            "org_id": str(self.org_id),
            "provider": (
                self.provider.value
                if isinstance(self.provider, Enum)
                else self.provider
            ),
            "principal_type": (
                self.principal_type.value
                if isinstance(self.principal_type, Enum)
                else self.principal_type
            ),
            "external_id": self.external_id,
            "email": self.email,
            "display_name": self.display_name,
            "is_human": self.is_human,
            # GSI1 for querying by account
            "GSI1PK": build_gsi1_pk(EntityType.ACCOUNT.value, self.account_id),
            "GSI1SK": build_gsi1_sk(EntityType.PRINCIPAL.value, self.principal_id),
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> "Principal":
        return cls(
            principal_id=UUID(item["principal_id"]),
            account_id=UUID(item["account_id"]),
            org_id=UUID(item["org_id"]),
            provider=Provider(item["provider"]),
            principal_type=PrincipalType(item["principal_type"]),
            external_id=item["external_id"],
            email=item.get("email"),
            display_name=item.get("display_name"),
            is_human=item.get("is_human"),
        )


class Resource(DynamoDBModel):
    """Resource entity - cloud/SaaS objects."""

    resource_id: UUID = Field(default_factory=uuid4)
    account_id: UUID
    org_id: UUID
    provider: Provider
    resource_type: str
    external_id: str
    name: Optional[str] = None
    parent_external_id: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def get_pk(self) -> str:
        return build_pk(EntityType.ORG.value, self.org_id)

    def get_sk(self) -> str:
        return build_sk(EntityType.RESOURCE.value, self.resource_id)

    def to_dynamodb_item(self) -> Dict[str, Any]:
        return {
            "PK": self.get_pk(),
            "SK": self.get_sk(),
            "entity_type": EntityType.RESOURCE.value,
            "resource_id": str(self.resource_id),
            "account_id": str(self.account_id),
            "org_id": str(self.org_id),
            "provider": (
                self.provider.value
                if isinstance(self.provider, Enum)
                else self.provider
            ),
            "resource_type": self.resource_type,
            "external_id": self.external_id,
            "name": self.name,
            "parent_external_id": self.parent_external_id,
            "created_at": self.created_at.isoformat(),
            # GSI1 for querying by account
            "GSI1PK": build_gsi1_pk(EntityType.ACCOUNT.value, self.account_id),
            "GSI1SK": build_gsi1_sk(EntityType.RESOURCE.value, self.resource_id),
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> "Resource":
        return cls(
            resource_id=UUID(item["resource_id"]),
            account_id=UUID(item["account_id"]),
            org_id=UUID(item["org_id"]),
            provider=Provider(item["provider"]),
            resource_type=item["resource_type"],
            external_id=item["external_id"],
            name=item.get("name"),
            parent_external_id=item.get("parent_external_id"),
            created_at=datetime.fromisoformat(item["created_at"]),
        )


class Rule(DynamoDBModel):
    """Rule entity - CEL/SQL/Rego rule expressions (global, not org-scoped)."""

    rule_id: UUID = Field(default_factory=uuid4)
    policy_id: Optional[UUID] = None
    name: str
    description: Optional[str] = None
    provider: List[str]
    resource_types: Optional[List[str]] = None
    expression_lang: ExpressionLang
    expression: str
    severity: Severity
    cwe: Optional[List[str]] = None
    cis: Optional[List[str]] = None
    nist_800_53: Optional[List[str]] = None
    mitre_attack: Optional[List[str]] = None
    version: int = 1
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def get_pk(self) -> str:
        return build_pk(EntityType.RULE.value, self.rule_id)

    def get_sk(self) -> str:
        return build_sk(EntityType.RULE.value, self.rule_id)

    def to_dynamodb_item(self) -> Dict[str, Any]:
        return {
            "PK": self.get_pk(),
            "SK": self.get_sk(),
            "entity_type": EntityType.RULE.value,
            "rule_id": str(self.rule_id),
            "policy_id": str(self.policy_id) if self.policy_id else None,
            "name": self.name,
            "description": self.description,
            "provider": self.provider,
            "resource_types": self.resource_types,
            "expression_lang": (
                self.expression_lang.value
                if isinstance(self.expression_lang, Enum)
                else self.expression_lang
            ),
            "expression": self.expression,
            "severity": (
                self.severity.value
                if isinstance(self.severity, Enum)
                else self.severity
            ),
            "cwe": self.cwe,
            "cis": self.cis,
            "nist_800_53": self.nist_800_53,
            "mitre_attack": self.mitre_attack,
            "version": self.version,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
            # GSI1 for listing active rules
            "GSI1PK": f"RULE#ACTIVE#{self.is_active}",
            "GSI1SK": f"SEVERITY#{self.severity.value if isinstance(self.severity, Enum) else self.severity}#{self.rule_id}",
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> "Rule":
        return cls(
            rule_id=UUID(item["rule_id"]),
            policy_id=UUID(item["policy_id"]) if item.get("policy_id") else None,
            name=item["name"],
            description=item.get("description"),
            provider=item["provider"],
            resource_types=item.get("resource_types"),
            expression_lang=ExpressionLang(item["expression_lang"]),
            expression=item["expression"],
            severity=Severity(item["severity"]),
            cwe=item.get("cwe"),
            cis=item.get("cis"),
            nist_800_53=item.get("nist_800_53"),
            mitre_attack=item.get("mitre_attack"),
            version=item.get("version", 1),
            is_active=item.get("is_active", True),
            created_at=datetime.fromisoformat(item["created_at"]),
        )


class Finding(DynamoDBModel):
    """Finding entity - materialized misconfigurations or violations."""

    finding_id: UUID = Field(default_factory=uuid4)
    org_id: UUID
    account_id: UUID
    provider: Provider
    rule_id: UUID
    rule_version: int
    resource_id: Optional[UUID] = None
    principal_id: Optional[UUID] = None
    first_seen: datetime
    last_seen: datetime
    status: FindingStatus = FindingStatus.OPEN
    severity: Severity
    fingerprint: str
    title: str
    summary: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None

    def get_pk(self) -> str:
        return build_pk(EntityType.ORG.value, self.org_id)

    def get_sk(self) -> str:
        return build_sk(EntityType.FINDING.value, self.finding_id)

    def to_dynamodb_item(self) -> Dict[str, Any]:
        status_val = self.status.value if isinstance(self.status, Enum) else self.status
        severity_val = (
            self.severity.value if isinstance(self.severity, Enum) else self.severity
        )
        provider_val = (
            self.provider.value if isinstance(self.provider, Enum) else self.provider
        )

        return {
            "PK": self.get_pk(),
            "SK": self.get_sk(),
            "entity_type": EntityType.FINDING.value,
            "finding_id": str(self.finding_id),
            "org_id": str(self.org_id),
            "account_id": str(self.account_id),
            "provider": provider_val,
            "rule_id": str(self.rule_id),
            "rule_version": self.rule_version,
            "resource_id": str(self.resource_id) if self.resource_id else None,
            "principal_id": str(self.principal_id) if self.principal_id else None,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "status": status_val,
            "severity": severity_val,
            "fingerprint": self.fingerprint,
            "title": self.title,
            "summary": self.summary,
            "evidence": self.evidence,
            # GSI1 for querying by rule
            "GSI1PK": build_gsi1_pk(EntityType.RULE.value, self.rule_id),
            "GSI1SK": build_gsi1_sk(EntityType.FINDING.value, self.finding_id),
            # GSI2 for querying by status/severity
            "GSI2PK": f"ORG#{self.org_id}#STATUS#{status_val}",
            "GSI2SK": f"SEVERITY#{severity_val}#{self.finding_id}",
            # GSI3 for querying by last_seen timestamp
            "GSI3PK": f"ORG#{self.org_id}",
            "GSI3SK": f"LAST_SEEN#{self.last_seen.isoformat()}",
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> "Finding":
        return cls(
            finding_id=UUID(item["finding_id"]),
            org_id=UUID(item["org_id"]),
            account_id=UUID(item["account_id"]),
            provider=Provider(item["provider"]),
            rule_id=UUID(item["rule_id"]),
            rule_version=item["rule_version"],
            resource_id=UUID(item["resource_id"]) if item.get("resource_id") else None,
            principal_id=(
                UUID(item["principal_id"]) if item.get("principal_id") else None
            ),
            first_seen=datetime.fromisoformat(item["first_seen"]),
            last_seen=datetime.fromisoformat(item["last_seen"]),
            status=FindingStatus(item["status"]),
            severity=Severity(item["severity"]),
            fingerprint=item["fingerprint"],
            title=item["title"],
            summary=item.get("summary"),
            evidence=item.get("evidence"),
        )


class Policy(DynamoDBModel):
    """Policy entity - policy frameworks."""

    policy_id: UUID = Field(default_factory=uuid4)
    org_id: UUID
    name: str
    description: Optional[str] = None
    framework: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def get_pk(self) -> str:
        return build_pk(EntityType.ORG.value, self.org_id)

    def get_sk(self) -> str:
        return build_sk(EntityType.POLICY.value, self.policy_id)

    def to_dynamodb_item(self) -> Dict[str, Any]:
        return {
            "PK": self.get_pk(),
            "SK": self.get_sk(),
            "entity_type": EntityType.POLICY.value,
            "policy_id": str(self.policy_id),
            "org_id": str(self.org_id),
            "name": self.name,
            "description": self.description,
            "framework": self.framework,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> "Policy":
        return cls(
            policy_id=UUID(item["policy_id"]),
            org_id=UUID(item["org_id"]),
            name=item["name"],
            description=item.get("description"),
            framework=item.get("framework"),
            created_at=datetime.fromisoformat(item["created_at"]),
        )


class Suppression(DynamoDBModel):
    """Suppression entity - scoped suppressions or risk acceptances."""

    suppression_id: UUID = Field(default_factory=uuid4)
    org_id: UUID
    rule_id: Optional[UUID] = None
    resource_pattern: Optional[str] = None
    principal_pattern: Optional[str] = None
    reason: str
    expires_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def get_pk(self) -> str:
        return build_pk(EntityType.ORG.value, self.org_id)

    def get_sk(self) -> str:
        return build_sk(EntityType.SUPPRESSION.value, self.suppression_id)

    def to_dynamodb_item(self) -> Dict[str, Any]:
        return {
            "PK": self.get_pk(),
            "SK": self.get_sk(),
            "entity_type": EntityType.SUPPRESSION.value,
            "suppression_id": str(self.suppression_id),
            "org_id": str(self.org_id),
            "rule_id": str(self.rule_id) if self.rule_id else None,
            "resource_pattern": self.resource_pattern,
            "principal_pattern": self.principal_pattern,
            "reason": self.reason,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> "Suppression":
        return cls(
            suppression_id=UUID(item["suppression_id"]),
            org_id=UUID(item["org_id"]),
            rule_id=UUID(item["rule_id"]) if item.get("rule_id") else None,
            resource_pattern=item.get("resource_pattern"),
            principal_pattern=item.get("principal_pattern"),
            reason=item["reason"],
            expires_at=(
                datetime.fromisoformat(item["expires_at"])
                if item.get("expires_at")
                else None
            ),
            created_at=datetime.fromisoformat(item["created_at"]),
        )


class ConfigSnapshot(DynamoDBModel):
    """Config snapshot entity - append-only configuration captures (stored in audit table)."""

    snapshot_id: UUID = Field(default_factory=uuid4)
    resource_id: UUID
    org_id: UUID
    captured_at: datetime
    config_sha: str  # Hex string instead of bytes for DynamoDB
    normalized_config: Dict[str, Any]
    collector_version: str

    def get_pk(self) -> str:
        return build_pk(EntityType.RESOURCE.value, self.resource_id)

    def get_sk(self) -> str:
        return f"CONFIG_SNAPSHOT#{self.captured_at.isoformat()}#{self.snapshot_id}"

    def to_dynamodb_item(self) -> Dict[str, Any]:
        return {
            "PK": self.get_pk(),
            "SK": self.get_sk(),
            "entity_type": EntityType.CONFIG_SNAPSHOT.value,
            "snapshot_id": str(self.snapshot_id),
            "resource_id": str(self.resource_id),
            "org_id": str(self.org_id),
            "captured_at": self.captured_at.isoformat(),
            "config_sha": self.config_sha,
            "normalized_config": self.normalized_config,
            "collector_version": self.collector_version,
            # GSI1 for querying by org and time
            "GSI1PK": f"ORG#{self.org_id}#CONFIG",
            "GSI1SK": f"CAPTURED#{self.captured_at.isoformat()}",
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> "ConfigSnapshot":
        return cls(
            snapshot_id=UUID(item["snapshot_id"]),
            resource_id=UUID(item["resource_id"]),
            org_id=UUID(item["org_id"]),
            captured_at=datetime.fromisoformat(item["captured_at"]),
            config_sha=item["config_sha"],
            normalized_config=item["normalized_config"],
            collector_version=item["collector_version"],
        )


class IamEdge(DynamoDBModel):
    """IAM edge entity - effective permissions between principals and resources."""

    edge_id: UUID = Field(default_factory=uuid4)
    account_id: UUID
    org_id: UUID
    provider: Provider
    principal_id: UUID
    resource_id: Optional[UUID] = None
    permission: str
    via: Optional[str] = None
    effective_at: datetime
    expires_at: Optional[datetime] = None
    is_admin: bool = False

    def get_pk(self) -> str:
        return build_pk(EntityType.ORG.value, self.org_id)

    def get_sk(self) -> str:
        return build_sk(EntityType.IAM_EDGE.value, self.edge_id)

    def to_dynamodb_item(self) -> Dict[str, Any]:
        provider_val = (
            self.provider.value if isinstance(self.provider, Enum) else self.provider
        )

        return {
            "PK": self.get_pk(),
            "SK": self.get_sk(),
            "entity_type": EntityType.IAM_EDGE.value,
            "edge_id": str(self.edge_id),
            "account_id": str(self.account_id),
            "org_id": str(self.org_id),
            "provider": provider_val,
            "principal_id": str(self.principal_id),
            "resource_id": str(self.resource_id) if self.resource_id else None,
            "permission": self.permission,
            "via": self.via,
            "effective_at": self.effective_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_admin": self.is_admin,
            # GSI1 for querying by principal
            "GSI1PK": build_gsi1_pk(EntityType.PRINCIPAL.value, self.principal_id),
            "GSI1SK": build_gsi1_sk(EntityType.IAM_EDGE.value, self.edge_id),
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> "IamEdge":
        return cls(
            edge_id=UUID(item["edge_id"]),
            account_id=UUID(item["account_id"]),
            org_id=UUID(item["org_id"]),
            provider=Provider(item["provider"]),
            principal_id=UUID(item["principal_id"]),
            resource_id=UUID(item["resource_id"]) if item.get("resource_id") else None,
            permission=item["permission"],
            via=item.get("via"),
            effective_at=datetime.fromisoformat(item["effective_at"]),
            expires_at=(
                datetime.fromisoformat(item["expires_at"])
                if item.get("expires_at")
                else None
            ),
            is_admin=item.get("is_admin", False),
        )


class AuditEvent(DynamoDBModel):
    """Audit event entity - append-only audit logs (stored in audit table with TTL)."""

    event_id: UUID = Field(default_factory=uuid4)
    account_id: UUID
    org_id: UUID
    provider: Provider
    occurred_at: datetime
    actor_external_id: Optional[str] = None
    action: str
    resource_external_id: Optional[str] = None
    raw: Dict[str, Any]
    ttl: Optional[int] = None  # Unix timestamp for automatic expiration

    def get_pk(self) -> str:
        return build_pk(EntityType.ACCOUNT.value, self.account_id)

    def get_sk(self) -> str:
        return f"AUDIT#{self.occurred_at.isoformat()}#{self.event_id}"

    def to_dynamodb_item(self) -> Dict[str, Any]:
        provider_val = (
            self.provider.value if isinstance(self.provider, Enum) else self.provider
        )

        item = {
            "PK": self.get_pk(),
            "SK": self.get_sk(),
            "entity_type": EntityType.AUDIT_EVENT.value,
            "event_id": str(self.event_id),
            "account_id": str(self.account_id),
            "org_id": str(self.org_id),
            "provider": provider_val,
            "occurred_at": self.occurred_at.isoformat(),
            "actor_external_id": self.actor_external_id,
            "action": self.action,
            "resource_external_id": self.resource_external_id,
            "raw": self.raw,
            # GSI1 for querying by org and time
            "GSI1PK": f"ORG#{self.org_id}#AUDIT",
            "GSI1SK": f"OCCURRED#{self.occurred_at.isoformat()}",
        }

        if self.ttl:
            item["ttl"] = self.ttl

        return item

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> "AuditEvent":
        return cls(
            event_id=UUID(item["event_id"]),
            account_id=UUID(item["account_id"]),
            org_id=UUID(item["org_id"]),
            provider=Provider(item["provider"]),
            occurred_at=datetime.fromisoformat(item["occurred_at"]),
            actor_external_id=item.get("actor_external_id"),
            action=item["action"],
            resource_external_id=item.get("resource_external_id"),
            raw=item["raw"],
            ttl=item.get("ttl"),
        )
