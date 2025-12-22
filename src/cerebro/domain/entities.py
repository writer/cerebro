"""Domain entities - pure data structures without infrastructure dependencies."""

from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID, uuid4
from enum import Enum


class PrincipalType(str, Enum):
    """Principal types."""

    USER = "user"
    GROUP = "group"
    SERVICE_ACCOUNT = "service_account"
    APP = "app"
    ROLE = "role"


class FindingStatus(str, Enum):
    """Finding status types."""

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


@dataclass(frozen=True)
class ResourceEntity:
    """Domain entity representing a cloud/SaaS resource."""

    external_id: str
    resource_type: str
    provider: str
    name: Optional[str] = None
    parent_external_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        """Validate resource entity."""
        if not self.external_id or not self.resource_type or not self.provider:
            raise ValueError("external_id, resource_type, and provider are required")


@dataclass(frozen=True)
class PrincipalEntity:
    """Domain entity representing a user, group, or service account."""

    external_id: str
    principal_type: PrincipalType
    provider: str
    email: Optional[str] = None
    display_name: Optional[str] = None
    is_human: Optional[bool] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate principal entity."""
        if not self.external_id or not self.provider:
            raise ValueError("external_id and provider are required")

        # Validate email format if provided
        if self.email and "@" not in self.email:
            raise ValueError("Invalid email format")


@dataclass(frozen=True)
class ConfigEntity:
    """Domain entity representing resource configuration."""

    resource_external_id: str
    captured_at: datetime
    normalized_config: Dict[str, Any]
    raw_config: Optional[Dict[str, Any]] = None
    collector_version: str = "1.0.0"
    config_hash: Optional[str] = None

    def __post_init__(self):
        """Validate config entity."""
        if not self.resource_external_id or not self.normalized_config:
            raise ValueError("resource_external_id and normalized_config are required")


@dataclass(frozen=True)
class IamPermissionEntity:
    """Domain entity representing an IAM permission edge."""

    principal_external_id: str
    permission: str
    resource_external_id: Optional[str] = None
    via: Optional[str] = None
    effective_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    is_admin: bool = False
    confidence: float = 1.0  # Confidence score for inferred permissions

    def __post_init__(self):
        """Validate IAM permission."""
        if not self.principal_external_id or not self.permission:
            raise ValueError("principal_external_id and permission are required")

        if (
            self.expires_at
            and self.effective_at
            and self.expires_at <= self.effective_at
        ):
            raise ValueError("expires_at must be after effective_at")


@dataclass
class FindingEntity:
    """Domain entity representing a security finding."""

    rule_id: UUID
    resource_external_id: Optional[str] = None
    principal_external_id: Optional[str] = None
    title: str = ""
    summary: str = ""
    severity: Severity = Severity.MEDIUM
    status: FindingStatus = FindingStatus.OPEN
    evidence: Dict[str, Any] = field(default_factory=dict)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    fingerprint: Optional[str] = None

    # Domain behavior
    def mark_as_suppressed(self, reason: str) -> None:
        """Mark finding as suppressed."""
        self.status = FindingStatus.SUPPRESSED
        self.evidence["suppression_reason"] = reason
        self.last_seen = datetime.utcnow()

    def accept_risk(self, reason: str) -> None:
        """Accept risk for this finding."""
        self.status = FindingStatus.ACCEPTED_RISK
        self.evidence["risk_acceptance_reason"] = reason
        self.last_seen = datetime.utcnow()

    def mark_as_fixed(self) -> None:
        """Mark finding as fixed."""
        self.status = FindingStatus.FIXED
        self.last_seen = datetime.utcnow()

    def update_last_seen(self) -> None:
        """Update last seen timestamp."""
        self.last_seen = datetime.utcnow()


@dataclass(frozen=True)
class RuleEntity:
    """Domain entity representing a security rule."""

    rule_id: UUID
    name: str
    expression: str
    expression_lang: str = "cel"
    severity: Severity = Severity.MEDIUM
    description: Optional[str] = None
    providers: Set[str] = field(default_factory=set)
    resource_types: Set[str] = field(default_factory=set)
    framework_mappings: Dict[str, List[str]] = field(default_factory=dict)
    is_active: bool = True
    version: int = 1

    def __post_init__(self):
        """Validate rule entity."""
        if not self.name or not self.expression:
            raise ValueError("name and expression are required")

        if self.expression_lang not in ["cel", "sql", "rego"]:
            raise ValueError("expression_lang must be 'cel', 'sql', or 'rego'")


@dataclass
class IdentityClusterEntity:
    """Domain entity representing a cluster of related identities."""

    cluster_id: str
    principals: List[PrincipalEntity] = field(default_factory=list)
    confidence_score: float = 0.0
    stitching_evidence: Dict[str, Any] = field(default_factory=dict)

    def add_principal(
        self, principal: PrincipalEntity, evidence: Dict[str, Any]
    ) -> None:
        """Add a principal to this cluster."""
        if principal not in self.principals:
            self.principals.append(principal)
            self.stitching_evidence[principal.external_id] = evidence

    def calculate_confidence(self) -> float:
        """Calculate overall confidence score for the cluster."""
        if len(self.principals) < 2:
            return 0.0

        # Email matches get high confidence
        emails = {p.email for p in self.principals if p.email}
        if len(emails) == 1 and len(self.principals) > 1:
            self.confidence_score = 0.9

        # Name matches get lower confidence
        names = {p.display_name for p in self.principals if p.display_name}
        if len(names) == 1 and len(self.principals) > 1:
            self.confidence_score = max(self.confidence_score, 0.6)

        return self.confidence_score


@dataclass
class CollectionJobEntity:
    """Domain entity representing a collection job."""

    job_id: UUID = field(default_factory=uuid4)
    org_id: UUID = None
    provider: Optional[str] = None
    resource_types: List[str] = field(default_factory=list)
    status: str = "pending"  # pending, running, completed, failed
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    resources_collected: int = 0
    principals_collected: int = 0
    errors: List[str] = field(default_factory=list)

    def start(self) -> None:
        """Mark job as started."""
        self.status = "running"
        self.started_at = datetime.utcnow()

    def complete(self) -> None:
        """Mark job as completed."""
        self.status = "completed" if not self.errors else "completed_with_errors"
        self.completed_at = datetime.utcnow()

    def fail(self, error: str) -> None:
        """Mark job as failed."""
        self.status = "failed"
        self.completed_at = datetime.utcnow()
        self.errors.append(error)
