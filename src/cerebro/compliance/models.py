"""
Unified evidence and compliance models with proper inheritance hierarchy.

Consolidates the 3 different EvidenceMetadata definitions and provides
a single, extensible model architecture for all compliance use cases.
"""

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any
from uuid import uuid4


class EvidenceStatus(Enum):
    """Lifecycle status of evidence items."""

    PENDING = "pending"
    COLLECTING = "collecting"
    COLLECTED = "collected"
    VERIFIED = "verified"
    SEALED = "sealed"
    ARCHIVED = "archived"
    EXPIRED = "expired"


class EvidenceCategory(Enum):
    """Standardized evidence categories."""

    CONFIGURATION = "configuration"
    ACCESS_LOG = "access_log"
    AUDIT_LOG = "audit_log"
    CONTROL_TEST = "control_test"
    POLICY_DOCUMENT = "policy_document"
    ATTESTATION = "attestation"
    SCREENSHOT = "screenshot"
    SYSTEM_REPORT = "system_report"
    VULNERABILITY_SCAN = "vulnerability_scan"
    INCIDENT_REPORT = "incident_report"
    TRAINING_RECORD = "training_record"
    BACKGROUND_CHECK = "background_check"
    VENDOR_ASSESSMENT = "vendor_assessment"
    CUSTOMER_PROFILE = "customer_profile"


class EvidenceCollectionMethod(Enum):
    """How the evidence was collected."""

    API_QUERY = "api_query"
    SQL_QUERY = "sql_query"
    FILE_UPLOAD = "file_upload"
    SCREENSHOT = "screenshot"
    MANUAL_ENTRY = "manual_entry"
    AUTOMATED_SCAN = "automated_scan"
    INTEGRATION = "integration"


class RetentionClass(Enum):
    """Evidence retention classification."""

    STANDARD = "standard"  # 3 years
    LONG_TERM = "long_term"  # 7 years
    PERMANENT = "permanent"  # Indefinite
    GDPR_RESTRICTED = "gdpr_restricted"  # Special handling


@dataclass
class ChainOfCustodyEntry:
    """Single entry in the chain of custody."""

    action: str
    actor_id: str
    actor_type: str  # "user", "system", "integration"
    timestamp: datetime
    details: dict[str, Any] = field(default_factory=dict)
    ip_address: str | None = None
    location: str | None = None


@dataclass
class CryptographicProof:
    """Cryptographic integrity proof for evidence."""

    content_hash: str  # SHA-256 of content
    signature: str | None = None
    signature_algorithm: str | None = None
    timestamp_token: str | None = None  # RFC 3161 timestamp
    merkle_root: str | None = None  # For transparency log inclusion
    chain_hash: str | None = None  # Links to previous evidence


@dataclass
class BaseEvidenceMetadata:
    """Base evidence metadata - foundation for all evidence types."""

    # Core identification
    id: str = field(default_factory=lambda: str(uuid4()))
    category: EvidenceCategory = EvidenceCategory.SYSTEM_REPORT
    content_type: str = "application/json"

    # Collection context
    collector_id: str = "system"
    collector_type: str = "automated"
    collection_method: EvidenceCollectionMethod = EvidenceCollectionMethod.API_QUERY
    source_system: str | None = None  # "okta", "aws", "github", etc.

    # Content properties
    content_size: int = 0
    content_hash: str | None = None

    # Lifecycle timestamps
    created_at: datetime = field(default_factory=datetime.utcnow)
    collected_at: datetime | None = None
    verified_at: datetime | None = None
    sealed_at: datetime | None = None

    # Status and classification
    status: EvidenceStatus = EvidenceStatus.PENDING
    retention_class: RetentionClass = RetentionClass.STANDARD
    expires_at: datetime | None = None

    # Security and integrity
    crypto_proof: CryptographicProof | None = None
    chain_of_custody: list[ChainOfCustodyEntry] = field(default_factory=list)

    # Data classification
    pii_detected: bool = False
    sensitivity_level: str = (
        "internal"  # "public", "internal", "confidential", "restricted"
    )
    encryption_required: bool = False

    # Relationships and context
    tags: dict[str, str] = field(default_factory=dict)
    related_evidence_ids: list[str] = field(default_factory=list)
    parent_bundle_id: str | None = None

    def add_custody_entry(
        self, action: str, actor_id: str, actor_type: str = "user", **details: Any
    ) -> None:
        """Add an entry to the chain of custody."""
        entry = ChainOfCustodyEntry(
            action=action,
            actor_id=actor_id,
            actor_type=actor_type,
            timestamp=datetime.utcnow(),
            details=details,
        )
        self.chain_of_custody.append(entry)

    def calculate_content_hash(self, content: str | bytes | dict) -> str:
        """Calculate and set content hash."""
        if isinstance(content, dict):
            content_str = json.dumps(content, sort_keys=True)
            content_bytes = content_str.encode("utf-8")
        elif isinstance(content, str):
            content_bytes = content.encode("utf-8")
        else:
            content_bytes = content

        self.content_hash = hashlib.sha256(content_bytes).hexdigest()
        self.content_size = len(content_bytes)
        return self.content_hash

    def set_retention_period(self, years: int | None = None) -> None:
        """Set retention period based on classification."""
        if years:
            self.expires_at = self.created_at + timedelta(days=years * 365)
        else:
            # Set based on retention class
            retention_periods = {
                RetentionClass.STANDARD: 3,
                RetentionClass.LONG_TERM: 7,
                RetentionClass.GDPR_RESTRICTED: 2,
                RetentionClass.PERMANENT: None,
            }
            period = retention_periods.get(self.retention_class)
            if period:
                self.expires_at = self.created_at + timedelta(days=period * 365)


@dataclass
class ComplianceEvidenceMetadata(BaseEvidenceMetadata):
    """Evidence metadata for compliance controls."""

    # Compliance context
    control_id: str | None = None
    framework_name: str | None = None
    control_family: str | None = None
    test_run_id: str | None = None

    # Assessment context
    audit_period_start: datetime | None = None
    audit_period_end: datetime | None = None
    assessment_type: str = "continuous"  # "continuous", "point_in_time", "historical"

    # Collection query context
    query_used: str | None = None
    query_execution_time_ms: int | None = None
    data_source_tables: list[str] = field(default_factory=list)

    # Compliance status
    control_status: str = (
        "testing"  # "compliant", "non_compliant", "testing", "not_applicable"
    )
    findings_count: int = 0
    exceptions_count: int = 0

    # Remediation
    remediation_required: bool = False
    remediation_priority: str = "medium"  # "low", "medium", "high", "critical"
    remediation_due_date: datetime | None = None


@dataclass
class ForensicEvidenceMetadata(BaseEvidenceMetadata):
    """Evidence metadata for forensic investigations."""

    # Investigation context
    incident_id: str | None = None
    investigation_id: str | None = None
    case_number: str | None = None

    # Legal context
    legal_hold: bool = False
    attorney_client_privilege: bool = False
    work_product_protection: bool = False

    # Forensic properties
    acquisition_method: str = (
        "live_api"  # "live_api", "disk_image", "memory_dump", "network_capture"
    )
    evidence_integrity_verified: bool = False
    hash_verification_passed: bool = False

    # Timeline context
    event_start_time: datetime | None = None
    event_end_time: datetime | None = None
    investigation_priority: str = "medium"


@dataclass
class AuditEvidenceMetadata(BaseEvidenceMetadata):
    """Evidence metadata for external audits."""

    # Audit context
    audit_firm: str | None = None
    audit_engagement_id: str | None = None
    auditor_request_id: str | None = None

    # Audit period and scope
    audit_year: int | None = None
    audit_quarter: str | None = None
    audit_scope: list[str] = field(
        default_factory=list
    )  # Business units, systems, processes

    # Delivery and access
    provided_to_auditor: bool = False
    auditor_access_granted: bool = False
    access_granted_to: list[str] = field(default_factory=list)
    delivery_method: str = (
        "secure_portal"  # "secure_portal", "encrypted_email", "physical_media"
    )

    # Review status
    auditor_reviewed: bool = False
    audit_findings: list[str] = field(default_factory=list)
    management_responses: list[str] = field(default_factory=list)


@dataclass
class VendorEvidenceMetadata(BaseEvidenceMetadata):
    """Metadata describing third-party vendor posture and relationship."""

    vendor_id: str = ""
    vendor_name: str = ""
    risk_level: str = "medium"
    inherent_risk_score: float = 0.0
    residual_risk_score: float = 0.0
    business_criticality: str = "medium"
    vendor_category: str | None = None
    data_types_processed: list[str] = field(default_factory=list)
    certifications: list[str] = field(default_factory=list)
    compliance_frameworks: list[str] = field(default_factory=list)
    last_assessment_date: datetime | None = None
    next_review_due: datetime | None = None
    contract_end_date: datetime | None = None
    lifecycle_stage: str = "active"
    relationship_owner: str | None = None
    service_regions: list[str] = field(default_factory=list)
    primary_contacts: list[str] = field(default_factory=list)
    access_monitoring_enabled: bool = False
    security_alerts_configured: bool = False
    incident_count_last_year: int = 0


@dataclass
class CustomerEvidenceMetadata(BaseEvidenceMetadata):
    """Metadata summarizing customer account health and lifecycle."""

    customer_id: str = ""
    customer_name: str = ""
    segment: str = "commercial"
    industry: str | None = None
    region: str | None = None
    lifecycle_stage: str = "active"
    health_score: float = 0.0
    churn_risk_score: float = 0.0
    account_manager: str | None = None
    annual_recurring_revenue: float | None = None
    seats_committed: int | None = None
    adoption_metrics: dict[str, float] = field(default_factory=dict)
    last_engagement_at: datetime | None = None
    next_qbr_at: datetime | None = None
    support_tickets_open: int = 0
    advocacy_level: str = "neutral"
    success_programs: list[str] = field(default_factory=list)


@dataclass
class EvidenceBundle:
    """Collection of related evidence items for delivery/audit."""

    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    bundle_type: str = "compliance"  # "compliance", "audit", "forensic", "legal"

    # Framework and scope
    framework_name: str | None = None
    control_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)

    # Time period
    period_start: datetime | None = None
    period_end: datetime | None = None

    # Bundle metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    created_by: str = ""
    organization_id: str | None = None

    # Integrity and security
    bundle_hash: str | None = None
    manifest: dict[str, Any] = field(default_factory=dict)
    sealed: bool = False

    # Delivery and access
    exported_at: datetime | None = None
    export_format: str = "zip"
    access_granted_to: list[str] = field(default_factory=list)
    delivery_confirmation: str | None = None

    # Compliance and retention
    retention_years: int = 7
    legal_hold: bool = False
    destruction_date: datetime | None = None

    def add_evidence(self, evidence_id: str) -> None:
        """Add evidence to bundle."""
        if evidence_id not in self.evidence_ids:
            self.evidence_ids.append(evidence_id)

    def calculate_bundle_hash(self, evidence_hashes: list[str]) -> str:
        """Calculate hash of all evidence in bundle."""
        combined = ":".join(sorted(evidence_hashes))
        self.bundle_hash = hashlib.sha256(combined.encode()).hexdigest()
        return self.bundle_hash

    def seal_bundle(self) -> None:
        """Mark bundle as sealed (immutable)."""
        self.sealed = True
        self.manifest["sealed_at"] = datetime.utcnow().isoformat()


class EvidenceRepository(ABC):
    """Abstract interface for evidence storage backends."""

    @abstractmethod
    async def store_evidence(
        self, content: bytes, metadata: BaseEvidenceMetadata
    ) -> str:
        """Store evidence and return evidence ID."""
        pass

    @abstractmethod
    async def get_evidence(
        self, evidence_id: str
    ) -> tuple[bytes, BaseEvidenceMetadata] | None:
        """Retrieve evidence content and metadata."""
        pass

    @abstractmethod
    async def get_metadata(self, evidence_id: str) -> BaseEvidenceMetadata | None:
        """Get evidence metadata only."""
        pass

    @abstractmethod
    async def search_evidence(self, **filters: Any) -> list[BaseEvidenceMetadata]:
        """Search evidence by filters."""
        pass

    @abstractmethod
    async def create_bundle(self, bundle: EvidenceBundle) -> str:
        """Create evidence bundle."""
        pass

    @abstractmethod
    async def get_bundle(self, bundle_id: str) -> EvidenceBundle | None:
        """Get evidence bundle."""
        pass


# Factory functions for creating evidence metadata
def create_compliance_evidence(
    control_id: str, framework_name: str, **kwargs: Any
) -> ComplianceEvidenceMetadata:
    """Create compliance evidence metadata."""
    metadata = ComplianceEvidenceMetadata(
        control_id=control_id,
        framework_name=framework_name,
        category=EvidenceCategory.CONTROL_TEST,
        **kwargs,
    )
    metadata.add_custody_entry("created", "system", "system")
    return metadata


def create_forensic_evidence(incident_id: str, **kwargs: Any) -> ForensicEvidenceMetadata:
    """Create forensic evidence metadata."""
    metadata = ForensicEvidenceMetadata(
        incident_id=incident_id,
        category=EvidenceCategory.AUDIT_LOG,
        retention_class=RetentionClass.LONG_TERM,
        **kwargs,
    )
    metadata.add_custody_entry("created", "system", "system")
    return metadata


def create_audit_evidence(audit_firm: str, **kwargs: Any) -> AuditEvidenceMetadata:
    """Create audit evidence metadata."""
    metadata = AuditEvidenceMetadata(
        audit_firm=audit_firm,
        category=EvidenceCategory.SYSTEM_REPORT,
        retention_class=RetentionClass.LONG_TERM,
        **kwargs,
    )
    metadata.add_custody_entry("created", "system", "system")
    return metadata


def create_vendor_evidence(
    vendor_id: str,
    vendor_name: str,
    *,
    created_by: str,
    risk_level: str = "medium",
    inherent_risk_score: float = 0.0,
    residual_risk_score: float = 0.0,
    business_criticality: str = "medium",
    vendor_category: str | None = None,
    data_types_processed: list[str] | None = None,
    certifications: list[str] | None = None,
    compliance_frameworks: list[str] | None = None,
    last_assessment_date: datetime | None = None,
    next_review_due: datetime | None = None,
    contract_end_date: datetime | None = None,
    lifecycle_stage: str = "active",
    relationship_owner: str | None = None,
    service_regions: list[str] | None = None,
    primary_contacts: list[str] | None = None,
    access_monitoring_enabled: bool = False,
    security_alerts_configured: bool = False,
    incident_count_last_year: int = 0,
    source_system: str | None = "vendor_registry",
    collector_id: str | None = None,
    collector_type: str | None = None,
    collection_method: EvidenceCollectionMethod | None = None,
    tags: dict[str, str] | None = None,
) -> VendorEvidenceMetadata:
    """Create vendor evidence metadata with rich risk and compliance context."""

    tag_payload = {"vendor_id": vendor_id, "entity_type": "vendor"}
    if vendor_category:
        tag_payload["vendor_category"] = vendor_category
    tag_payload["risk_level"] = risk_level
    tag_payload["business_criticality"] = business_criticality
    if tags:
        tag_payload.update(tags)

    metadata = VendorEvidenceMetadata(
        vendor_id=vendor_id,
        vendor_name=vendor_name,
        risk_level=risk_level,
        inherent_risk_score=inherent_risk_score,
        residual_risk_score=residual_risk_score,
        business_criticality=business_criticality,
        vendor_category=vendor_category,
        data_types_processed=data_types_processed or [],
        certifications=certifications or [],
        compliance_frameworks=compliance_frameworks or [],
        last_assessment_date=last_assessment_date,
        next_review_due=next_review_due,
        contract_end_date=contract_end_date,
        lifecycle_stage=lifecycle_stage,
        relationship_owner=relationship_owner,
        service_regions=service_regions or [],
        primary_contacts=primary_contacts or [],
        access_monitoring_enabled=access_monitoring_enabled,
        security_alerts_configured=security_alerts_configured,
        incident_count_last_year=incident_count_last_year,
        category=EvidenceCategory.VENDOR_ASSESSMENT,
        source_system=source_system,
        collector_id=collector_id or "vendor_registry",
        collector_type=collector_type or "automated",
        collection_method=collection_method or EvidenceCollectionMethod.INTEGRATION,
        tags=tag_payload,
    )
    metadata.add_custody_entry("created", created_by, "system")
    return metadata


def create_customer_evidence(
    customer_id: str,
    customer_name: str,
    *,
    created_by: str,
    segment: str = "commercial",
    industry: str | None = None,
    region: str | None = None,
    lifecycle_stage: str = "active",
    health_score: float = 0.0,
    churn_risk_score: float = 0.0,
    account_manager: str | None = None,
    annual_recurring_revenue: float | None = None,
    seats_committed: int | None = None,
    adoption_metrics: dict[str, float] | None = None,
    last_engagement_at: datetime | None = None,
    next_qbr_at: datetime | None = None,
    support_tickets_open: int = 0,
    advocacy_level: str = "neutral",
    success_programs: list[str] | None = None,
    source_system: str | None = "customer_registry",
    collector_id: str | None = None,
    collector_type: str | None = None,
    collection_method: EvidenceCollectionMethod | None = None,
    tags: dict[str, str] | None = None,
) -> CustomerEvidenceMetadata:
    """Create customer evidence metadata capturing account health signals."""

    tag_payload = {
        "customer_id": customer_id,
        "entity_type": "customer",
        "segment": segment,
    }
    if tags:
        tag_payload.update(tags)

    metadata = CustomerEvidenceMetadata(
        customer_id=customer_id,
        customer_name=customer_name,
        segment=segment,
        industry=industry,
        region=region,
        lifecycle_stage=lifecycle_stage,
        health_score=health_score,
        churn_risk_score=churn_risk_score,
        account_manager=account_manager,
        annual_recurring_revenue=annual_recurring_revenue,
        seats_committed=seats_committed,
        adoption_metrics=adoption_metrics or {},
        last_engagement_at=last_engagement_at,
        next_qbr_at=next_qbr_at,
        support_tickets_open=support_tickets_open,
        advocacy_level=advocacy_level,
        success_programs=success_programs or [],
        category=EvidenceCategory.CUSTOMER_PROFILE,
        source_system=source_system,
        collector_id=collector_id or "customer_registry",
        collector_type=collector_type or "automated",
        collection_method=collection_method or EvidenceCollectionMethod.INTEGRATION,
        tags=tag_payload,
    )
    metadata.add_custody_entry("created", created_by, "system")
    return metadata


def metadata_to_dict(metadata: BaseEvidenceMetadata) -> dict[str, Any]:
    """Serialize evidence metadata into JSON-friendly dictionary."""

    def _convert(value: Any) -> Any:
        if isinstance(value, Enum):
            return value.value
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, list):
            return [_convert(item) for item in value]
        if isinstance(value, dict):
            return {key: _convert(val) for key, val in value.items()}
        return value

    raw = asdict(metadata)
    result = _convert(raw)
    # asdict always returns a dict, so _convert will return a dict
    assert isinstance(result, dict)
    return result
