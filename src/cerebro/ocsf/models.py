"""
OCSF Data Models

Pydantic models representing OCSF v1.4.0 schema for security events.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Any

from pydantic import BaseModel

# ==================== OCSF Enums ====================


class OCSFSeverity(IntEnum):
    """OCSF Severity Levels."""

    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6


class OCSFStatus(IntEnum):
    """OCSF Activity Status."""

    UNKNOWN = 0
    SUCCESS = 1
    FAILURE = 2


class OCSFActivityID(IntEnum):
    """OCSF Finding Activity IDs (Category 2)."""

    UNKNOWN = 0
    CREATE = 1
    UPDATE = 2
    CLOSE = 3
    REOPEN = 4


class OCSFComplianceStatus(str):
    """OCSF Compliance Status."""

    PASS = "Pass"
    FAIL = "Fail"
    NOT_APPLICABLE = "Not Applicable"
    UNKNOWN = "Unknown"


# ==================== OCSF Base Objects ====================


class OCSFMetadata(BaseModel):
    """OCSF Metadata Object."""

    version: str = "1.4.0"
    product: OCSFProduct
    profiles: list[str] = []
    event_code: str | None = None
    correlation_uid: str | None = None
    log_name: str | None = None
    log_provider: str | None = None
    logged_time: int | None = None  # Unix epoch ms
    original_time: str | None = None


class OCSFProduct(BaseModel):
    """OCSF Product Object."""

    name: str = "Cerebro"
    version: str = "1.0.0"
    vendor_name: str = "Cerebro Security"
    feature: dict[str, Any] | None = None


class OCSFActor(BaseModel):
    """OCSF Actor Object (User/Process/Device)."""

    user: OCSFUser | None = None
    process: OCSFProcess | None = None
    session: dict[str, Any] | None = None
    idp: dict[str, Any] | None = None


class OCSFUser(BaseModel):
    """OCSF User Object."""

    name: str | None = None
    uid: str | None = None
    email_addr: str | None = None
    full_name: str | None = None
    domain: str | None = None
    type: str | None = None
    type_id: int | None = None
    groups: list[dict[str, Any]] | None = None


class OCSFProcess(BaseModel):
    """OCSF Process Object."""

    name: str | None = None
    pid: int | None = None
    file: dict[str, Any] | None = None
    cmd_line: str | None = None
    user: OCSFUser | None = None


class OCSFResource(BaseModel):
    """OCSF Resource Object."""

    name: str | None = None
    uid: str | None = None
    type: str | None = None
    owner: OCSFUser | None = None
    labels: list[str] | None = None
    data: dict[str, Any] | None = None


class OCSFCloud(BaseModel):
    """OCSF Cloud Object."""

    provider: str  # AWS, Azure, GCP, etc.
    region: str | None = None
    account: OCSFAccount | None = None
    org: dict[str, Any] | None = None
    project_uid: str | None = None


class OCSFAccount(BaseModel):
    """OCSF Account Object."""

    name: str | None = None
    type: str | None = None
    type_id: int | None = None
    uid: str | None = None


class OCSFObservables(BaseModel):
    """OCSF Observables Array."""

    name: str
    type: str
    type_id: int
    value: Any
    reputation: dict[str, Any] | None = None


# ==================== OCSF Event Classes ====================


class OCSFEvent(BaseModel):
    """Base OCSF Event."""

    class_uid: int  # Event class UID
    class_name: str  # Event class name
    category_uid: int  # Category UID (1-8)
    category_name: str
    activity_id: int
    activity_name: str
    type_uid: int  # Composite: category_uid * 100 + class_uid
    type_name: str

    time: int  # Unix epoch milliseconds
    message: str
    severity_id: int
    severity: str
    status_id: int | None = None
    status: str | None = None

    metadata: OCSFMetadata
    observables: list[OCSFObservables] | None = []
    unmapped: dict[str, Any] | None = None  # Original data not mapped to OCSF


class OCSFFinding(OCSFEvent):
    """
    OCSF Security Finding (Category 2, Class 2001).

    Represents security findings like vulnerabilities, misconfigurations,
    compliance violations, and other security issues.
    """

    # Override base class defaults
    class_uid: int = 2001
    class_name: str = "Security Finding"
    category_uid: int = 2
    category_name: str = "Findings"

    # Finding-specific fields
    finding_info: OCSFFindingInfo
    resources: list[OCSFResource] | None = []
    remediation: OCSFRemediation | None = None
    compliance: OCSFCompliance | None = None
    vulnerabilities: list[OCSFVulnerability] | None = []

    # Risk and impact
    risk_level: str | None = None
    risk_level_id: int | None = None
    risk_score: int | None = None  # 0-100
    impact: str | None = None
    impact_id: int | None = None

    # Context
    actor: OCSFActor | None = None
    cloud: OCSFCloud | None = None
    confidence: int | None = None  # 0-100
    confidence_id: int | None = None


class OCSFFindingInfo(BaseModel):
    """OCSF Finding Info Object."""

    title: str
    desc: str | None = None
    uid: str
    types: list[str] = []  # e.g., ["Misconfiguration", "Compliance Violation"]
    first_seen_time: int | None = None  # Unix epoch ms
    last_seen_time: int | None = None
    modified_time: int | None = None
    created_time: int | None = None
    analytic: dict[str, Any] | None = None
    src_url: str | None = None  # Link to finding in Cerebro


class OCSFRemediation(BaseModel):
    """OCSF Remediation Object."""

    desc: str
    kb_articles: list[str] | None = []
    references: list[str] | None = []


class OCSFCompliance(BaseModel):
    """OCSF Compliance Object."""

    requirements: list[str] = []  # e.g., ["CIS AWS 1.1", "NIST CSF PR.AC-4"]
    status: str  # Pass, Fail, Not Applicable
    status_detail: str | None = None


class OCSFVulnerability(BaseModel):
    """OCSF Vulnerability Object."""

    cve_uid: str | None = None  # CVE-2024-1234
    cwe_uid: str | None = None  # CWE-79
    title: str | None = None
    desc: str | None = None
    severity: str | None = None
    cvss: dict[str, Any] | None = None  # CVSS scores


class OCSFComplianceFinding(OCSFFinding):
    """
    OCSF Compliance Finding (Category 2, Class 2003).

    Specialized finding for compliance control test results.
    """

    class_uid: int = 2003
    class_name: str = "Compliance Finding"

    # Override to require compliance
    compliance: OCSFCompliance


class OCSFIdentityActivity(OCSFEvent):
    """
    OCSF Identity & Access Management Activity (Category 3).

    Represents IAM-related events like authentication, authorization,
    entity changes, account activity, and group management.
    """

    category_uid: int = 3
    category_name: str = "Identity & Access Management"

    actor: OCSFActor | None = None
    user: OCSFUser | None = None
    group: dict[str, Any] | None = None
    policy: dict[str, Any] | None = None
    privileges: list[str] | None = []
    cloud: OCSFCloud | None = None
    is_mfa: bool | None = None
    auth_protocol: str | None = None
    auth_protocol_id: int | None = None


# ==================== Helper Classes ====================


class OCSFTypeUID:
    """OCSF Type UID Calculator."""

    @staticmethod
    def calculate(category_uid: int, class_uid: int, activity_id: int = 0) -> int:
        """
        Calculate OCSF type_uid.

        Formula: (category_uid * 100 + class_uid) * 100 + activity_id
        Example: Category 2 (Findings), Class 2001 (Security Finding), Activity 1 (Create)
                 = (2 * 100 + 2001) * 100 + 1 = 200201
        """
        return ((category_uid * 100) + class_uid) * 100 + activity_id


class OCSFMappings:
    """OCSF severity and status mappings."""

    # Cerebro → OCSF Severity
    SEVERITY_MAP = {
        "informational": OCSFSeverity.INFORMATIONAL,
        "low": OCSFSeverity.LOW,
        "medium": OCSFSeverity.MEDIUM,
        "high": OCSFSeverity.HIGH,
        "critical": OCSFSeverity.CRITICAL,
    }

    # Cerebro finding status → OCSF status
    STATUS_MAP = {
        "open": "New",
        "in_progress": "In Progress",
        "fixed": "Resolved",
        "accepted": "Suppressed",
        "false_positive": "Suppressed",
    }
