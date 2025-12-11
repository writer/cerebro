"""
OCSF Data Models

Pydantic models representing OCSF v1.4.0 schema for security events.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Any, Dict, List, Optional
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
    profiles: List[str] = []
    event_code: Optional[str] = None
    correlation_uid: Optional[str] = None
    log_name: Optional[str] = None
    log_provider: Optional[str] = None
    logged_time: Optional[int] = None  # Unix epoch ms
    original_time: Optional[str] = None


class OCSFProduct(BaseModel):
    """OCSF Product Object."""
    name: str = "Cerebro"
    version: str = "1.0.0"
    vendor_name: str = "Cerebro Security"
    feature: Optional[Dict[str, Any]] = None


class OCSFActor(BaseModel):
    """OCSF Actor Object (User/Process/Device)."""
    user: Optional[OCSFUser] = None
    process: Optional[OCSFProcess] = None
    session: Optional[Dict[str, Any]] = None
    idp: Optional[Dict[str, Any]] = None


class OCSFUser(BaseModel):
    """OCSF User Object."""
    name: Optional[str] = None
    uid: Optional[str] = None
    email_addr: Optional[str] = None
    full_name: Optional[str] = None
    domain: Optional[str] = None
    type: Optional[str] = None
    type_id: Optional[int] = None
    groups: Optional[List[Dict[str, Any]]] = None


class OCSFProcess(BaseModel):
    """OCSF Process Object."""
    name: Optional[str] = None
    pid: Optional[int] = None
    file: Optional[Dict[str, Any]] = None
    cmd_line: Optional[str] = None
    user: Optional[OCSFUser] = None


class OCSFResource(BaseModel):
    """OCSF Resource Object."""
    name: Optional[str] = None
    uid: Optional[str] = None
    type: Optional[str] = None
    owner: Optional[OCSFUser] = None
    labels: Optional[List[str]] = None
    data: Optional[Dict[str, Any]] = None


class OCSFCloud(BaseModel):
    """OCSF Cloud Object."""
    provider: str  # AWS, Azure, GCP, etc.
    region: Optional[str] = None
    account: Optional[OCSFAccount] = None
    org: Optional[Dict[str, Any]] = None
    project_uid: Optional[str] = None


class OCSFAccount(BaseModel):
    """OCSF Account Object."""
    name: Optional[str] = None
    type: Optional[str] = None
    type_id: Optional[int] = None
    uid: Optional[str] = None


class OCSFObservables(BaseModel):
    """OCSF Observables Array."""
    name: str
    type: str
    type_id: int
    value: Any
    reputation: Optional[Dict[str, Any]] = None


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
    status_id: Optional[int] = None
    status: Optional[str] = None

    metadata: OCSFMetadata
    observables: Optional[List[OCSFObservables]] = []
    unmapped: Optional[Dict[str, Any]] = None  # Original data not mapped to OCSF


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
    resources: Optional[List[OCSFResource]] = []
    remediation: Optional[OCSFRemediation] = None
    compliance: Optional[OCSFCompliance] = None
    vulnerabilities: Optional[List[OCSFVulnerability]] = []

    # Risk and impact
    risk_level: Optional[str] = None
    risk_level_id: Optional[int] = None
    risk_score: Optional[int] = None  # 0-100
    impact: Optional[str] = None
    impact_id: Optional[int] = None

    # Context
    actor: Optional[OCSFActor] = None
    cloud: Optional[OCSFCloud] = None
    confidence: Optional[int] = None  # 0-100
    confidence_id: Optional[int] = None


class OCSFFindingInfo(BaseModel):
    """OCSF Finding Info Object."""
    title: str
    desc: Optional[str] = None
    uid: str
    types: List[str] = []  # e.g., ["Misconfiguration", "Compliance Violation"]
    first_seen_time: Optional[int] = None  # Unix epoch ms
    last_seen_time: Optional[int] = None
    modified_time: Optional[int] = None
    created_time: Optional[int] = None
    analytic: Optional[Dict[str, Any]] = None
    src_url: Optional[str] = None  # Link to finding in Cerebro


class OCSFRemediation(BaseModel):
    """OCSF Remediation Object."""
    desc: str
    kb_articles: Optional[List[str]] = []
    references: Optional[List[str]] = []


class OCSFCompliance(BaseModel):
    """OCSF Compliance Object."""
    requirements: List[str] = []  # e.g., ["CIS AWS 1.1", "NIST CSF PR.AC-4"]
    status: str  # Pass, Fail, Not Applicable
    status_detail: Optional[str] = None


class OCSFVulnerability(BaseModel):
    """OCSF Vulnerability Object."""
    cve_uid: Optional[str] = None  # CVE-2024-1234
    cwe_uid: Optional[str] = None  # CWE-79
    title: Optional[str] = None
    desc: Optional[str] = None
    severity: Optional[str] = None
    cvss: Optional[Dict[str, Any]] = None  # CVSS scores


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

    actor: Optional[OCSFActor] = None
    user: Optional[OCSFUser] = None
    group: Optional[Dict[str, Any]] = None
    policy: Optional[Dict[str, Any]] = None
    privileges: Optional[List[str]] = []
    cloud: Optional[OCSFCloud] = None
    is_mfa: Optional[bool] = None
    auth_protocol: Optional[str] = None
    auth_protocol_id: Optional[int] = None


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