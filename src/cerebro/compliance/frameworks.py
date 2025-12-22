"""
Compliance framework definitions for automated evidence generation.

Defines control requirements and evidence mapping for major compliance frameworks.
"""

from typing import List, Optional
from dataclasses import dataclass
from enum import Enum


class ControlType(Enum):
    """Types of security controls."""

    PREVENTIVE = "preventive"
    DETECTIVE = "detective"
    CORRECTIVE = "corrective"
    ADMINISTRATIVE = "administrative"
    TECHNICAL = "technical"
    PHYSICAL = "physical"


class EvidenceType(Enum):
    """Types of evidence that can be collected."""

    CONFIGURATION = "configuration"
    ACCESS_LOG = "access_log"
    AUDIT_LOG = "audit_log"
    POLICY_DOCUMENT = "policy_document"
    SCREENSHOT = "screenshot"
    SYSTEM_REPORT = "system_report"
    VULNERABILITY_SCAN = "vulnerability_scan"
    PENETRATION_TEST = "penetration_test"
    TRAINING_RECORD = "training_record"
    INCIDENT_REPORT = "incident_report"


@dataclass
class ComplianceControl:
    """Definition of a compliance control requirement."""

    control_id: str
    title: str
    description: str
    category: str
    control_type: ControlType
    required_evidence: List[EvidenceType]
    sql_queries: List[str]  # SQL queries to collect evidence
    remediation_guidance: str
    frequency: str  # How often evidence needs to be collected
    automation_level: str  # manual, semi-automated, automated


@dataclass
class ComplianceFramework:
    """Base class for compliance frameworks."""

    name: str
    version: str
    description: str
    controls: List[ComplianceControl]

    def get_control(self, control_id: str) -> Optional[ComplianceControl]:
        """Get a specific control by ID."""
        return next((c for c in self.controls if c.control_id == control_id), None)

    def get_controls_by_category(self, category: str) -> List[ComplianceControl]:
        """Get all controls in a category."""
        return [c for c in self.controls if c.category == category]

    def get_automated_controls(self) -> List[ComplianceControl]:
        """Get controls that can be fully automated."""
        return [c for c in self.controls if c.automation_level == "automated"]


class SOC2Framework:
    """SOC 2 Type II compliance framework implementation."""

    @classmethod
    def get_framework(cls) -> ComplianceFramework:
        """Get SOC 2 framework definition."""
        controls = [
            # Security - Access Controls
            ComplianceControl(
                control_id="CC6.1",
                title="Logical Access - Access Rights",
                description="Entities implement logical access security software, infrastructure, and architectures over protected information assets to protect them from security events to meet the entity's objectives.",
                category="Access Controls",
                control_type=ControlType.PREVENTIVE,
                required_evidence=[
                    EvidenceType.CONFIGURATION,
                    EvidenceType.ACCESS_LOG,
                    EvidenceType.SYSTEM_REPORT,
                ],
                sql_queries=[
                    "SELECT username, roles, last_login, mfa_enabled FROM okta_user WHERE status = 'active'",
                    "SELECT group_name, member_count FROM okta_group",
                    "SELECT user_name, attached_policies, mfa_enabled FROM aws_iam_user",
                    "SELECT * FROM github_repository WHERE private = false",
                ],
                remediation_guidance="Implement role-based access controls and regular access reviews",
                frequency="quarterly",
                automation_level="automated",
            ),
            ComplianceControl(
                control_id="CC6.2",
                title="Logical Access - Authentication",
                description="Entities authenticate users and related parties before access to the system is granted.",
                category="Access Controls",
                control_type=ControlType.PREVENTIVE,
                required_evidence=[EvidenceType.CONFIGURATION, EvidenceType.AUDIT_LOG],
                sql_queries=[
                    "SELECT username, mfa_enabled, last_login FROM okta_user WHERE mfa_enabled = false",
                    "SELECT app_name, sign_on_mode FROM okta_application",
                    "SELECT username, password_last_used FROM aws_iam_user WHERE password_last_used IS NULL",
                ],
                remediation_guidance="Enforce multi-factor authentication for all users",
                frequency="quarterly",
                automation_level="automated",
            ),
            ComplianceControl(
                control_id="CC6.3",
                title="Logical Access - Authorization",
                description="Entities authorize access to the system based on business requirements.",
                category="Access Controls",
                control_type=ControlType.PREVENTIVE,
                required_evidence=[EvidenceType.CONFIGURATION, EvidenceType.ACCESS_LOG],
                sql_queries=[
                    "SELECT username, groups, roles FROM okta_user",
                    "SELECT user_name, attached_policies, inline_policies FROM aws_iam_user",
                    "SELECT repository, permissions FROM github_repository",
                ],
                remediation_guidance="Implement least privilege access principles",
                frequency="quarterly",
                automation_level="automated",
            ),
            # Security - System Monitoring
            ComplianceControl(
                control_id="CC7.1",
                title="System Monitoring - Detection",
                description="To meet its objectives, the entity uses detection and monitoring procedures to identify security events.",
                category="System Monitoring",
                control_type=ControlType.DETECTIVE,
                required_evidence=[EvidenceType.AUDIT_LOG, EvidenceType.SYSTEM_REPORT],
                sql_queries=[
                    "SELECT alert_id, severity, status FROM github_vulnerability_alert WHERE state = 'open'",
                    "SELECT secret_type, state FROM github_secret_scanning_alert WHERE state = 'open'",
                    "SELECT repository, created_at FROM github_vulnerability_alert WHERE severity = 'critical'",
                ],
                remediation_guidance="Implement continuous security monitoring and alerting",
                frequency="monthly",
                automation_level="automated",
            ),
            ComplianceControl(
                control_id="CC7.2",
                title="System Monitoring - Analysis and Response",
                description="The entity monitors, evaluates, and responds to security events in a timely manner.",
                category="System Monitoring",
                control_type=ControlType.CORRECTIVE,
                required_evidence=[
                    EvidenceType.INCIDENT_REPORT,
                    EvidenceType.AUDIT_LOG,
                ],
                sql_queries=[
                    "SELECT repository, state, resolved_at FROM github_vulnerability_alert WHERE resolved_at IS NOT NULL",
                    "SELECT secret_type, resolution FROM github_secret_scanning_alert WHERE resolution IS NOT NULL",
                ],
                remediation_guidance="Establish incident response procedures with documented resolution times",
                frequency="monthly",
                automation_level="semi-automated",
            ),
            # Security - Configuration Management
            ComplianceControl(
                control_id="CC8.1",
                title="Change Management - Authorization",
                description="The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures to meet its objectives.",
                category="Change Management",
                control_type=ControlType.ADMINISTRATIVE,
                required_evidence=[EvidenceType.CONFIGURATION, EvidenceType.AUDIT_LOG],
                sql_queries=[
                    "SELECT instance_id, state, last_modified FROM aws_ec2_instance",
                    "SELECT group_id, group_name, ingress_rules FROM aws_security_group",
                    "SELECT repository, default_branch, updated_at FROM github_repository",
                ],
                remediation_guidance="Implement change management processes with approval workflows",
                frequency="quarterly",
                automation_level="semi-automated",
            ),
        ]

        return ComplianceFramework(
            name="SOC 2 Type II",
            version="2017 TSC",
            description="Service Organization Control 2 Type II Trust Services Criteria",
            controls=controls,
        )


class ISO27001Framework:
    """ISO 27001 compliance framework implementation."""

    @classmethod
    def get_framework(cls) -> ComplianceFramework:
        """Get ISO 27001 framework definition."""
        controls = [
            # A.9 Access Control
            ComplianceControl(
                control_id="A.9.1.1",
                title="Access Control Policy",
                description="An access control policy shall be established, documented and reviewed based on business and information security requirements.",
                category="Access Control",
                control_type=ControlType.ADMINISTRATIVE,
                required_evidence=[
                    EvidenceType.POLICY_DOCUMENT,
                    EvidenceType.CONFIGURATION,
                ],
                sql_queries=[
                    "SELECT username, status, groups FROM okta_user",
                    "SELECT user_name, arn, attached_policies FROM aws_iam_user",
                ],
                remediation_guidance="Document and implement comprehensive access control policies",
                frequency="annually",
                automation_level="semi-automated",
            ),
            ComplianceControl(
                control_id="A.9.2.1",
                title="User Registration and De-registration",
                description="A formal user registration and de-registration process shall be implemented to enable assignment of access rights.",
                category="Access Control",
                control_type=ControlType.ADMINISTRATIVE,
                required_evidence=[EvidenceType.ACCESS_LOG, EvidenceType.AUDIT_LOG],
                sql_queries=[
                    "SELECT username, created_at, status FROM okta_user WHERE status = 'inactive'",
                    "SELECT user_name, create_date FROM aws_iam_user",
                ],
                remediation_guidance="Implement formal user lifecycle management processes",
                frequency="quarterly",
                automation_level="automated",
            ),
            # A.12 Operations Security
            ComplianceControl(
                control_id="A.12.1.1",
                title="Documented Operating Procedures",
                description="Operating procedures shall be documented and made available to all users who need them.",
                category="Operations Security",
                control_type=ControlType.ADMINISTRATIVE,
                required_evidence=[
                    EvidenceType.POLICY_DOCUMENT,
                    EvidenceType.SYSTEM_REPORT,
                ],
                sql_queries=[
                    "SELECT repository, topics FROM github_repository WHERE topics LIKE '%documentation%'",
                    "SELECT app_name, settings FROM okta_application",
                ],
                remediation_guidance="Document all operational procedures and maintain current versions",
                frequency="annually",
                automation_level="manual",
            ),
            ComplianceControl(
                control_id="A.12.4.1",
                title="Event Logging",
                description="Event logs recording user activities, exceptions, faults and information security events shall be produced, kept and regularly reviewed.",
                category="Operations Security",
                control_type=ControlType.DETECTIVE,
                required_evidence=[EvidenceType.AUDIT_LOG, EvidenceType.SYSTEM_REPORT],
                sql_queries=[
                    "SELECT username, last_login FROM okta_user WHERE last_login IS NOT NULL",
                    "SELECT repository, created_at FROM github_vulnerability_alert",
                ],
                remediation_guidance="Implement comprehensive logging and regular log review processes",
                frequency="monthly",
                automation_level="automated",
            ),
            # A.18 Compliance
            ComplianceControl(
                control_id="A.18.1.1",
                title="Identification of Applicable Legislation",
                description="All relevant legislative, statutory, regulatory, contractual requirements and the organization's approach to meet these requirements shall be explicitly identified, documented and kept up to date for each information system and the organization.",
                category="Compliance",
                control_type=ControlType.ADMINISTRATIVE,
                required_evidence=[
                    EvidenceType.POLICY_DOCUMENT,
                    EvidenceType.SYSTEM_REPORT,
                ],
                sql_queries=[
                    "SELECT repository, visibility, topics FROM github_repository WHERE visibility = 'public'",
                    "SELECT instance_id, tags FROM aws_ec2_instance",
                ],
                remediation_guidance="Maintain inventory of applicable legal and regulatory requirements",
                frequency="annually",
                automation_level="semi-automated",
            ),
        ]

        return ComplianceFramework(
            name="ISO 27001",
            version="2013",
            description="International Standard for Information Security Management Systems",
            controls=controls,
        )


class PCIDSSFramework:
    """PCI DSS compliance framework implementation."""

    @classmethod
    def get_framework(cls) -> ComplianceFramework:
        """Get PCI DSS framework definition."""
        controls = [
            # Requirement 2: Do not use vendor-supplied defaults
            ComplianceControl(
                control_id="2.1",
                title="Change Vendor-Supplied Defaults",
                description="Always change vendor-supplied defaults and remove or disable unnecessary default accounts before installing a system on the network.",
                category="Configuration Management",
                control_type=ControlType.PREVENTIVE,
                required_evidence=[
                    EvidenceType.CONFIGURATION,
                    EvidenceType.VULNERABILITY_SCAN,
                ],
                sql_queries=[
                    "SELECT user_name, password_last_used FROM aws_iam_user WHERE user_name IN ('admin', 'root', 'default')",
                    "SELECT instance_id, key_name FROM aws_ec2_instance WHERE key_name IS NULL",
                ],
                remediation_guidance="Remove default accounts and change default passwords/configurations",
                frequency="quarterly",
                automation_level="automated",
            ),
            # Requirement 7: Restrict access by business need-to-know
            ComplianceControl(
                control_id="7.1.1",
                title="Access Rights Assignment",
                description="Limit access to computing resources and cardholder data by business need-to-know.",
                category="Access Control",
                control_type=ControlType.PREVENTIVE,
                required_evidence=[EvidenceType.ACCESS_LOG, EvidenceType.CONFIGURATION],
                sql_queries=[
                    "SELECT username, groups, roles FROM okta_user",
                    "SELECT user_name, attached_policies FROM aws_iam_user",
                    "SELECT repository, permissions FROM github_repository WHERE private = true",
                ],
                remediation_guidance="Implement role-based access controls based on business need-to-know",
                frequency="quarterly",
                automation_level="automated",
            ),
            # Requirement 10: Track and monitor access
            ComplianceControl(
                control_id="10.1",
                title="Audit Log Implementation",
                description="Implement audit trails to link all access to system components to each individual user.",
                category="Logging and Monitoring",
                control_type=ControlType.DETECTIVE,
                required_evidence=[EvidenceType.AUDIT_LOG, EvidenceType.SYSTEM_REPORT],
                sql_queries=[
                    "SELECT username, last_login FROM okta_user WHERE last_login IS NOT NULL",
                    "SELECT repository, created_at FROM github_vulnerability_alert WHERE created_at >= DATE('now', '-30 days')",
                ],
                remediation_guidance="Ensure all system access is logged and regularly reviewed",
                frequency="monthly",
                automation_level="automated",
            ),
        ]

        return ComplianceFramework(
            name="PCI DSS",
            version="4.0",
            description="Payment Card Industry Data Security Standard",
            controls=controls,
        )


# Registry of available frameworks
COMPLIANCE_FRAMEWORKS = {
    "soc2": SOC2Framework.get_framework(),
    "iso27001": ISO27001Framework.get_framework(),
    "pci_dss": PCIDSSFramework.get_framework(),
}


def get_framework(framework_name: str) -> Optional[ComplianceFramework]:
    """Get a compliance framework by name."""
    return COMPLIANCE_FRAMEWORKS.get(framework_name.lower())


def list_frameworks() -> List[str]:
    """List all available compliance frameworks."""
    return list(COMPLIANCE_FRAMEWORKS.keys())
