"""
ISO 27001 framework provider implementation.

Implements ISO/IEC 27001:2022 Information Security Management System
with automated evidence collection and validation.
"""

from typing import List, Optional, Any

from ..framework_registry import (
    FrameworkProvider, FrameworkDefinition, ControlDefinition,
    ControlType, AutomationLevel, TestingFrequency
)


class ISO27001FrameworkProvider(FrameworkProvider):
    """ISO 27001 Information Security Management System framework provider."""

    @property
    def framework_id(self) -> str:
        return "iso27001"

    @property
    def supported_versions(self) -> List[str]:
        return ["2013", "2022", "latest"]

    def get_framework_definition(self, version: Optional[str] = None) -> FrameworkDefinition:
        """Get ISO 27001 framework definition."""
        controls = self._get_iso27001_controls()

        return FrameworkDefinition(
            framework_id="iso27001",
            name="ISO 27001",
            version=version or "2022",
            description="International Standard for Information Security Management Systems",
            issuing_organization="ISO/IEC",
            framework_type="security",
            industry_focus=["all"],
            geographic_scope=["Global"],
            controls=controls,
            control_families={
                "A.5 Information Security Policies": [c.control_id for c in controls if c.control_id.startswith("A.5")],
                "A.6 Organization of Information Security": [c.control_id for c in controls if c.control_id.startswith("A.6")],
                "A.7 Human Resource Security": [c.control_id for c in controls if c.control_id.startswith("A.7")],
                "A.8 Asset Management": [c.control_id for c in controls if c.control_id.startswith("A.8")],
                "A.9 Access Control": [c.control_id for c in controls if c.control_id.startswith("A.9")],
                "A.10 Cryptography": [c.control_id for c in controls if c.control_id.startswith("A.10")],
                "A.11 Physical and Environmental Security": [c.control_id for c in controls if c.control_id.startswith("A.11")],
                "A.12 Operations Security": [c.control_id for c in controls if c.control_id.startswith("A.12")],
                "A.13 Communications Security": [c.control_id for c in controls if c.control_id.startswith("A.13")],
                "A.14 System Acquisition, Development and Maintenance": [c.control_id for c in controls if c.control_id.startswith("A.14")],
                "A.15 Supplier Relationships": [c.control_id for c in controls if c.control_id.startswith("A.15")],
                "A.16 Information Security Incident Management": [c.control_id for c in controls if c.control_id.startswith("A.16")],
                "A.17 Information Security Aspects of BCM": [c.control_id for c in controls if c.control_id.startswith("A.17")],
                "A.18 Compliance": [c.control_id for c in controls if c.control_id.startswith("A.18")]
            },
            effective_date="2022-10-01",
            update_frequency="5-7 years",
            certification_available=True,
            maturity_model={
                "levels": ["Initial", "Repeatable", "Defined", "Managed", "Optimized"],
                "assessment_criteria": "Plan-Do-Check-Act Cycle"
            },
            implementation_tiers=["Foundation", "Advanced", "Expert"],
            references=[
                "ISO/IEC 27001:2022",
                "ISO/IEC 27002:2022",
                "ISO/IEC 27005:2018"
            ],
            documentation_urls=[
                "https://www.iso.org/standard/27001",
                "https://www.iso.org/standard/75652.html"
            ]
        )

    def _get_iso27001_controls(self) -> List[ControlDefinition]:
        """Define ISO 27001 controls with evidence collection."""
        return [
            # A.5 Information Security Policies
            ControlDefinition(
                control_id="A.5.1.1",
                title="Information Security Policy",
                description="Information security policy shall be defined, approved by management, published and communicated to employees and relevant external parties.",
                category="Information Security Policies",
                control_type=ControlType.ADMINISTRATIVE,
                automation_level=AutomationLevel.MANUAL,
                testing_frequency=TestingFrequency.ANNUALLY,
                evidence_queries=[
                    "SELECT repository_name, file_path FROM github_repository WHERE file_path LIKE '%policy%'",
                    "SELECT repository_name, file_path FROM github_repository WHERE file_path LIKE '%security%'",
                    "SELECT document_name, last_updated, approval_status FROM policy_documents WHERE category = 'information_security'"
                ],
                evidence_collection_methods=["document_review", "sql_query"],
                remediation_guidance="Develop, approve, and regularly review information security policies that align with business objectives.",
                implementation_guidance="Create comprehensive information security policy framework with executive approval and regular updates.",
                testing_procedures=[
                    "Review policy documentation and approval records",
                    "Verify policy communication to all stakeholders",
                    "Test policy awareness through surveys or training records"
                ],
                risk_level="medium",
                business_impact="Medium - lack of clear policies creates compliance and operational risks",
                tags={"iso_clause": "A.5.1.1", "domain": "governance", "priority": "medium"},
                references=["ISO 27001 A.5.1.1", "ISO 27002 5.1.1"]
            ),

            # A.9 Access Control
            ControlDefinition(
                control_id="A.9.1.1",
                title="Access Control Policy",
                description="An access control policy shall be established, documented and reviewed based on business and information security requirements.",
                category="Access Control",
                control_type=ControlType.ADMINISTRATIVE,
                automation_level=AutomationLevel.SEMI_AUTOMATED,
                testing_frequency=TestingFrequency.QUARTERLY,
                evidence_queries=[
                    "SELECT username, status, groups, last_login FROM okta_user WHERE status IN ('active', 'inactive')",
                    "SELECT user_name, arn, attached_policies, create_date FROM aws_iam_user",
                    "SELECT group_name, members, permissions FROM okta_group",
                    "SELECT repository_name, collaborators, permissions FROM github_repository WHERE private = true"
                ],
                evidence_collection_methods=["sql_query", "policy_review"],
                remediation_guidance="Document and implement comprehensive access control policies with regular reviews.",
                implementation_guidance="Establish role-based access control with documented procedures for access provisioning and review.",
                testing_procedures=[
                    "Review access control policy documentation",
                    "Test access provisioning processes",
                    "Validate regular access reviews are conducted"
                ],
                risk_level="high",
                business_impact="High - inadequate access controls lead to unauthorized data access",
                tags={"iso_clause": "A.9.1.1", "domain": "access_control", "priority": "high"},
                references=["ISO 27001 A.9.1.1", "ISO 27002 9.1.1"],
                related_controls=["A.9.2.1", "A.9.2.2"]
            ),

            ControlDefinition(
                control_id="A.9.2.1",
                title="User Registration and De-registration",
                description="A formal user registration and de-registration process shall be implemented to enable assignment of access rights.",
                category="Access Control",
                control_type=ControlType.ADMINISTRATIVE,
                automation_level=AutomationLevel.AUTOMATED,
                testing_frequency=TestingFrequency.QUARTERLY,
                evidence_queries=[
                    "SELECT username, created_at, status, last_status_change FROM okta_user WHERE created_at >= NOW() - INTERVAL '90 days'",
                    "SELECT username, created_at, status, last_status_change FROM okta_user WHERE last_status_change >= NOW() - INTERVAL '90 days'",
                    "SELECT user_name, create_date, password_last_used FROM aws_iam_user WHERE create_date >= NOW() - INTERVAL '90 days'",
                    "SELECT username, account_status, last_activity FROM github_organization_members"
                ],
                evidence_collection_methods=["sql_query", "process_review"],
                remediation_guidance="Implement formal user lifecycle management processes with documented procedures.",
                implementation_guidance="Establish automated user provisioning and deprovisioning workflows with approval processes.",
                testing_procedures=[
                    "Test user provisioning process",
                    "Test user deprovisioning process",
                    "Review access assignment documentation"
                ],
                risk_level="high",
                business_impact="High - orphaned accounts create security vulnerabilities",
                tags={"iso_clause": "A.9.2.1", "domain": "access_control", "priority": "high"},
                references=["ISO 27001 A.9.2.1", "ISO 27002 9.2.1"],
                depends_on=["A.9.1.1"]
            ),

            ControlDefinition(
                control_id="A.9.2.2",
                title="User Access Provisioning",
                description="A formal user access provisioning process shall be implemented to assign or revoke access rights for all user types to all systems and services.",
                category="Access Control",
                control_type=ControlType.ADMINISTRATIVE,
                automation_level=AutomationLevel.SEMI_AUTOMATED,
                testing_frequency=TestingFrequency.QUARTERLY,
                evidence_queries=[
                    "SELECT username, groups, roles, permissions_last_updated FROM okta_user",
                    "SELECT user_name, attached_policies, inline_policies, policy_attachment_date FROM aws_iam_user",
                    "SELECT team_name, members, permissions FROM github_team",
                    "SELECT app_name, assigned_users, assignment_date FROM okta_application_assignments"
                ],
                evidence_collection_methods=["sql_query", "access_review"],
                remediation_guidance="Implement formal access provisioning with approval workflows and regular reviews.",
                implementation_guidance="Use role-based access control with documented approval processes for access changes.",
                testing_procedures=[
                    "Test access request and approval process",
                    "Validate least privilege implementation",
                    "Review access assignment records"
                ],
                risk_level="high",
                business_impact="High - excessive privileges increase insider threat risk",
                tags={"iso_clause": "A.9.2.2", "domain": "access_control", "priority": "high"},
                references=["ISO 27001 A.9.2.2", "ISO 27002 9.2.2"],
                depends_on=["A.9.1.1", "A.9.2.1"]
            ),

            # A.12 Operations Security
            ControlDefinition(
                control_id="A.12.1.1",
                title="Documented Operating Procedures",
                description="Operating procedures shall be documented and made available to all users who need them.",
                category="Operations Security",
                control_type=ControlType.ADMINISTRATIVE,
                automation_level=AutomationLevel.MANUAL,
                testing_frequency=TestingFrequency.ANNUALLY,
                evidence_queries=[
                    "SELECT repository_name, file_path, last_updated FROM github_repository WHERE file_path LIKE '%procedure%'",
                    "SELECT repository_name, file_path, last_updated FROM github_repository WHERE file_path LIKE '%runbook%'",
                    "SELECT document_name, category, last_reviewed FROM operational_documents WHERE category IN ('procedure', 'runbook', 'manual')"
                ],
                evidence_collection_methods=["document_review", "sql_query"],
                remediation_guidance="Document all operational procedures and maintain current versions accessible to relevant staff.",
                implementation_guidance="Create comprehensive operational documentation with version control and regular updates.",
                testing_procedures=[
                    "Review operational procedure documentation",
                    "Test procedure accessibility and usability",
                    "Validate procedures are current and accurate"
                ],
                risk_level="medium",
                business_impact="Medium - lack of procedures increases operational risk and errors",
                tags={"iso_clause": "A.12.1.1", "domain": "operations", "priority": "medium"},
                references=["ISO 27001 A.12.1.1", "ISO 27002 12.1.1"]
            ),

            ControlDefinition(
                control_id="A.12.4.1",
                title="Event Logging",
                description="Event logs recording user activities, exceptions, faults and information security events shall be produced, kept and regularly reviewed.",
                category="Operations Security",
                control_type=ControlType.DETECTIVE,
                automation_level=AutomationLevel.AUTOMATED,
                testing_frequency=TestingFrequency.MONTHLY,
                evidence_queries=[
                    "SELECT username, event_type, timestamp, source_ip FROM okta_system_logs WHERE timestamp >= NOW() - INTERVAL '24 hours'",
                    "SELECT event_name, source_ip_address, event_time, user_identity FROM aws_cloudtrail_events WHERE event_time >= NOW() - INTERVAL '24 hours'",
                    "SELECT repository_name, action, actor, created_at FROM github_audit_log WHERE created_at >= NOW() - INTERVAL '24 hours'",
                    "SELECT log_level, message, timestamp FROM application_logs WHERE timestamp >= NOW() - INTERVAL '1 hour'"
                ],
                evidence_collection_methods=["sql_query", "log_analysis"],
                remediation_guidance="Implement comprehensive logging and regular log review processes with retention policies.",
                implementation_guidance="Deploy centralized logging with automated analysis and alerting for security events.",
                testing_procedures=[
                    "Test log generation for key system events",
                    "Validate log retention and protection",
                    "Review log analysis and alerting processes"
                ],
                risk_level="medium",
                business_impact="Medium - insufficient logging hampers incident response and forensics",
                tags={"iso_clause": "A.12.4.1", "domain": "operations", "priority": "medium"},
                references=["ISO 27001 A.12.4.1", "ISO 27002 12.4.1"]
            ),

            # A.16 Information Security Incident Management
            ControlDefinition(
                control_id="A.16.1.1",
                title="Incident Management Responsibilities and Procedures",
                description="Management responsibilities and procedures shall be established to ensure a quick, effective and orderly response to information security incidents.",
                category="Incident Management",
                control_type=ControlType.ADMINISTRATIVE,
                automation_level=AutomationLevel.SEMI_AUTOMATED,
                testing_frequency=TestingFrequency.QUARTERLY,
                evidence_queries=[
                    "SELECT incident_id, severity, status, created_at, resolved_at FROM security_incidents WHERE created_at >= NOW() - INTERVAL '90 days'",
                    "SELECT finding_id, title, severity, status, first_seen, resolved_at FROM findings WHERE severity IN ('critical', 'high') AND first_seen >= NOW() - INTERVAL '90 days'",
                    "SELECT alert_id, repository_name, severity, state, created_at FROM github_vulnerability_alert WHERE created_at >= NOW() - INTERVAL '90 days'"
                ],
                evidence_collection_methods=["sql_query", "process_review"],
                remediation_guidance="Establish formal incident management procedures with defined roles and response timeframes.",
                implementation_guidance="Implement incident response plan with clear escalation procedures and communication protocols.",
                testing_procedures=[
                    "Review incident response procedures documentation",
                    "Test incident response capabilities through exercises",
                    "Validate incident documentation and lessons learned"
                ],
                risk_level="high",
                business_impact="High - poor incident response increases damage and recovery time",
                tags={"iso_clause": "A.16.1.1", "domain": "incident_management", "priority": "high"},
                references=["ISO 27001 A.16.1.1", "ISO 27002 16.1.1"]
            ),

            # A.18 Compliance
            ControlDefinition(
                control_id="A.18.1.1",
                title="Identification of Applicable Legislation and Contractual Requirements",
                description="All relevant legislative, statutory, regulatory, contractual requirements and the organization's approach to meet these requirements shall be explicitly identified, documented and kept up to date.",
                category="Compliance",
                control_type=ControlType.ADMINISTRATIVE,
                automation_level=AutomationLevel.SEMI_AUTOMATED,
                testing_frequency=TestingFrequency.ANNUALLY,
                evidence_queries=[
                    "SELECT repository_name, visibility, topics FROM github_repository WHERE visibility = 'public'",
                    "SELECT repository_name, visibility, topics FROM github_repository WHERE topics LIKE '%compliance%'",
                    "SELECT resource_id, tags, compliance_status FROM aws_resources WHERE tags LIKE '%compliance%'",
                    "SELECT framework_name, controls_count, last_assessment FROM compliance_frameworks"
                ],
                evidence_collection_methods=["sql_query", "document_review"],
                remediation_guidance="Maintain inventory of applicable legal and regulatory requirements with regular updates.",
                implementation_guidance="Establish compliance tracking system with regular legal requirement reviews and updates.",
                testing_procedures=[
                    "Review legal and regulatory requirement inventory",
                    "Test compliance monitoring processes",
                    "Validate compliance documentation is current"
                ],
                risk_level="medium",
                business_impact="Medium - non-compliance can result in legal penalties and reputation damage",
                tags={"iso_clause": "A.18.1.1", "domain": "compliance", "priority": "medium"},
                references=["ISO 27001 A.18.1.1", "ISO 27002 18.1.1"]
            )
        ]

    def validate_control_implementation(self, control_id: str, evidence_data: Any) -> bool:
        """Validate ISO 27001 control implementation based on evidence."""
        if not evidence_data:
            return False

        # ISO 27001 specific validation logic
        if control_id == "A.9.1.1":
            return self._validate_access_policy(evidence_data)
        elif control_id == "A.9.2.1":
            return self._validate_user_lifecycle(evidence_data)
        elif control_id == "A.12.4.1":
            return self._validate_logging(evidence_data)
        elif control_id == "A.16.1.1":
            return self._validate_incident_management(evidence_data)
        else:
            return bool(evidence_data)

    def _validate_access_policy(self, evidence_data: Any) -> bool:
        """Validate access control policy implementation."""
        try:
            if not isinstance(evidence_data, dict):
                return False

            users = evidence_data.get("users", [])
            groups = evidence_data.get("groups", [])
            policies = evidence_data.get("policies", [])

            # Check for structured access control
            has_users = len(users) > 0
            has_groups = len(groups) > 0
            has_policies = len(policies) > 0

            return has_users and (has_groups or has_policies)

        except Exception:
            return False

    def _validate_user_lifecycle(self, evidence_data: Any) -> bool:
        """Validate user registration and deregistration processes."""
        try:
            if not isinstance(evidence_data, dict):
                return False

            users = evidence_data.get("users", [])
            recent_changes = evidence_data.get("recent_changes", [])

            # Check for evidence of user lifecycle management
            active_users = [u for u in users if u.get("status") == "active"]
            inactive_users = [u for u in users if u.get("status") in ["inactive", "suspended"]]

            # Look for recent provisioning/deprovisioning activity
            has_lifecycle_activity = len(recent_changes) > 0 or len(inactive_users) > 0

            return len(active_users) > 0 and has_lifecycle_activity

        except Exception:
            return False

    def _validate_logging(self, evidence_data: Any) -> bool:
        """Validate event logging implementation."""
        try:
            if not isinstance(evidence_data, dict):
                return False

            logs = evidence_data.get("logs", [])
            log_types = set(log.get("event_type", "") for log in logs)

            # Check for comprehensive logging
            required_log_types = {"authentication", "authorization", "system", "application"}
            covered_types = required_log_types.intersection(log_types)

            return len(logs) > 0 and len(covered_types) >= 2

        except Exception:
            return False

    def _validate_incident_management(self, evidence_data: Any) -> bool:
        """Validate incident management implementation."""
        try:
            if not isinstance(evidence_data, dict):
                return False

            incidents = evidence_data.get("incidents", [])
            findings = evidence_data.get("findings", [])

            # Check for incident tracking and resolution
            resolved_incidents = [i for i in incidents if i.get("resolved_at")]
            open_incidents = [i for i in incidents if not i.get("resolved_at")]

            # Evidence of incident management process
            has_incident_tracking = len(incidents) > 0 or len(findings) > 0
            has_resolution_process = len(resolved_incidents) > 0

            return has_incident_tracking and (has_resolution_process or len(open_incidents) == 0)

        except Exception:
            return False