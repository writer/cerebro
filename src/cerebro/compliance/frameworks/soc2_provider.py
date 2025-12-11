"""
SOC 2 Type II framework provider implementation.

Implements SOC 2 Trust Services Criteria with automated evidence collection
and validation using the pluggable framework system.
"""

from typing import List, Optional, Any

from ..framework_registry import (
    FrameworkProvider, FrameworkDefinition, ControlDefinition,
    ControlType, AutomationLevel, TestingFrequency
)


class SOC2FrameworkProvider(FrameworkProvider):
    """SOC 2 Type II compliance framework provider."""

    @property
    def framework_id(self) -> str:
        return "soc2"

    @property
    def supported_versions(self) -> List[str]:
        return ["2017", "latest"]

    def get_framework_definition(self, version: Optional[str] = None) -> FrameworkDefinition:
        """Get SOC 2 framework definition."""
        controls = self._get_soc2_controls()

        return FrameworkDefinition(
            framework_id="soc2",
            name="SOC 2 Type II",
            version="2017",
            description="Service Organization Control 2 Type II Trust Services Criteria",
            issuing_organization="AICPA",
            framework_type="compliance",
            industry_focus=["technology", "saas", "cloud"],
            geographic_scope=["US", "Global"],
            controls=controls,
            control_families={
                "Security": [c.control_id for c in controls if "CC6" in c.control_id or "CC7" in c.control_id],
                "Availability": [c.control_id for c in controls if "A1" in c.control_id],
                "Processing Integrity": [c.control_id for c in controls if "PI1" in c.control_id],
                "Confidentiality": [c.control_id for c in controls if "C1" in c.control_id],
                "Privacy": [c.control_id for c in controls if "P1" in c.control_id],
                "Common Criteria": [c.control_id for c in controls if c.control_id.startswith("CC")]
            },
            effective_date="2017-12-01",
            update_frequency="annually",
            certification_available=True,
            maturity_model={
                "levels": ["Initial", "Repeatable", "Defined", "Managed", "Optimized"],
                "assessment_criteria": "Design and Operating Effectiveness"
            },
            implementation_tiers=["Type I", "Type II"],
            references=[
                "AICPA TSC Framework",
                "SSAE 18",
                "AT-C Section 315"
            ],
            documentation_urls=[
                "https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html"
            ]
        )

    def _get_soc2_controls(self) -> List[ControlDefinition]:
        """Define SOC 2 controls with evidence collection queries."""
        return [
            # CC6 - Logical and Physical Access Controls
            ControlDefinition(
                control_id="CC6.1",
                title="Logical Access - Access Rights Management",
                description="The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events to meet the entity's objectives.",
                category="Access Controls",
                control_type=ControlType.PREVENTIVE,
                automation_level=AutomationLevel.AUTOMATED,
                testing_frequency=TestingFrequency.QUARTERLY,
                evidence_queries=[
                    "SELECT username, roles, groups, last_login, mfa_enabled FROM okta_user WHERE status = 'active'",
                    "SELECT group_name, member_count, permissions FROM okta_group WHERE type != 'BUILT_IN'",
                    "SELECT user_name, attached_policies, groups, mfa_enabled FROM aws_iam_user WHERE user_name != 'root'",
                    "SELECT role_name, attached_policies, assume_role_policy FROM aws_iam_role",
                    "SELECT name, permissions, members FROM github_team"
                ],
                evidence_collection_methods=["sql_query", "api_query"],
                remediation_guidance="Implement role-based access controls with regular access reviews. Ensure principle of least privilege is applied.",
                implementation_guidance="Deploy centralized identity management system with automated provisioning and deprovisioning workflows.",
                testing_procedures=[
                    "Review user access rights quarterly",
                    "Test access provisioning and deprovisioning processes",
                    "Validate segregation of duties implementation"
                ],
                risk_level="high",
                business_impact="High - unauthorized access to critical systems and data",
                tags={"tsc": "CC6.1", "domain": "security", "priority": "high"},
                references=["TSC CC6.1", "NIST AC-2"],
                last_updated="2024-01-01"
            ),

            ControlDefinition(
                control_id="CC6.2",
                title="Logical Access - Authentication",
                description="The entity authenticates users and other parties before granting access to the system and data.",
                category="Access Controls",
                control_type=ControlType.PREVENTIVE,
                automation_level=AutomationLevel.AUTOMATED,
                testing_frequency=TestingFrequency.QUARTERLY,
                evidence_queries=[
                    "SELECT username, mfa_enabled, last_login, authentication_methods FROM okta_user WHERE status = 'active'",
                    "SELECT app_name, sign_on_mode, mfa_required FROM okta_application",
                    "SELECT username, mfa_devices, password_last_used FROM aws_iam_user",
                    "SELECT policy_name, mfa_requirement FROM aws_iam_policy WHERE policy_document LIKE '%MFA%'"
                ],
                evidence_collection_methods=["sql_query"],
                remediation_guidance="Enforce multi-factor authentication for all users. Implement strong password policies.",
                implementation_guidance="Configure SSO with MFA requirements. Disable legacy authentication methods.",
                testing_procedures=[
                    "Test MFA enforcement for all user types",
                    "Validate password policy compliance",
                    "Review authentication method security"
                ],
                risk_level="high",
                business_impact="High - weak authentication enables account compromise",
                tags={"tsc": "CC6.2", "domain": "security", "priority": "high"},
                references=["TSC CC6.2", "NIST IA-2"]
            ),

            ControlDefinition(
                control_id="CC6.3",
                title="Logical Access - Authorization",
                description="The entity authorizes access to data, software, functions, and other protected information assets based on business requirements.",
                category="Access Controls",
                control_type=ControlType.PREVENTIVE,
                automation_level=AutomationLevel.AUTOMATED,
                testing_frequency=TestingFrequency.QUARTERLY,
                evidence_queries=[
                    "SELECT username, groups, roles, permissions FROM okta_user",
                    "SELECT user_name, attached_policies, inline_policies FROM aws_iam_user",
                    "SELECT repository_name, permissions, collaborators FROM github_repository WHERE private = true",
                    "SELECT group_name, members, permissions FROM okta_group"
                ],
                evidence_collection_methods=["sql_query"],
                remediation_guidance="Implement least privilege access principles. Conduct regular access reviews.",
                implementation_guidance="Use role-based access control (RBAC) with predefined roles aligned to job functions.",
                testing_procedures=[
                    "Test authorization controls for critical systems",
                    "Validate segregation of duties",
                    "Review privileged access assignments"
                ],
                risk_level="high",
                business_impact="High - excessive privileges increase insider threat risk",
                tags={"tsc": "CC6.3", "domain": "security", "priority": "high"},
                references=["TSC CC6.3", "NIST AC-3"]
            ),

            # CC7 - System Operations
            ControlDefinition(
                control_id="CC7.1",
                title="System Monitoring - Detection and Analysis",
                description="To meet its objectives, the entity uses detection and monitoring procedures to identify security events.",
                category="System Monitoring",
                control_type=ControlType.DETECTIVE,
                automation_level=AutomationLevel.AUTOMATED,
                testing_frequency=TestingFrequency.MONTHLY,
                evidence_queries=[
                    "SELECT repository_name, alert_id, severity, state, created_at FROM github_vulnerability_alert WHERE state = 'open'",
                    "SELECT repository_name, secret_type, state, resolution FROM github_secret_scanning_alert WHERE state = 'open'",
                    "SELECT finding_id, severity, title, status, first_seen FROM findings WHERE status = 'open' AND severity IN ('critical', 'high')",
                    "SELECT log_level, event_type, timestamp FROM system_logs WHERE timestamp >= NOW() - INTERVAL '24 hours'"
                ],
                evidence_collection_methods=["sql_query", "log_analysis"],
                remediation_guidance="Implement continuous security monitoring with automated alerting for critical events.",
                implementation_guidance="Deploy SIEM/SOAR tools with correlation rules and automated response capabilities.",
                testing_procedures=[
                    "Test security event detection capabilities",
                    "Validate alert notification systems",
                    "Review security monitoring coverage"
                ],
                risk_level="medium",
                business_impact="Medium - delayed threat detection increases incident impact",
                tags={"tsc": "CC7.1", "domain": "security", "priority": "medium"},
                references=["TSC CC7.1", "NIST SI-4"]
            ),

            ControlDefinition(
                control_id="CC7.2",
                title="System Monitoring - Response and Remediation",
                description="The entity monitors, evaluates, and responds to security events and incidents in a timely manner.",
                category="System Monitoring",
                control_type=ControlType.CORRECTIVE,
                automation_level=AutomationLevel.SEMI_AUTOMATED,
                testing_frequency=TestingFrequency.MONTHLY,
                evidence_queries=[
                    "SELECT alert_id, response_time, resolution_time, status FROM incident_responses WHERE created_at >= NOW() - INTERVAL '30 days'",
                    "SELECT repository_name, alert_id, resolved_at, resolution_method FROM github_vulnerability_alert WHERE resolved_at IS NOT NULL",
                    "SELECT finding_id, remediation_status, resolved_at FROM findings WHERE resolved_at >= NOW() - INTERVAL '30 days'"
                ],
                evidence_collection_methods=["sql_query"],
                remediation_guidance="Establish incident response procedures with documented resolution timeframes by severity.",
                implementation_guidance="Implement automated incident response workflows with escalation procedures.",
                testing_procedures=[
                    "Test incident response procedures",
                    "Validate resolution time adherence to SLAs",
                    "Review post-incident documentation"
                ],
                risk_level="medium",
                business_impact="Medium - slow incident response increases damage scope",
                tags={"tsc": "CC7.2", "domain": "security", "priority": "medium"},
                references=["TSC CC7.2", "NIST IR-4"]
            ),

            # CC8 - Change Management
            ControlDefinition(
                control_id="CC8.1",
                title="Change Management - Authorization and Testing",
                description="The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures.",
                category="Change Management",
                control_type=ControlType.ADMINISTRATIVE,
                automation_level=AutomationLevel.SEMI_AUTOMATED,
                testing_frequency=TestingFrequency.QUARTERLY,
                evidence_queries=[
                    "SELECT instance_id, state, last_modified, tags FROM aws_ec2_instance WHERE last_modified >= NOW() - INTERVAL '90 days'",
                    "SELECT group_id, group_name, ingress_rules, egress_rules FROM aws_security_group",
                    "SELECT repository_name, default_branch, updated_at, branch_protection FROM github_repository WHERE updated_at >= NOW() - INTERVAL '90 days'",
                    "SELECT pull_request_id, state, created_at, merged_at FROM github_pull_requests WHERE state = 'merged'"
                ],
                evidence_collection_methods=["sql_query", "configuration_monitoring"],
                remediation_guidance="Implement formal change management processes with approval workflows and testing requirements.",
                implementation_guidance="Use infrastructure as code and automated deployment pipelines with approval gates.",
                testing_procedures=[
                    "Review change approval documentation",
                    "Test change rollback procedures",
                    "Validate segregation of duties in change process"
                ],
                risk_level="medium",
                business_impact="Medium - uncontrolled changes can cause service disruption",
                tags={"tsc": "CC8.1", "domain": "operations", "priority": "medium"},
                references=["TSC CC8.1", "NIST CM-3"]
            ),

            # A1 - Availability Controls
            ControlDefinition(
                control_id="A1.1",
                title="Availability - Performance Monitoring",
                description="The entity maintains, monitors, and evaluates current processing capacity and use of system components to manage capacity demand and to enable the implementation of additional capacity to help meet its objectives.",
                category="Availability",
                control_type=ControlType.DETECTIVE,
                automation_level=AutomationLevel.AUTOMATED,
                testing_frequency=TestingFrequency.CONTINUOUS,
                evidence_queries=[
                    "SELECT instance_id, cpu_utilization, memory_utilization, disk_utilization FROM aws_ec2_instance_metrics WHERE timestamp >= NOW() - INTERVAL '24 hours'",
                    "SELECT metric_name, value, timestamp FROM system_performance_metrics WHERE timestamp >= NOW() - INTERVAL '1 hour'",
                    "SELECT service_name, uptime_percentage, response_time_avg FROM service_health_metrics"
                ],
                evidence_collection_methods=["metrics_collection", "api_query"],
                remediation_guidance="Implement automated capacity monitoring with alerting and auto-scaling capabilities.",
                implementation_guidance="Deploy infrastructure monitoring tools with predictive capacity planning.",
                testing_procedures=[
                    "Test capacity monitoring and alerting",
                    "Validate auto-scaling functionality",
                    "Review capacity planning processes"
                ],
                risk_level="medium",
                business_impact="Medium - capacity issues can impact service availability",
                tags={"tsc": "A1.1", "domain": "availability", "priority": "medium"},
                references=["TSC A1.1", "ITIL Capacity Management"]
            )
        ]

    def validate_control_implementation(self, control_id: str, evidence_data: Any) -> bool:
        """Validate SOC 2 control implementation based on evidence."""
        if not evidence_data:
            return False

        # SOC 2 specific validation logic
        if control_id == "CC6.1":
            # Validate access controls
            return self._validate_access_controls(evidence_data)
        elif control_id == "CC6.2":
            # Validate authentication
            return self._validate_authentication(evidence_data)
        elif control_id == "CC7.1":
            # Validate monitoring
            return self._validate_monitoring(evidence_data)
        else:
            # Default validation - check if evidence exists
            return bool(evidence_data)

    def _validate_access_controls(self, evidence_data: Any) -> bool:
        """Validate access control implementation."""
        try:
            # Check for required evidence elements
            if not isinstance(evidence_data, dict):
                return False

            # Look for user access data
            users = evidence_data.get("users", [])
            groups = evidence_data.get("groups", [])

            # Basic checks
            has_users = len(users) > 0
            has_rbac = len(groups) > 0
            has_mfa = any(user.get("mfa_enabled", False) for user in users)

            return has_users and has_rbac and has_mfa

        except Exception:
            return False

    def _validate_authentication(self, evidence_data: Any) -> bool:
        """Validate authentication controls."""
        try:
            if not isinstance(evidence_data, dict):
                return False

            users = evidence_data.get("users", [])
            apps = evidence_data.get("applications", [])

            # Check MFA enforcement
            mfa_users = [u for u in users if u.get("mfa_enabled", False)]
            mfa_percentage = len(mfa_users) / len(users) if users else 0

            # Check SSO configuration
            sso_apps = [a for a in apps if a.get("sign_on_mode") in ["SAML_2_0", "OPENID_CONNECT"]]

            return mfa_percentage >= 0.95 and len(sso_apps) > 0

        except Exception:
            return False

    def _validate_monitoring(self, evidence_data: Any) -> bool:
        """Validate security monitoring."""
        try:
            if not isinstance(evidence_data, dict):
                return False

            alerts = evidence_data.get("alerts", [])
            logs = evidence_data.get("logs", [])

            # Check for active monitoring
            recent_alerts = [a for a in alerts if a.get("state") == "open"]
            recent_logs = [l for l in logs if "security" in l.get("event_type", "").lower()]

            return len(recent_alerts) > 0 or len(recent_logs) > 0

        except Exception:
            return False