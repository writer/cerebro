"""
NIST Cybersecurity Framework 2.0 provider implementation.

Implements the NIST CSF 2.0 with its six core functions:
- Govern (GV) - New in 2.0
- Identify (ID)
- Protect (PR)
- Detect (DE)
- Respond (RS)
- Recover (RC)
"""

from typing import Any

from ..framework_registry import (
    AutomationLevel,
    ControlDefinition,
    ControlType,
    FrameworkDefinition,
    FrameworkProvider,
    TestingFrequency,
)


class NISTCSFFrameworkProvider(FrameworkProvider):
    """NIST Cybersecurity Framework 2.0 provider."""

    @property
    def framework_id(self) -> str:
        return "nist_csf"

    @property
    def supported_versions(self) -> list[str]:
        return ["2.0", "1.1", "1.0"]

    def get_framework_definition(
        self, version: str | None = None
    ) -> FrameworkDefinition:
        """Get NIST CSF framework definition."""
        effective_version = version or "2.0"
        controls = self._get_nist_csf_controls(effective_version)

        return FrameworkDefinition(
            framework_id="nist_csf",
            name="NIST Cybersecurity Framework",
            version=effective_version,
            description="NIST Cybersecurity Framework 2.0 - A comprehensive guide for managing cybersecurity risk",
            issuing_organization="National Institute of Standards and Technology (NIST)",
            framework_type="risk_management",
            industry_focus=["all", "critical_infrastructure"],
            geographic_scope=["US", "Global"],
            controls=controls,
            control_families={
                "Govern": [c.control_id for c in controls if c.control_id.startswith("GV")],
                "Identify": [c.control_id for c in controls if c.control_id.startswith("ID")],
                "Protect": [c.control_id for c in controls if c.control_id.startswith("PR")],
                "Detect": [c.control_id for c in controls if c.control_id.startswith("DE")],
                "Respond": [c.control_id for c in controls if c.control_id.startswith("RS")],
                "Recover": [c.control_id for c in controls if c.control_id.startswith("RC")],
            },
            effective_date="2024-02-26",
            update_frequency="as_needed",
            certification_available=False,
            maturity_model={
                "levels": ["Partial", "Risk Informed", "Repeatable", "Adaptive"],
                "assessment_criteria": "Implementation Tier Assessment",
            },
            implementation_tiers=["Tier 1", "Tier 2", "Tier 3", "Tier 4"],
            references=[
                "NIST SP 800-53",
                "ISO/IEC 27001",
                "CIS Controls",
                "COBIT",
            ],
            documentation_urls=[
                "https://www.nist.gov/cyberframework",
                "https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf",
            ],
        )

    def _get_nist_csf_controls(self, version: str) -> list[ControlDefinition]:
        """Define NIST CSF controls with evidence collection queries."""
        controls = []

        # ============================================================
        # GOVERN (GV) - New in CSF 2.0
        # ============================================================
        controls.extend([
            ControlDefinition(
                control_id="GV.OC-01",
                title="Organizational Context",
                description="The organizational mission is understood and informs cybersecurity risk management",
                category="Govern",
                control_type=ControlType.ADMINISTRATIVE,
                automation_level=AutomationLevel.MANUAL,
                testing_frequency=TestingFrequency.ANNUALLY,
                evidence_queries=[],
                evidence_collection_methods=["document_review", "interview"],
                remediation_guidance="Document organizational mission and ensure cybersecurity strategy aligns with business objectives",
                implementation_guidance="Establish cybersecurity governance committee with executive sponsorship",
                testing_procedures=[
                    "Review organizational mission statement",
                    "Assess cybersecurity strategy alignment",
                    "Interview stakeholders on risk tolerance",
                ],
                risk_level="medium",
                business_impact="Strategic - misalignment leads to ineffective security investments",
                tags={"function": "govern", "category": "context", "priority": "high"},
                references=["NIST CSF GV.OC-01"],
            ),
            ControlDefinition(
                control_id="GV.RM-01",
                title="Risk Management Strategy",
                description="Risk management objectives are established and agreed to by organizational stakeholders",
                category="Govern",
                control_type=ControlType.ADMINISTRATIVE,
                automation_level=AutomationLevel.SEMI_AUTOMATED,
                testing_frequency=TestingFrequency.QUARTERLY,
                evidence_queries=[
                    "SELECT policy_name, policy_type, status, last_reviewed FROM compliance_policies WHERE policy_type = 'risk_management'",
                ],
                evidence_collection_methods=["document_review", "sql_query"],
                remediation_guidance="Develop and document risk management strategy with clear risk appetite statements",
                implementation_guidance="Create risk register, define risk appetite, and establish risk governance processes",
                testing_procedures=[
                    "Review risk management policy",
                    "Validate risk appetite documentation",
                    "Assess risk governance effectiveness",
                ],
                risk_level="high",
                business_impact="High - undefined risk strategy leads to inconsistent security decisions",
                tags={"function": "govern", "category": "risk_management", "priority": "high"},
                references=["NIST CSF GV.RM-01", "NIST SP 800-39"],
            ),
            ControlDefinition(
                control_id="GV.SC-01",
                title="Supply Chain Risk Management",
                description=(
                    "Cybersecurity supply chain risk management processes are identified, "
                    "established, and agreed to by organizational stakeholders"
                ),
                category="Govern",
                control_type=ControlType.PREVENTIVE,
                automation_level=AutomationLevel.SEMI_AUTOMATED,
                testing_frequency=TestingFrequency.QUARTERLY,
                evidence_queries=[
                    "SELECT vendor_name, risk_rating, last_assessment, compliance_status FROM vendor_assessments WHERE status = 'active'",
                    "SELECT package_name, version, license, vulnerabilities FROM dependency_inventory WHERE is_direct = true",
                ],
                evidence_collection_methods=["sql_query", "vendor_assessment"],
                remediation_guidance="Establish supply chain risk management program with vendor assessment procedures",
                implementation_guidance="Implement vendor risk assessment process, dependency scanning, and SBOM generation",
                testing_procedures=[
                    "Review vendor risk assessment records",
                    "Validate third-party security requirements",
                    "Test dependency vulnerability scanning",
                ],
                risk_level="high",
                business_impact="High - supply chain compromise can affect entire organization",
                tags={"function": "govern", "category": "supply_chain", "priority": "high"},
                references=["NIST CSF GV.SC-01", "NIST SP 800-161"],
            ),
        ])

        # ============================================================
        # IDENTIFY (ID)
        # ============================================================
        controls.extend([
            ControlDefinition(
                control_id="ID.AM-01",
                title="Asset Management - Hardware Inventory",
                description="Inventories of hardware managed by the organization are maintained",
                category="Identify",
                control_type=ControlType.DETECTIVE,
                automation_level=AutomationLevel.AUTOMATED,
                testing_frequency=TestingFrequency.CONTINUOUS,
                evidence_queries=[
                    "SELECT device_id, hostname, os_type, last_seen, agent_version FROM endpoint_inventory",
                    "SELECT instance_id, instance_type, state, launch_time FROM aws_ec2_instance",
                    "SELECT name, machine_type, status, zone FROM gcp_compute_instance",
                    "SELECT id, vm_size, power_state, location FROM azure_virtual_machine",
                ],
                evidence_collection_methods=["sql_query", "api_query"],
                remediation_guidance="Deploy endpoint agents and cloud inventory tools to maintain comprehensive asset inventory",
                implementation_guidance="Implement automated asset discovery with regular reconciliation",
                testing_procedures=[
                    "Validate asset inventory completeness",
                    "Test automated discovery mechanisms",
                    "Reconcile inventory with network scans",
                ],
                risk_level="high",
                business_impact="High - unknown assets cannot be protected",
                tags={"function": "identify", "category": "asset_management", "priority": "high"},
                references=["NIST CSF ID.AM-01", "CIS Control 1"],
            ),
            ControlDefinition(
                control_id="ID.AM-02",
                title="Asset Management - Software Inventory",
                description="Inventories of software, services, and systems managed by the organization are maintained",
                category="Identify",
                control_type=ControlType.DETECTIVE,
                automation_level=AutomationLevel.AUTOMATED,
                testing_frequency=TestingFrequency.CONTINUOUS,
                evidence_queries=[
                    "SELECT package_name, version, publisher, install_date FROM software_inventory",
                    "SELECT name, runtime, memory, last_modified FROM aws_lambda_function",
                    "SELECT app_name, status, sign_on_mode FROM okta_application",
                    "SELECT name, full_name, visibility, default_branch FROM github_repository",
                ],
                evidence_collection_methods=["sql_query", "api_query"],
                remediation_guidance="Implement software inventory management with automated discovery",
                implementation_guidance="Deploy application inventory tools and integrate with CMDB",
                testing_procedures=[
                    "Validate software inventory accuracy",
                    "Test application discovery automation",
                    "Review unauthorized software detection",
                ],
                risk_level="high",
                business_impact="High - unmanaged software creates security blind spots",
                tags={"function": "identify", "category": "asset_management", "priority": "high"},
                references=["NIST CSF ID.AM-02", "CIS Control 2"],
            ),
            ControlDefinition(
                control_id="ID.RA-01",
                title="Risk Assessment",
                description="Vulnerabilities in assets are identified, validated, and recorded",
                category="Identify",
                control_type=ControlType.DETECTIVE,
                automation_level=AutomationLevel.AUTOMATED,
                testing_frequency=TestingFrequency.CONTINUOUS,
                evidence_queries=[
                    "SELECT cve_id, severity, affected_asset, status, discovered_at FROM vulnerability_findings WHERE status = 'open'",
                    "SELECT finding_type, severity, resource_id, description FROM security_findings WHERE status != 'resolved'",
                    "SELECT package_name, version, cve_ids, severity FROM dependency_vulnerabilities",
                ],
                evidence_collection_methods=["sql_query", "vulnerability_scanner"],
                remediation_guidance="Implement continuous vulnerability scanning with prioritized remediation",
                implementation_guidance="Deploy vulnerability management platform with automated scanning and ticketing integration",
                testing_procedures=[
                    "Validate vulnerability scan coverage",
                    "Test remediation SLA compliance",
                    "Review vulnerability trending",
                ],
                risk_level="critical",
                business_impact="Critical - unaddressed vulnerabilities lead to breaches",
                tags={"function": "identify", "category": "risk_assessment", "priority": "critical"},
                references=["NIST CSF ID.RA-01", "CIS Control 7"],
            ),
        ])

        # ============================================================
        # PROTECT (PR)
        # ============================================================
        controls.extend([
            ControlDefinition(
                control_id="PR.AA-01",
                title="Identity Management and Authentication",
                description="Identities and credentials for authorized users, services, and hardware are managed by the organization",
                category="Protect",
                control_type=ControlType.PREVENTIVE,
                automation_level=AutomationLevel.AUTOMATED,
                testing_frequency=TestingFrequency.QUARTERLY,
                evidence_queries=[
                    "SELECT username, status, mfa_enabled, last_login, created_at FROM okta_user",
                    "SELECT user_name, mfa_devices, access_keys, password_last_used FROM aws_iam_user",
                    "SELECT email, is_admin, two_factor_enabled FROM gcp_iam_service_account",
                    "SELECT login, two_factor_authentication FROM github_user",
                ],
                evidence_collection_methods=["sql_query", "api_query"],
                remediation_guidance="Implement centralized identity management with MFA enforcement",
                implementation_guidance="Deploy SSO with MFA, implement automated provisioning/deprovisioning",
                testing_procedures=[
                    "Validate MFA enforcement",
                    "Test provisioning/deprovisioning workflows",
                    "Review privileged account inventory",
                ],
                risk_level="high",
                business_impact="High - compromised identities enable unauthorized access",
                tags={"function": "protect", "category": "identity", "priority": "high"},
                references=["NIST CSF PR.AA-01", "NIST SP 800-63"],
            ),
            ControlDefinition(
                control_id="PR.AA-02",
                title="Access Control",
                description="Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed",
                category="Protect",
                control_type=ControlType.PREVENTIVE,
                automation_level=AutomationLevel.AUTOMATED,
                testing_frequency=TestingFrequency.QUARTERLY,
                evidence_queries=[
                    "SELECT role_name, permissions, assigned_users FROM okta_role",
                    "SELECT policy_name, policy_document, attached_entities FROM aws_iam_policy",
                    "SELECT role, members, resource FROM gcp_iam_binding",
                    "SELECT team_name, permission, repositories FROM github_team_permission",
                ],
                evidence_collection_methods=["sql_query", "api_query"],
                remediation_guidance="Implement role-based access control with regular access reviews",
                implementation_guidance="Define roles based on job functions, implement least privilege principle",
                testing_procedures=[
                    "Review access control policies",
                    "Test least privilege enforcement",
                    "Validate access review completion",
                ],
                risk_level="high",
                business_impact="High - excessive permissions increase breach impact",
                tags={"function": "protect", "category": "access_control", "priority": "high"},
                references=["NIST CSF PR.AA-02", "CIS Control 6"],
            ),
            ControlDefinition(
                control_id="PR.DS-01",
                title="Data Security - Data at Rest",
                description="The confidentiality, integrity, and availability of data-at-rest are protected",
                category="Protect",
                control_type=ControlType.PREVENTIVE,
                automation_level=AutomationLevel.AUTOMATED,
                testing_frequency=TestingFrequency.QUARTERLY,
                evidence_queries=[
                    "SELECT bucket_name, encryption_configuration, versioning_status FROM aws_s3_bucket",
                    "SELECT db_instance_id, storage_encrypted, kms_key_id FROM aws_rds_instance",
                    "SELECT name, encryption_state, kms_key_name FROM gcp_storage_bucket",
                    "SELECT name, sku_name, access_tier FROM azure_storage_account WHERE encryption_services IS NOT NULL",
                ],
                evidence_collection_methods=["sql_query", "api_query"],
                remediation_guidance="Enable encryption at rest for all data stores using managed encryption keys",
                implementation_guidance="Implement organization-wide encryption policies with KMS integration",
                testing_procedures=[
                    "Validate encryption at rest configuration",
                    "Test encryption key management",
                    "Review unencrypted data store detection",
                ],
                risk_level="high",
                business_impact="High - unencrypted data exposure in breach",
                tags={"function": "protect", "category": "data_security", "priority": "high"},
                references=["NIST CSF PR.DS-01", "CIS Control 3"],
            ),
            ControlDefinition(
                control_id="PR.DS-02",
                title="Data Security - Data in Transit",
                description="The confidentiality, integrity, and availability of data-in-transit are protected",
                category="Protect",
                control_type=ControlType.PREVENTIVE,
                automation_level=AutomationLevel.AUTOMATED,
                testing_frequency=TestingFrequency.QUARTERLY,
                evidence_queries=[
                    "SELECT distribution_id, viewer_protocol_policy, ssl_certificate FROM aws_cloudfront_distribution",
                    "SELECT load_balancer_name, listener_protocol, ssl_policy FROM aws_elb_listener WHERE listener_protocol = 'HTTPS'",
                    "SELECT name, protocol, certificate FROM gcp_load_balancer",
                ],
                evidence_collection_methods=["sql_query", "network_scan"],
                remediation_guidance="Enforce TLS 1.2+ for all network communications",
                implementation_guidance="Configure TLS policies, implement certificate management",
                testing_procedures=[
                    "Validate TLS configuration",
                    "Test certificate validity",
                    "Review insecure protocol usage",
                ],
                risk_level="high",
                business_impact="High - unencrypted transit enables interception",
                tags={"function": "protect", "category": "data_security", "priority": "high"},
                references=["NIST CSF PR.DS-02", "CIS Control 3"],
            ),
            ControlDefinition(
                control_id="PR.PS-01",
                title="Platform Security",
                description="Configuration management practices are applied",
                category="Protect",
                control_type=ControlType.PREVENTIVE,
                automation_level=AutomationLevel.AUTOMATED,
                testing_frequency=TestingFrequency.MONTHLY,
                evidence_queries=[
                    "SELECT resource_type, resource_id, compliance_status, finding FROM config_compliance_findings",
                    "SELECT check_id, status, severity, resource_id FROM aws_securityhub_finding WHERE compliance_status = 'FAILED'",
                    "SELECT finding_category, severity, resource_name FROM gcp_scc_finding WHERE state = 'ACTIVE'",
                ],
                evidence_collection_methods=["sql_query", "configuration_audit"],
                remediation_guidance="Implement secure configuration baselines with continuous monitoring",
                implementation_guidance="Deploy configuration management tools, implement hardening standards",
                testing_procedures=[
                    "Validate baseline compliance",
                    "Test configuration drift detection",
                    "Review remediation workflows",
                ],
                risk_level="medium",
                business_impact="Medium - misconfigurations create vulnerabilities",
                tags={"function": "protect", "category": "platform_security", "priority": "medium"},
                references=["NIST CSF PR.PS-01", "CIS Controls 4, 5"],
            ),
        ])

        # ============================================================
        # DETECT (DE)
        # ============================================================
        controls.extend([
            ControlDefinition(
                control_id="DE.CM-01",
                title="Continuous Monitoring - Networks",
                description="Networks and network services are monitored to find potentially adverse events",
                category="Detect",
                control_type=ControlType.DETECTIVE,
                automation_level=AutomationLevel.AUTOMATED,
                testing_frequency=TestingFrequency.CONTINUOUS,
                evidence_queries=[
                    "SELECT event_time, source_ip, destination_ip, action, log_status FROM aws_vpc_flow_log WHERE action = 'REJECT'",
                    "SELECT timestamp, src_ip, dest_ip, rule_name, action FROM gcp_firewall_log WHERE action = 'denied'",
                    "SELECT time_generated, source_ip, destination_ip, rule_name FROM azure_nsg_flow_log",
                ],
                evidence_collection_methods=["sql_query", "siem_query"],
                remediation_guidance="Implement network monitoring with threat detection capabilities",
                implementation_guidance="Deploy network monitoring tools, configure flow logs, integrate with SIEM",
                testing_procedures=[
                    "Validate network monitoring coverage",
                    "Test threat detection rules",
                    "Review alert response times",
                ],
                risk_level="high",
                business_impact="High - undetected network threats lead to breaches",
                tags={"function": "detect", "category": "monitoring", "priority": "high"},
                references=["NIST CSF DE.CM-01", "CIS Control 13"],
            ),
            ControlDefinition(
                control_id="DE.CM-03",
                title="Continuous Monitoring - Personnel Activity",
                description="Personnel activity and technology usage are monitored to find potentially adverse events",
                category="Detect",
                control_type=ControlType.DETECTIVE,
                automation_level=AutomationLevel.AUTOMATED,
                testing_frequency=TestingFrequency.CONTINUOUS,
                evidence_queries=[
                    "SELECT event_time, user_identity, event_name, source_ip FROM aws_cloudtrail_event WHERE error_code IS NOT NULL",
                    "SELECT timestamp, principal_email, method_name, resource_name FROM gcp_audit_log WHERE severity = 'ERROR'",
                    "SELECT event_time, actor, target, action FROM okta_system_log WHERE outcome = 'FAILURE'",
                ],
                evidence_collection_methods=["sql_query", "siem_query"],
                remediation_guidance="Implement user activity monitoring with behavioral analytics",
                implementation_guidance="Configure audit logging, deploy UEBA solutions, set up alerting",
                testing_procedures=[
                    "Validate audit log coverage",
                    "Test anomaly detection",
                    "Review privileged activity monitoring",
                ],
                risk_level="high",
                business_impact="High - insider threats and compromised accounts",
                tags={"function": "detect", "category": "monitoring", "priority": "high"},
                references=["NIST CSF DE.CM-03", "CIS Control 8"],
            ),
            ControlDefinition(
                control_id="DE.CM-06",
                title="Continuous Monitoring - Malicious Code",
                description="External service provider activities and services are monitored to find potentially adverse events",
                category="Detect",
                control_type=ControlType.DETECTIVE,
                automation_level=AutomationLevel.AUTOMATED,
                testing_frequency=TestingFrequency.CONTINUOUS,
                evidence_queries=[
                    "SELECT threat_id, hostname, severity, detection_time, status FROM endpoint_threat WHERE status = 'active'",
                    "SELECT detection_id, host_id, tactic, technique, severity FROM crowdstrike_detection",
                    "SELECT threat_name, classification, confidence, detected_at FROM sentinelone_threat",
                ],
                evidence_collection_methods=["sql_query", "edr_query"],
                remediation_guidance="Deploy endpoint detection and response (EDR) solutions organization-wide",
                implementation_guidance="Implement EDR with automated response capabilities",
                testing_procedures=[
                    "Validate EDR agent deployment",
                    "Test detection capabilities",
                    "Review response automation",
                ],
                risk_level="critical",
                business_impact="Critical - malware can destroy or exfiltrate data",
                tags={"function": "detect", "category": "monitoring", "priority": "critical"},
                references=["NIST CSF DE.CM-06", "CIS Control 10"],
            ),
            ControlDefinition(
                control_id="DE.AE-02",
                title="Adverse Event Analysis",
                description="Potentially adverse events are analyzed to better understand associated activities",
                category="Detect",
                control_type=ControlType.DETECTIVE,
                automation_level=AutomationLevel.SEMI_AUTOMATED,
                testing_frequency=TestingFrequency.CONTINUOUS,
                evidence_queries=[
                    (
                        "SELECT incident_id, severity, status, created_at, resolved_at "
                        "FROM security_incidents WHERE status IN ('open', 'investigating')"
                    ),
                    "SELECT alert_id, rule_name, severity, triggered_at, acknowledged_at FROM security_alerts",
                ],
                evidence_collection_methods=["sql_query", "siem_query", "incident_management"],
                remediation_guidance="Establish security operations with threat intelligence integration",
                implementation_guidance="Deploy SIEM, implement threat hunting program",
                testing_procedures=[
                    "Review incident analysis procedures",
                    "Test threat intelligence integration",
                    "Validate alert triage processes",
                ],
                risk_level="high",
                business_impact="High - poor analysis leads to missed threats",
                tags={"function": "detect", "category": "analysis", "priority": "high"},
                references=["NIST CSF DE.AE-02", "CIS Control 17"],
            ),
        ])

        # ============================================================
        # RESPOND (RS)
        # ============================================================
        controls.extend([
            ControlDefinition(
                control_id="RS.MA-01",
                title="Incident Management",
                description="Incidents are reported consistent with established criteria",
                category="Respond",
                control_type=ControlType.CORRECTIVE,
                automation_level=AutomationLevel.SEMI_AUTOMATED,
                testing_frequency=TestingFrequency.QUARTERLY,
                evidence_queries=[
                    "SELECT incident_id, severity, reporter, reported_at, status FROM security_incidents",
                    "SELECT case_id, priority, assigned_to, created_at, sla_status FROM incident_tickets",
                ],
                evidence_collection_methods=["sql_query", "incident_management"],
                remediation_guidance="Establish incident reporting procedures with clear escalation paths",
                implementation_guidance="Deploy incident management platform, define severity classifications",
                testing_procedures=[
                    "Test incident reporting workflows",
                    "Validate escalation procedures",
                    "Review SLA compliance",
                ],
                risk_level="high",
                business_impact="High - delayed response increases breach impact",
                tags={"function": "respond", "category": "incident_management", "priority": "high"},
                references=["NIST CSF RS.MA-01", "CIS Control 17"],
            ),
            ControlDefinition(
                control_id="RS.AN-03",
                title="Incident Analysis",
                description="Analysis is performed to understand what has happened and to support recovery activities",
                category="Respond",
                control_type=ControlType.CORRECTIVE,
                automation_level=AutomationLevel.SEMI_AUTOMATED,
                testing_frequency=TestingFrequency.QUARTERLY,
                evidence_queries=[
                    "SELECT incident_id, root_cause, impact_assessment, lessons_learned FROM incident_postmortems",
                    "SELECT investigation_id, findings, recommendations, completed_at FROM forensic_investigations",
                ],
                evidence_collection_methods=["document_review", "sql_query"],
                remediation_guidance="Conduct thorough incident analysis with root cause identification",
                implementation_guidance="Establish forensic capabilities, implement post-incident review process",
                testing_procedures=[
                    "Review incident analysis documentation",
                    "Test forensic investigation procedures",
                    "Validate root cause analysis quality",
                ],
                risk_level="medium",
                business_impact="Medium - poor analysis leads to recurring incidents",
                tags={"function": "respond", "category": "analysis", "priority": "medium"},
                references=["NIST CSF RS.AN-03", "NIST SP 800-61"],
            ),
            ControlDefinition(
                control_id="RS.MI-01",
                title="Incident Mitigation",
                description="Incidents are contained",
                category="Respond",
                control_type=ControlType.CORRECTIVE,
                automation_level=AutomationLevel.SEMI_AUTOMATED,
                testing_frequency=TestingFrequency.QUARTERLY,
                evidence_queries=[
                    (
                        "SELECT incident_id, containment_actions, containment_time, status "
                        "FROM incident_response_actions WHERE action_type = 'containment'"
                    ),
                    "SELECT host_id, isolation_status, isolated_at, isolated_by FROM endpoint_isolation",
                ],
                evidence_collection_methods=["sql_query", "incident_management"],
                remediation_guidance="Implement incident containment procedures with automated capabilities",
                implementation_guidance="Configure automated containment actions, establish isolation procedures",
                testing_procedures=[
                    "Test containment procedures",
                    "Validate automated response actions",
                    "Review containment effectiveness",
                ],
                risk_level="critical",
                business_impact="Critical - delayed containment increases damage",
                tags={"function": "respond", "category": "mitigation", "priority": "critical"},
                references=["NIST CSF RS.MI-01", "NIST SP 800-61"],
            ),
        ])

        # ============================================================
        # RECOVER (RC)
        # ============================================================
        controls.extend([
            ControlDefinition(
                control_id="RC.RP-01",
                title="Recovery Planning",
                description="Recovery activities are performed to ensure operational availability",
                category="Recover",
                control_type=ControlType.CORRECTIVE,
                automation_level=AutomationLevel.SEMI_AUTOMATED,
                testing_frequency=TestingFrequency.ANNUALLY,
                evidence_queries=[
                    "SELECT plan_id, plan_type, last_tested, test_result FROM disaster_recovery_plans",
                    "SELECT backup_job_id, status, backup_type, completion_time FROM backup_jobs WHERE backup_type = 'full'",
                ],
                evidence_collection_methods=["document_review", "sql_query"],
                remediation_guidance="Develop and test disaster recovery and business continuity plans",
                implementation_guidance="Implement backup solutions, document recovery procedures, conduct regular testing",
                testing_procedures=[
                    "Review DR/BC plans",
                    "Test recovery procedures",
                    "Validate backup restoration",
                ],
                risk_level="high",
                business_impact="High - poor recovery extends outages",
                tags={"function": "recover", "category": "planning", "priority": "high"},
                references=["NIST CSF RC.RP-01", "CIS Control 11"],
            ),
            ControlDefinition(
                control_id="RC.CO-03",
                title="Recovery Communications",
                description="Recovery activities and progress are communicated to designated internal and external stakeholders",
                category="Recover",
                control_type=ControlType.ADMINISTRATIVE,
                automation_level=AutomationLevel.MANUAL,
                testing_frequency=TestingFrequency.ANNUALLY,
                evidence_queries=[
                    "SELECT incident_id, communication_type, recipients, sent_at FROM incident_communications",
                ],
                evidence_collection_methods=["document_review", "sql_query"],
                remediation_guidance="Establish recovery communication procedures and stakeholder notification lists",
                implementation_guidance="Define communication templates, establish notification chains",
                testing_procedures=[
                    "Review communication procedures",
                    "Test notification systems",
                    "Validate stakeholder lists",
                ],
                risk_level="medium",
                business_impact="Medium - poor communication erodes trust",
                tags={"function": "recover", "category": "communications", "priority": "medium"},
                references=["NIST CSF RC.CO-03"],
            ),
        ])

        return controls

    def map_to_other_frameworks(self, control_id: str) -> dict[str, list[str]]:
        """Map NIST CSF controls to other frameworks."""
        mappings: dict[str, dict[str, list[str]]] = {
            "GV.RM-01": {
                "soc2": ["CC3.1", "CC3.2"],
                "iso27001": ["A.5.1", "A.6.1"],
            },
            "ID.AM-01": {
                "soc2": ["CC6.1"],
                "iso27001": ["A.8.1.1"],
                "cis": ["1.1", "1.2"],
            },
            "ID.AM-02": {
                "soc2": ["CC6.1"],
                "iso27001": ["A.8.1.1", "A.8.1.2"],
                "cis": ["2.1", "2.2"],
            },
            "ID.RA-01": {
                "soc2": ["CC3.2", "CC7.1"],
                "iso27001": ["A.12.6.1"],
                "cis": ["7.1", "7.2"],
            },
            "PR.AA-01": {
                "soc2": ["CC6.1", "CC6.2"],
                "iso27001": ["A.9.2.1", "A.9.2.2"],
                "cis": ["5.1", "5.2"],
            },
            "PR.AA-02": {
                "soc2": ["CC6.1", "CC6.3"],
                "iso27001": ["A.9.1.1", "A.9.2.3"],
                "cis": ["6.1", "6.2"],
            },
            "PR.DS-01": {
                "soc2": ["CC6.1", "C1.1"],
                "iso27001": ["A.8.2.3", "A.10.1.1"],
                "cis": ["3.11"],
            },
            "DE.CM-01": {
                "soc2": ["CC7.2"],
                "iso27001": ["A.12.4.1"],
                "cis": ["13.1", "13.2"],
            },
            "DE.CM-03": {
                "soc2": ["CC7.2", "CC7.3"],
                "iso27001": ["A.12.4.1", "A.12.4.3"],
                "cis": ["8.2", "8.5"],
            },
            "RS.MA-01": {
                "soc2": ["CC7.4", "CC7.5"],
                "iso27001": ["A.16.1.2", "A.16.1.4"],
                "cis": ["17.1", "17.2"],
            },
            "RC.RP-01": {
                "soc2": ["A1.2", "A1.3"],
                "iso27001": ["A.17.1.1", "A.17.1.2"],
                "cis": ["11.1", "11.2"],
            },
        }
        return mappings.get(control_id, {})

    def validate_control_implementation(
        self, control_id: str, evidence_data: Any
    ) -> bool:
        """Validate NIST CSF control implementation based on evidence.

        Args:
            control_id: The control ID to validate
            evidence_data: Evidence data from queries/collections

        Returns:
            True if control implementation is validated
        """
        if not evidence_data:
            return False

        # Control-specific validation
        if control_id.startswith("ID.AM"):
            # Asset Management - verify inventory exists
            return self._validate_asset_inventory(evidence_data)
        elif control_id.startswith("PR.AA"):
            # Access Control - verify IAM controls
            return self._validate_access_controls(evidence_data)
        elif control_id.startswith("PR.DS"):
            # Data Security - verify encryption
            return self._validate_data_security(evidence_data)
        elif control_id.startswith("DE.CM"):
            # Monitoring - verify detection capabilities
            return self._validate_monitoring(evidence_data)
        else:
            # Default validation - check if evidence exists
            return bool(evidence_data)

    def _validate_asset_inventory(self, evidence_data: Any) -> bool:
        """Validate asset inventory completeness."""
        try:
            if not isinstance(evidence_data, dict):
                return bool(evidence_data)

            # Check for asset data
            assets = evidence_data.get("assets", evidence_data.get("resources", []))
            return len(assets) > 0
        except Exception:
            return False

    def _validate_access_controls(self, evidence_data: Any) -> bool:
        """Validate access control implementation."""
        try:
            if not isinstance(evidence_data, dict):
                return bool(evidence_data)

            users = evidence_data.get("users", [])
            roles = evidence_data.get("roles", [])

            # Check MFA adoption
            mfa_users = [u for u in users if u.get("mfa_enabled")]
            mfa_rate = len(mfa_users) / len(users) if users else 0

            return len(users) > 0 and len(roles) > 0 and mfa_rate >= 0.8
        except Exception:
            return False

    def _validate_data_security(self, evidence_data: Any) -> bool:
        """Validate data security controls."""
        try:
            if not isinstance(evidence_data, dict):
                return bool(evidence_data)

            # Check encryption status
            resources = evidence_data.get("resources", [])
            encrypted = [r for r in resources if r.get("encrypted", False)]
            encryption_rate = len(encrypted) / len(resources) if resources else 0

            return encryption_rate >= 0.9
        except Exception:
            return False

    def _validate_monitoring(self, evidence_data: Any) -> bool:
        """Validate monitoring implementation."""
        try:
            if not isinstance(evidence_data, dict):
                return bool(evidence_data)

            # Check for monitoring data
            logs = evidence_data.get("logs", [])
            alerts = evidence_data.get("alerts", [])

            return len(logs) > 0 or len(alerts) > 0
        except Exception:
            return False
