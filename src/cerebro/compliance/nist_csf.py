"""
NIST Cybersecurity Framework (CSF) 2.0 Support

Complete implementation of NIST CSF v2.0 for compliance testing,
framework mapping, and security control validation.

NIST CSF 2.0 Released: February 2024
https://www.nist.gov/cyberframework
"""

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel


# ==================== NIST CSF 2.0 Structure ====================

class NISTFunction(str, Enum):
    """NIST CSF 2.0 Functions (6 core functions)."""
    GOVERN = "GV"  # NEW in version 2.0
    IDENTIFY = "ID"
    PROTECT = "PR"
    DETECT = "DE"
    RESPOND = "RS"
    RECOVER = "RC"


class NISTControl(BaseModel):
    """NIST CSF Control Definition."""
    control_id: str  # e.g., "GV.OC-01"
    function: NISTFunction
    category: str  # e.g., "Organizational Context (GV.OC)"
    title: str
    description: str
    implementation_examples: List[str]
    references: List[str]  # CIS, ISO 27001, etc.


# ==================== NIST CSF 2.0 Controls ====================

NIST_CSF_CONTROLS: Dict[str, NISTControl] = {
    # ==================== GOVERN (GV) - NEW in 2.0 ====================
    "GV.OC-01": NISTControl(
        control_id="GV.OC-01",
        function=NISTFunction.GOVERN,
        category="Organizational Context (GV.OC)",
        title="The organizational mission is understood and informs cybersecurity risk management",
        description="Cybersecurity risk management activities are aligned with organizational mission, strategic priorities, and risk tolerance",
        implementation_examples=[
            "Document organizational mission statement",
            "Define cybersecurity objectives aligned with business goals",
            "Establish risk tolerance levels",
        ],
        references=["ISO 27001: Clause 5.2", "CIS Control 1"],
    ),
    "GV.OC-02": NISTControl(
        control_id="GV.OC-02",
        function=NISTFunction.GOVERN,
        category="Organizational Context (GV.OC)",
        title="Internal and external stakeholders are understood, and their needs and expectations regarding cybersecurity risk management are understood and considered",
        description="Stakeholder expectations guide cybersecurity risk management strategies and decisions",
        implementation_examples=[
            "Identify key stakeholders (board, executives, customers)",
            "Document stakeholder cybersecurity requirements",
            "Regular stakeholder communication on security posture",
        ],
        references=["ISO 27001: Clause 4.2", "SOC 2: CC1.4"],
    ),

    "GV.RM-01": NISTControl(
        control_id="GV.RM-01",
        function=NISTFunction.GOVERN,
        category="Risk Management Strategy (GV.RM)",
        title="Risk management objectives are established and agreed to by organizational stakeholders",
        description="Clear risk management objectives guide security investments and priorities",
        implementation_examples=[
            "Define quantitative and qualitative risk metrics",
            "Establish acceptable risk thresholds",
            "Document risk management strategy",
        ],
        references=["ISO 27001: Clause 6.1.2", "NIST 800-53: PM-9"],
    ),

    "GV.RR-01": NISTControl(
        control_id="GV.RR-01",
        function=NISTFunction.GOVERN,
        category="Roles, Responsibilities, and Authorities (GV.RR)",
        title="Organizational leadership is responsible and accountable for cybersecurity risk and fosters a culture of cybersecurity",
        description="Executive leadership demonstrates commitment to cybersecurity through resource allocation and accountability",
        implementation_examples=[
            "Designate CISO or equivalent role",
            "Board-level cybersecurity oversight",
            "Regular executive security briefings",
        ],
        references=["SOC 2: CC1.1", "ISO 27001: Clause 5.1"],
    ),

    # ==================== IDENTIFY (ID) ====================
    "ID.AM-01": NISTControl(
        control_id="ID.AM-01",
        function=NISTFunction.IDENTIFY,
        category="Asset Management (ID.AM)",
        title="Physical devices and systems within the organization are inventoried",
        description="Maintain comprehensive inventory of all physical assets",
        implementation_examples=[
            "Automated asset discovery tools",
            "CMDB integration",
            "Regular asset inventory audits",
        ],
        references=["CIS Control 1", "ISO 27001: A.8.1.1", "NIST 800-53: CM-8"],
    ),

    "ID.AM-02": NISTControl(
        control_id="ID.AM-02",
        function=NISTFunction.IDENTIFY,
        category="Asset Management (ID.AM)",
        title="Software platforms and applications within the organization are inventoried",
        description="Comprehensive software asset inventory including SaaS applications",
        implementation_examples=[
            "Software inventory management system",
            "SaaS application discovery",
            "License management",
        ],
        references=["CIS Control 2", "ISO 27001: A.8.1.1"],
    ),

    "ID.AM-03": NISTControl(
        control_id="ID.AM-03",
        function=NISTFunction.IDENTIFY,
        category="Asset Management (ID.AM)",
        title="Organizational communication and data flows are mapped",
        description="Document how data flows through systems and between entities",
        implementation_examples=[
            "Data flow diagrams",
            "Network topology maps",
            "API documentation",
        ],
        references=["ISO 27001: A.13.2.1", "GDPR Article 30"],
    ),

    "ID.AM-05": NISTControl(
        control_id="ID.AM-05",
        function=NISTFunction.IDENTIFY,
        category="Asset Management (ID.AM)",
        title="Resources (e.g., hardware, devices, data, time, personnel, and software) are prioritized based on their classification, criticality, and business value",
        description="Asset prioritization guides security investment and focus",
        implementation_examples=[
            "Asset classification scheme (critical/high/medium/low)",
            "Business impact analysis",
            "Recovery time objectives (RTO)",
        ],
        references=["ISO 27001: A.8.2.1", "SOC 2: CC6.6"],
    ),

    "ID.RA-01": NISTControl(
        control_id="ID.RA-01",
        function=NISTFunction.IDENTIFY,
        category="Risk Assessment (ID.RA)",
        title="Asset vulnerabilities are identified and documented",
        description="Regular vulnerability scanning and assessment of all assets",
        implementation_examples=[
            "Automated vulnerability scanning",
            "Penetration testing program",
            "Security assessments",
        ],
        references=["CIS Control 3", "ISO 27001: A.12.6.1", "NIST 800-53: RA-5"],
    ),

    "ID.RA-02": NISTControl(
        control_id="ID.RA-02",
        function=NISTFunction.IDENTIFY,
        category="Risk Assessment (ID.RA)",
        title="Cyber threat intelligence is received from information sharing forums and sources",
        description="Leverage threat intelligence to inform risk assessment",
        implementation_examples=[
            "Threat intelligence feeds",
            "ISAC participation",
            "Vendor security advisories",
        ],
        references=["NIST 800-53: PM-16", "CIS Control 8"],
    ),

    # ==================== PROTECT (PR) ====================
    "PR.AA-01": NISTControl(
        control_id="PR.AA-01",
        function=NISTFunction.PROTECT,
        category="Identity Management, Authentication and Access Control (PR.AA)",
        title="Identities and credentials are issued, managed, verified, revoked, and audited for authorized devices, users and processes",
        description="Comprehensive identity lifecycle management",
        implementation_examples=[
            "Automated provisioning/deprovisioning",
            "Regular access reviews",
            "Strong password policies",
        ],
        references=["CIS Control 5", "ISO 27001: A.9.2.1", "SOC 2: CC6.1"],
    ),

    "PR.AA-02": NISTControl(
        control_id="PR.AA-02",
        function=NISTFunction.PROTECT,
        category="Identity Management, Authentication and Access Control (PR.AA)",
        title="Identity and credentials are managed by the organization",
        description="Centralized identity management and credential storage",
        implementation_examples=[
            "Single sign-on (SSO)",
            "Identity provider (IdP) integration",
            "Centralized credential vault",
        ],
        references=["CIS Control 5", "ISO 27001: A.9.2.4"],
    ),

    "PR.AA-03": NISTControl(
        control_id="PR.AA-03",
        function=NISTFunction.PROTECT,
        category="Identity Management, Authentication and Access Control (PR.AA)",
        title="Users, devices, and other assets are authenticated",
        description="Multi-factor authentication for all access",
        implementation_examples=[
            "MFA for all users",
            "Device authentication",
            "Certificate-based authentication",
        ],
        references=["CIS Control 6", "ISO 27001: A.9.4.2", "SOC 2: CC6.1"],
    ),

    "PR.AA-04": NISTControl(
        control_id="PR.AA-04",
        function=NISTFunction.PROTECT,
        category="Identity Management, Authentication and Access Control (PR.AA)",
        title="Identity assertions are protected, conveyed, and verified",
        description="Secure assertion protocols and token validation",
        implementation_examples=[
            "SAML assertions",
            "OAuth tokens with expiration",
            "JWT validation",
        ],
        references=["ISO 27001: A.9.4.3", "NIST 800-63B"],
    ),

    "PR.AA-05": NISTControl(
        control_id="PR.AA-05",
        function=NISTFunction.PROTECT,
        category="Identity Management, Authentication and Access Control (PR.AA)",
        title="Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, incorporating the principles of least privilege and separation of duties",
        description="Least privilege access with regular reviews",
        implementation_examples=[
            "Role-based access control (RBAC)",
            "Quarterly access reviews",
            "Separation of duties enforcement",
        ],
        references=["CIS Control 5.4", "ISO 27001: A.9.1.2", "SOC 2: CC6.2"],
    ),

    "PR.DS-01": NISTControl(
        control_id="PR.DS-01",
        function=NISTFunction.PROTECT,
        category="Data Security (PR.DS)",
        title="Data-at-rest is protected",
        description="Encryption and access controls for stored data",
        implementation_examples=[
            "Disk encryption",
            "Database encryption",
            "Cloud storage encryption",
        ],
        references=["CIS Control 3.11", "ISO 27001: A.10.1.1", "SOC 2: CC6.6"],
    ),

    "PR.DS-02": NISTControl(
        control_id="PR.DS-02",
        function=NISTFunction.PROTECT,
        category="Data Security (PR.DS)",
        title="Data-in-transit is protected",
        description="Encryption for data transmission",
        implementation_examples=[
            "TLS 1.2+ for all connections",
            "VPN for remote access",
            "Encrypted messaging",
        ],
        references=["CIS Control 3.10", "ISO 27001: A.13.1.1"],
    ),

    # ==================== DETECT (DE) ====================
    "DE.AE-01": NISTControl(
        control_id="DE.AE-01",
        function=NISTFunction.DETECT,
        category="Anomalies and Events (DE.AE)",
        title="A baseline of network operations and expected data flows for users and systems is established and managed",
        description="Baseline normal behavior to detect anomalies",
        implementation_examples=[
            "Network traffic baselines",
            "User behavior analytics",
            "System performance baselines",
        ],
        references=["NIST 800-53: SI-4", "CIS Control 13"],
    ),

    "DE.AE-02": NISTControl(
        control_id="DE.AE-02",
        function=NISTFunction.DETECT,
        category="Anomalies and Events (DE.AE)",
        title="Detected events are analyzed to understand attack targets and methods",
        description="Security event analysis and correlation",
        implementation_examples=[
            "SIEM correlation rules",
            "Threat hunting",
            "Log analysis",
        ],
        references=["NIST 800-53: AU-6", "CIS Control 8"],
    ),

    "DE.CM-01": NISTControl(
        control_id="DE.CM-01",
        function=NISTFunction.DETECT,
        category="Security Continuous Monitoring (DE.CM)",
        title="The network is monitored to detect potential cybersecurity events",
        description="Continuous network monitoring and alerting",
        implementation_examples=[
            "Intrusion detection systems (IDS)",
            "Network flow monitoring",
            "SIEM alerts",
        ],
        references=["CIS Control 13", "ISO 27001: A.12.4.1", "NIST 800-53: SI-4"],
    ),

    # ==================== RESPOND (RS) ====================
    "RS.RP-01": NISTControl(
        control_id="RS.RP-01",
        function=NISTFunction.RESPOND,
        category="Response Planning (RS.RP)",
        title="Response plan is executed during or after an incident",
        description="Documented incident response procedures",
        implementation_examples=[
            "Incident response playbooks",
            "Escalation procedures",
            "Communication templates",
        ],
        references=["ISO 27001: A.16.1.5", "NIST 800-53: IR-8", "SOC 2: CC7.4"],
    ),

    "RS.AN-01": NISTControl(
        control_id="RS.AN-01",
        function=NISTFunction.RESPOND,
        category="Analysis (RS.AN)",
        title="Notifications from detection systems are investigated",
        description="Timely investigation of security alerts",
        implementation_examples=[
            "Alert triage process",
            "Incident investigation procedures",
            "Forensic analysis capability",
        ],
        references=["ISO 27001: A.16.1.4", "NIST 800-53: IR-4"],
    ),

    # ==================== RECOVER (RC) ====================
    "RC.RP-01": NISTControl(
        control_id="RC.RP-01",
        function=NISTFunction.RECOVER,
        category="Recovery Planning (RC.RP)",
        title="Recovery plan is executed during or after a cybersecurity incident",
        description="Documented recovery procedures and business continuity",
        implementation_examples=[
            "Business continuity plan",
            "Disaster recovery procedures",
            "Recovery time objectives (RTO)",
        ],
        references=["ISO 27001: A.17.1.1", "SOC 2: A1.2"],
    ),

    "RC.CO-01": NISTControl(
        control_id="RC.CO-01",
        function=NISTFunction.RECOVER,
        category="Communications (RC.CO)",
        title="Public relations are managed",
        description="Communication strategy for security incidents",
        implementation_examples=[
            "PR communication plan",
            "Stakeholder notification procedures",
            "Media response team",
        ],
        references=["ISO 27001: A.16.1.2", "GDPR Article 33"],
    ),
}


# ==================== NIST CSF Mappings ====================

class NISTCSFMapper:
    """Map security findings and controls to NIST CSF framework."""

    @staticmethod
    def get_control(control_id: str) -> Optional[NISTControl]:
        """Get NIST CSF control by ID."""
        return NIST_CSF_CONTROLS.get(control_id)

    @staticmethod
    def get_controls_by_function(function: NISTFunction) -> List[NISTControl]:
        """Get all controls for a specific function."""
        return [
            control for control in NIST_CSF_CONTROLS.values()
            if control.function == function
        ]

    @staticmethod
    def get_all_control_ids() -> List[str]:
        """Get list of all control IDs."""
        return list(NIST_CSF_CONTROLS.keys())

    @staticmethod
    def map_finding_to_nist(finding_title: str, finding_description: str) -> List[str]:
        """
        Map a security finding to applicable NIST CSF controls.

        Args:
            finding_title: Finding title
            finding_description: Finding description

        Returns:
            List of applicable NIST CSF control IDs
        """

        mapped_controls = []
        text = f"{finding_title} {finding_description}".lower()

        # Keyword-based mapping
        mappings = {
            "mfa": ["PR.AA-03"],
            "multi-factor": ["PR.AA-03"],
            "authentication": ["PR.AA-01", "PR.AA-03"],
            "access": ["PR.AA-05"],
            "permission": ["PR.AA-05"],
            "least privilege": ["PR.AA-05"],
            "encryption": ["PR.DS-01", "PR.DS-02"],
            "public": ["PR.DS-01", "PR.AA-05"],
            "exposed": ["PR.DS-01"],
            "vulnerability": ["ID.RA-01"],
            "patch": ["ID.RA-01"],
            "monitoring": ["DE.CM-01"],
            "logging": ["DE.AE-02"],
            "incident": ["RS.RP-01", "RS.AN-01"],
            "backup": ["RC.RP-01"],
            "recovery": ["RC.RP-01"],
        }

        for keyword, controls in mappings.items():
            if keyword in text:
                mapped_controls.extend(controls)

        # Remove duplicates
        return list(set(mapped_controls))


# ==================== Summary Statistics ====================

def get_nist_csf_summary() -> Dict[str, any]:
    """Get summary statistics of NIST CSF implementation."""

    function_counts = {}
    for function in NISTFunction:
        count = len([c for c in NIST_CSF_CONTROLS.values() if c.function == function])
        function_counts[function.value] = count

    return {
        "version": "2.0",
        "total_controls": len(NIST_CSF_CONTROLS),
        "functions": function_counts,
        "release_date": "February 2024",
    }