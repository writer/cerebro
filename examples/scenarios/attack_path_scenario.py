#!/usr/bin/env python3
"""Attack Path Analysis Scenario

This scenario demonstrates attack path modeling and lateral movement analysis:
- Initial compromise vectors
- Privilege escalation paths
- Lateral movement possibilities
- Critical asset exposure
- Defense gap analysis
- Attack chain reconstruction

Attack Scenario:
1. Initial access via compromised developer workstation
2. Privilege escalation through misconfigured service account
3. Lateral movement to production environment
4. Data exfiltration from critical databases
5. Persistence through backdoor accounts
"""

from datetime import datetime, timedelta
from uuid import uuid4
from typing import List, Dict, Any


def generate_attack_path_scenario() -> Dict[str, Any]:
    """Generate attack path analysis scenario."""

    now = datetime.now()

    # Organization - Financial Services
    org_id = uuid4()
    org = {
        "org_id": org_id,
        "name": "SecureBank Corp",
        "created_at": datetime.now() - timedelta(days=1500),
    }

    # Network segments
    aws_prod_account = {
        "account_id": uuid4(),
        "org_id": org_id,
        "provider": "aws",
        "external_id": "777777777777",
        "display_name": "AWS Production DMZ",
    }

    aws_internal_account = {
        "account_id": uuid4(),
        "org_id": org_id,
        "provider": "aws",
        "external_id": "888888888888",
        "display_name": "AWS Internal Network",
    }

    github_account = {
        "account_id": uuid4(),
        "org_id": org_id,
        "provider": "github",
        "external_id": "securebank-corp",
        "display_name": "GitHub Development",
    }

    # Attack Path Assets

    # 1. Initial Access Point - Web Application
    web_app_server = {
        "resource_id": uuid4(),
        "account_id": aws_prod_account["account_id"],
        "provider": "aws",
        "resource_type": "ec2_instance",
        "external_id": "i-web-app-server-01",
        "name": "Customer Portal Web Server",
        "parent_external_id": None,
        "created_at": now - timedelta(days=600),
    }

    # 2. Stepping Stone - Development Server
    dev_server = {
        "resource_id": uuid4(),
        "account_id": aws_internal_account["account_id"],
        "provider": "aws",
        "resource_type": "ec2_instance",
        "external_id": "i-dev-build-server",
        "name": "Development Build Server",
        "parent_external_id": None,
        "created_at": now - timedelta(days=300),
    }

    # 3. Critical Target - Database Server
    core_database = {
        "resource_id": uuid4(),
        "account_id": aws_internal_account["account_id"],
        "provider": "aws",
        "resource_type": "rds_instance",
        "external_id": "prod-core-banking-db",
        "name": "Core Banking Database",
        "parent_external_id": None,
        "created_at": now - timedelta(days=1200),
    }

    # 4. High-Value Target - Backup System
    backup_system = {
        "resource_id": uuid4(),
        "account_id": aws_internal_account["account_id"],
        "provider": "aws",
        "resource_type": "s3_bucket",
        "external_id": "securebank-backup-vault",
        "name": "Enterprise Backup Vault",
        "parent_external_id": None,
        "created_at": now - timedelta(days=900),
    }

    # Attack Path Principals

    # Compromised developer
    compromised_dev = {
        "principal_id": uuid4(),
        "account_id": aws_prod_account["account_id"],
        "provider": "aws",
        "principal_type": "user",
        "external_id": "alex.developer",
        "email": "alex.developer@securebank.com",
        "display_name": "Alex Developer",
        "is_human": True,
    }

    # Overprivileged service account (pivot point)
    build_service = {
        "principal_id": uuid4(),
        "account_id": aws_internal_account["account_id"],
        "provider": "aws",
        "principal_type": "service_account",
        "external_id": "build-automation-service",
        "email": "build-automation@securebank.com",
        "display_name": "Build Automation Service",
        "is_human": False,
    }

    # Database service account (target)
    db_service = {
        "principal_id": uuid4(),
        "account_id": aws_internal_account["account_id"],
        "provider": "aws",
        "principal_type": "service_account",
        "external_id": "db-maintenance-service",
        "email": "db-maintenance@securebank.com",
        "display_name": "Database Maintenance Service",
        "is_human": False,
    }

    # IAM Attack Path Edges
    iam_edges = [
        # 1. Developer -> Web App (initial access)
        {
            "edge_id": uuid4(),
            "account_id": aws_prod_account["account_id"],
            "provider": "aws",
            "principal_id": compromised_dev["principal_id"],
            "resource_id": web_app_server["resource_id"],
            "permission": "ec2:DescribeInstances",
            "via": "DeveloperRole",
            "effective_at": now - timedelta(days=180),
            "expires_at": None,
            "is_admin": False,
        },
        # 2. Developer -> Cross-account access (privilege escalation)
        {
            "edge_id": uuid4(),
            "account_id": aws_internal_account["account_id"],
            "provider": "aws",
            "principal_id": compromised_dev["principal_id"],
            "resource_id": None,  # Cross-account role
            "permission": "sts:AssumeRole",
            "via": "CrossAccountDeveloperAccess",
            "effective_at": now - timedelta(days=180),
            "expires_at": None,
            "is_admin": False,
        },
        # 3. Build service -> Database access (lateral movement)
        {
            "edge_id": uuid4(),
            "account_id": aws_internal_account["account_id"],
            "provider": "aws",
            "principal_id": build_service["principal_id"],
            "resource_id": core_database["resource_id"],
            "permission": "rds:Connect",
            "via": "BuildServiceRole",
            "effective_at": now - timedelta(days=120),
            "expires_at": None,
            "is_admin": False,
        },
        # 4. Build service -> Backup access (data exfiltration path)
        {
            "edge_id": uuid4(),
            "account_id": aws_internal_account["account_id"],
            "provider": "aws",
            "principal_id": build_service["principal_id"],
            "resource_id": backup_system["resource_id"],
            "permission": "s3:GetObject",
            "via": "BuildServiceRole",
            "effective_at": now - timedelta(days=120),
            "expires_at": None,
            "is_admin": False,
        },
        # 5. Build service -> Admin escalation (persistence)
        {
            "edge_id": uuid4(),
            "account_id": aws_internal_account["account_id"],
            "provider": "aws",
            "principal_id": build_service["principal_id"],
            "resource_id": None,
            "permission": "iam:CreateUser",
            "via": "BuildServiceRole",
            "effective_at": now - timedelta(days=120),
            "expires_at": None,
            "is_admin": True,  # Escalation capability
        },
    ]

    # Attack Path Findings
    findings = [
        {
            "finding_id": uuid4(),
            "org_id": org_id,
            "account_id": aws_prod_account["account_id"],
            "provider": "aws",
            "rule_id": uuid4(),
            "rule_version": 1,
            "resource_id": web_app_server["resource_id"],
            "principal_id": compromised_dev["principal_id"],
            "first_seen": now - timedelta(days=7),
            "last_seen": now - timedelta(hours=2),
            "status": "open",
            "severity": "critical",
            "fingerprint": "attack-path-initial-access-vector",
            "title": "Critical Attack Path: Initial Access Vector Identified",
            "summary": "Developer account can access public-facing web server and pivot to internal network, creating a high-risk attack path to core banking systems.",
            "evidence": {
                "attack_path_length": 4,
                "initial_access": {
                    "vector": "Compromised developer credentials",
                    "entry_point": "Customer Portal Web Server",
                    "attack_surface": "SSH access + web application vulnerabilities",
                },
                "privilege_escalation": {
                    "method": "Cross-account role assumption",
                    "from": "Developer role (limited)",
                    "to": "Build service role (elevated)",
                },
                "lateral_movement": {
                    "stepping_stones": [
                        "Web server",
                        "Build server",
                        "Database access",
                    ],
                    "network_segmentation": "Insufficient between dev and prod",
                },
                "critical_assets_at_risk": [
                    "Core Banking Database (2.5M customer accounts)",
                    "Backup Vault (Complete system backups)",
                    "Transaction Processing System",
                    "Customer PII and Financial Records",
                ],
                "blast_radius_score": 98,
                "mttr_estimate": "2-4 weeks for full remediation",
            },
        },
        {
            "finding_id": uuid4(),
            "org_id": org_id,
            "account_id": aws_internal_account["account_id"],
            "provider": "aws",
            "rule_id": uuid4(),
            "rule_version": 1,
            "resource_id": None,
            "principal_id": build_service["principal_id"],
            "first_seen": now - timedelta(days=30),
            "last_seen": now - timedelta(hours=1),
            "status": "open",
            "severity": "critical",
            "fingerprint": "attack-path-privilege-escalation-node",
            "title": "Critical Attack Path: Privilege Escalation Node",
            "summary": "Build automation service account has excessive permissions enabling complete privilege escalation and persistence in the environment.",
            "evidence": {
                "escalation_capabilities": [
                    "Create IAM users and roles",
                    "Modify security policies",
                    "Access production databases",
                    "Read backup systems",
                ],
                "persistence_mechanisms": {
                    "backdoor_user_creation": "Possible",
                    "policy_modification": "Possible",
                    "key_manipulation": "Possible",
                },
                "lateral_movement_facilitation": {
                    "cross_account_access": "Enabled",
                    "service_impersonation": "Possible",
                    "resource_manipulation": "Full access",
                },
                "attack_chain_criticality": "Single point of failure in attack path",
                "defense_bypass": {
                    "monitoring": "Limited for service accounts",
                    "mfa": "Not required",
                    "session_controls": "Minimal",
                },
            },
        },
        {
            "finding_id": uuid4(),
            "org_id": org_id,
            "account_id": aws_internal_account["account_id"],
            "provider": "aws",
            "rule_id": uuid4(),
            "rule_version": 1,
            "resource_id": core_database["resource_id"],
            "principal_id": None,
            "first_seen": now - timedelta(days=14),
            "last_seen": now - timedelta(hours=3),
            "status": "open",
            "severity": "high",
            "fingerprint": "attack-path-critical-asset-exposure",
            "title": "Attack Path: Critical Asset Exposure",
            "summary": "Core banking database is accessible through identified attack path with insufficient protection against lateral movement attacks.",
            "evidence": {
                "asset_classification": "Tier 1 Critical",
                "data_sensitivity": {
                    "customer_accounts": 2500000,
                    "transaction_records": "5+ years historical",
                    "financial_data": "Complete banking profiles",
                    "regulatory_scope": ["PCI DSS", "SOX", "GDPR"],
                },
                "attack_path_distance": 3,  # 3 hops from initial compromise
                "access_controls": {
                    "network_segmentation": "Insufficient",
                    "database_level_auth": "Service account based",
                    "encryption": "At rest only",
                    "activity_monitoring": "Basic audit logs",
                },
                "potential_impact": {
                    "data_breach_scope": "Complete customer database",
                    "regulatory_fines": "$50M - $100M+",
                    "business_disruption": "Complete banking operations",
                    "reputation_damage": "Severe",
                },
            },
        },
        {
            "finding_id": uuid4(),
            "org_id": org_id,
            "account_id": aws_internal_account["account_id"],
            "provider": "aws",
            "rule_id": uuid4(),
            "rule_version": 1,
            "resource_id": backup_system["resource_id"],
            "principal_id": build_service["principal_id"],
            "first_seen": now - timedelta(days=5),
            "last_seen": now - timedelta(hours=4),
            "status": "open",
            "severity": "high",
            "fingerprint": "attack-path-data-exfiltration-vector",
            "title": "Attack Path: Data Exfiltration Vector",
            "summary": "Attack path leads to backup system containing complete enterprise data, enabling massive data exfiltration with minimal detection.",
            "evidence": {
                "exfiltration_potential": {
                    "data_volume": "2.5TB complete system backups",
                    "data_types": [
                        "Customer databases",
                        "Application source code",
                        "Configuration data",
                        "Security policies",
                    ],
                    "exfiltration_methods": [
                        "Direct S3 download",
                        "Cross-region replication",
                        "External sharing",
                    ],
                },
                "detection_evasion": {
                    "legitimate_service_account": True,
                    "normal_backup_patterns": "Could mask exfiltration",
                    "monitoring_gaps": [
                        "No data volume alerts",
                        "No unusual access pattern detection",
                    ],
                },
                "business_impact": {
                    "complete_data_loss": "Possible",
                    "competitor_advantage": "Severe risk",
                    "recovery_complexity": "Months to rebuild",
                    "customer_trust": "Irreparable damage",
                },
            },
        },
    ]

    return {
        "scenario_name": "Attack Path Analysis",
        "organization": org,
        "accounts": [aws_prod_account, aws_internal_account, github_account],
        "principals": [compromised_dev, build_service, db_service],
        "resources": [web_app_server, dev_server, core_database, backup_system],
        "iam_edges": iam_edges,
        "findings": findings,
        "attack_analysis": {
            "attack_chains": [
                {
                    "chain_id": "primary_attack_path",
                    "description": "Developer compromise -> Build service escalation -> Database access",
                    "steps": [
                        {
                            "step": 1,
                            "action": "Initial access",
                            "asset": "Developer workstation",
                            "method": "Credential compromise",
                        },
                        {
                            "step": 2,
                            "action": "Privilege escalation",
                            "asset": "Web server",
                            "method": "SSH access + vulnerabilities",
                        },
                        {
                            "step": 3,
                            "action": "Lateral movement",
                            "asset": "Build server",
                            "method": "Cross-account role assumption",
                        },
                        {
                            "step": 4,
                            "action": "Privilege escalation",
                            "asset": "Build service account",
                            "method": "Service account impersonation",
                        },
                        {
                            "step": 5,
                            "action": "Data access",
                            "asset": "Core database",
                            "method": "Database connection",
                        },
                        {
                            "step": 6,
                            "action": "Data exfiltration",
                            "asset": "Backup system",
                            "method": "S3 download",
                        },
                    ],
                    "likelihood": "High",
                    "impact": "Critical",
                    "risk_score": 95,
                }
            ],
            "defense_gaps": [
                "Network segmentation between dev and prod",
                "Service account privilege management",
                "Cross-account access controls",
                "Data access monitoring",
                "Lateral movement detection",
            ],
            "critical_nodes": [
                {
                    "asset": "Build service account",
                    "criticality": "Single point of failure",
                },
                {
                    "asset": "Cross-account role",
                    "criticality": "Privilege escalation enabler",
                },
                {"asset": "Core database", "criticality": "High-value target"},
            ],
        },
        "investigation_notes": {
            "priority": "P0 - Active Threat Modeling",
            "business_impact": "Complete enterprise compromise possible via identified attack path",
            "attack_path_length": 4,
            "critical_assets_at_risk": 4,
            "estimated_breach_cost": "$50M - $100M+",
            "remediation_urgency": "Immediate - within 48 hours",
            "stakeholders": [
                "CISO",
                "Incident Response Team",
                "Network Security",
                "Application Security",
            ],
        },
        "agent_prompts": [
            "Show me the complete attack path from initial compromise to critical assets",
            "What are the key nodes that enable privilege escalation in this attack chain?",
            "Identify all defense gaps that allow this attack path to succeed",
            "What's the blast radius if an attacker follows this path?",
            "Generate specific remediation steps to break this attack chain",
            "Show me alternative attack paths that could reach the same critical assets",
            "What monitoring and detection controls would identify this attack?",
            "Prioritize the most critical security controls to implement first",
        ],
    }


def print_attack_path_summary(scenario: Dict[str, Any]):
    """Print attack path analysis summary."""
    print(f"=== {scenario['scenario_name']} ===")
    print(f"Organization: {scenario['organization']['name']}")

    attack_analysis = scenario["attack_analysis"]
    primary_chain = attack_analysis["attack_chains"][0]

    print(f"Primary Attack Chain Risk Score: {primary_chain['risk_score']}/100")
    print(f"Attack Path Length: {len(primary_chain['steps'])} steps")
    print()

    print("Attack Chain Steps:")
    for step in primary_chain["steps"]:
        print(f"  {step['step']}. {step['action']} → {step['asset']}")
        print(f"     Method: {step['method']}")
    print()

    print("Critical Findings:")
    for finding in scenario["findings"]:
        print(f"  • [{finding['severity'].upper()}] {finding['title']}")
    print()

    print("Defense Gaps:")
    for gap in attack_analysis["defense_gaps"]:
        print(f"  • {gap}")
    print()

    print(
        f"Estimated Breach Cost: {scenario['investigation_notes']['estimated_breach_cost']}"
    )
    print(
        f"Remediation Urgency: {scenario['investigation_notes']['remediation_urgency']}"
    )


if __name__ == "__main__":
    scenario = generate_attack_path_scenario()
    print_attack_path_summary(scenario)
