#!/usr/bin/env python3
"""Critical IAM Finding Scenario - Overprivileged Service Accounts

This scenario demonstrates a common enterprise security issue where service accounts
have accumulated excessive permissions across multiple cloud providers.

Key Security Issues:
- Service account with full admin access across AWS and GCP
- Unused high-privilege permissions for 90+ days
- Cross-account access from development to production
- Shadow IT discovery through OAuth applications
"""

from datetime import datetime, timedelta
from uuid import uuid4
from typing import List, Dict, Any


def generate_critical_iam_scenario() -> Dict[str, Any]:
    """Generate critical IAM scenario with overprivileged service accounts."""

    # Organization
    org_id = uuid4()
    org = {
        "org_id": org_id,
        "name": "TechCorp Industries",
        "created_at": datetime.now() - timedelta(days=365),
    }

    # AWS Production Account
    aws_prod_account = {
        "account_id": uuid4(),
        "org_id": org_id,
        "provider": "aws",
        "external_id": "123456789012",
        "display_name": "AWS Production",
    }

    # GCP Production Project
    gcp_prod_account = {
        "account_id": uuid4(),
        "org_id": org_id,
        "provider": "gcp",
        "external_id": "techcorp-prod-2024",
        "display_name": "GCP Production",
    }

    # Critical Service Account - Analytics Pipeline
    analytics_service_account = {
        "principal_id": uuid4(),
        "account_id": aws_prod_account["account_id"],
        "provider": "aws",
        "principal_type": "service_account",
        "external_id": "analytics-pipeline-sa",
        "email": "analytics-pipeline@techcorp.iam.gserviceaccount.com",
        "display_name": "Analytics Pipeline Service Account",
        "is_human": False,
    }

    # Overprivileged IAM Edges
    now = datetime.now()
    iam_edges = [
        # AWS Admin access - CRITICAL
        {
            "edge_id": uuid4(),
            "account_id": aws_prod_account["account_id"],
            "provider": "aws",
            "principal_id": analytics_service_account["principal_id"],
            "resource_id": None,  # Global permission
            "permission": "iam:*",
            "via": "AdministratorAccess",
            "effective_at": now - timedelta(days=120),
            "expires_at": None,
            "is_admin": True,
        },
        # S3 Full access - Used but excessive
        {
            "edge_id": uuid4(),
            "account_id": aws_prod_account["account_id"],
            "provider": "aws",
            "principal_id": analytics_service_account["principal_id"],
            "resource_id": None,
            "permission": "s3:*",
            "via": "S3FullAccess",
            "effective_at": now - timedelta(days=120),
            "expires_at": None,
            "is_admin": False,
        },
        # EC2 Full access - UNUSED for 90 days
        {
            "edge_id": uuid4(),
            "account_id": aws_prod_account["account_id"],
            "provider": "aws",
            "principal_id": analytics_service_account["principal_id"],
            "resource_id": None,
            "permission": "ec2:*",
            "via": "EC2FullAccess",
            "effective_at": now - timedelta(days=120),
            "expires_at": None,
            "is_admin": False,
        },
    ]

    # Critical Resources
    prod_database = {
        "resource_id": uuid4(),
        "account_id": aws_prod_account["account_id"],
        "provider": "aws",
        "resource_type": "rds_instance",
        "external_id": "prod-customer-db",
        "name": "Production Customer Database",
        "parent_external_id": None,
        "created_at": now - timedelta(days=200),
    }

    # Critical Findings
    findings = [
        {
            "finding_id": uuid4(),
            "org_id": org_id,
            "account_id": aws_prod_account["account_id"],
            "provider": "aws",
            "rule_id": uuid4(),  # Will be created by rule
            "rule_version": 1,
            "resource_id": None,
            "principal_id": analytics_service_account["principal_id"],
            "first_seen": now - timedelta(hours=1),
            "last_seen": now,
            "status": "open",
            "severity": "critical",
            "fingerprint": "service-account-admin-access-analytics-pipeline",
            "title": "Service Account Has Excessive Administrative Permissions",
            "summary": "Analytics Pipeline service account has full IAM administrative access across AWS production account. This violates principle of least privilege and creates significant blast radius for potential compromise.",
            "evidence": {
                "permissions": ["iam:*", "s3:*", "ec2:*"],
                "unused_permissions": ["ec2:*"],
                "unused_duration_days": 93,
                "blast_radius_score": 95,
                "affected_resources": 1247,
                "similar_issues": 3,
            },
        },
        {
            "finding_id": uuid4(),
            "org_id": org_id,
            "account_id": aws_prod_account["account_id"],
            "provider": "aws",
            "rule_id": uuid4(),
            "rule_version": 1,
            "resource_id": prod_database["resource_id"],
            "principal_id": analytics_service_account["principal_id"],
            "first_seen": now - timedelta(days=2),
            "last_seen": now,
            "status": "open",
            "severity": "high",
            "fingerprint": "direct-database-access-service-account",
            "title": "Service Account Has Direct Database Access",
            "summary": "Analytics service account can directly access production customer database, bypassing application-layer controls and audit trails.",
            "evidence": {
                "database_permissions": ["rds:Connect", "rds:Describe*"],
                "customer_data_access": True,
                "encryption_bypass": True,
                "audit_trail_gaps": ["direct_connection_logs"],
            },
        },
    ]

    # Supporting Rules
    rules = [
        {
            "rule_id": findings[0]["rule_id"],
            "policy_id": None,
            "name": "Service Account Administrative Access",
            "description": "Detects service accounts with administrative permissions",
            "provider": ["aws", "gcp"],
            "resource_types": None,
            "expression_lang": "cel",
            "expression": """
            has(principal.permissions) && 
            principal.is_human == false && 
            exists(principal.permissions, p, p.matches(".*:.*\\*.*")) &&
            principal.unused_permissions_days > 60
            """,
            "severity": "critical",
            "cwe": ["CWE-250", "CWE-266"],
            "cis": ["CIS-1.16", "CIS-1.22"],
            "nist_800_53": ["AC-2", "AC-6"],
            "mitre_attack": ["T1098", "T1078"],
            "version": 1,
            "is_active": True,
            "created_at": now - timedelta(days=30),
        }
    ]

    return {
        "scenario_name": "Critical IAM Finding",
        "organization": org,
        "accounts": [aws_prod_account, gcp_prod_account],
        "principals": [analytics_service_account],
        "resources": [prod_database],
        "iam_edges": iam_edges,
        "rules": rules,
        "findings": findings,
        "investigation_notes": {
            "priority": "P0 - Critical",
            "business_impact": "Potential for complete AWS account compromise",
            "remediation_effort": "2-4 hours",
            "stakeholders": ["Security Team", "DevOps", "Analytics Team"],
            "compliance_risk": "SOX, PCI DSS violations if exploited",
        },
        "agent_prompts": [
            "What are the most critical IAM findings that need immediate attention?",
            "Show me service accounts with administrative access",
            "Identify unused permissions that can be removed",
            "What's the blast radius if this service account is compromised?",
            "Generate a remediation plan for overprivileged service accounts",
        ],
    }


def print_scenario_summary(scenario: Dict[str, Any]):
    """Print a human-readable summary of the scenario."""
    print(f"=== {scenario['scenario_name']} ===")
    print(f"Organization: {scenario['organization']['name']}")
    print(
        f"Accounts: {len(scenario['accounts'])} ({', '.join([a['provider'] for a in scenario['accounts']])})"
    )
    print(
        f"Critical Findings: {len([f for f in scenario['findings'] if f['severity'] == 'critical'])}"
    )
    print(
        f"High Findings: {len([f for f in scenario['findings'] if f['severity'] == 'high'])}"
    )
    print(f"Investigation Priority: {scenario['investigation_notes']['priority']}")
    print(f"Business Impact: {scenario['investigation_notes']['business_impact']}")
    print()

    print("Top Findings:")
    for finding in scenario["findings"]:
        print(f"  • [{finding['severity'].upper()}] {finding['title']}")
        print(f"    {finding['summary'][:100]}...")
    print()


if __name__ == "__main__":
    scenario = generate_critical_iam_scenario()
    print_scenario_summary(scenario)
