#!/usr/bin/env python3
"""Multi-Cloud Security Review Scenario

This scenario demonstrates a comprehensive security review across multiple cloud providers:
- AWS, GCP, Azure, and GitHub
- Cross-provider identity federation issues
- Resource sprawl and shadow IT discovery
- Security posture inconsistencies
- Cost vs security trade-offs

Key Issues:
- Inconsistent security policies across providers
- Identity federation gaps and orphaned accounts
- Unmanaged resource sprawl in development accounts
- Missing security monitoring in some environments
- Cost optimization vs security hardening tensions
"""

from datetime import datetime, timedelta
from uuid import uuid4
from typing import List, Dict, Any
import random

def generate_multi_cloud_review_scenario() -> Dict[str, Any]:
    """Generate multi-cloud security review scenario."""
    
    now = datetime.now()
    
    # Organization
    org_id = uuid4()
    org = {
        "org_id": org_id,
        "name": "GlobalTech Enterprises",
        "created_at": datetime.now() - timedelta(days=900)
    }
    
    # Multi-cloud accounts
    aws_prod_account = {
        "account_id": uuid4(),
        "org_id": org_id,
        "provider": "aws",
        "external_id": "555555555555",
        "display_name": "AWS Production"
    }
    
    aws_dev_account = {
        "account_id": uuid4(),
        "org_id": org_id,
        "provider": "aws", 
        "external_id": "666666666666",
        "display_name": "AWS Development"
    }
    
    gcp_account = {
        "account_id": uuid4(),
        "org_id": org_id,
        "provider": "gcp",
        "external_id": "globaltech-cloud-2024",
        "display_name": "GCP Production"
    }
    
    github_account = {
        "account_id": uuid4(),
        "org_id": org_id,
        "provider": "github",
        "external_id": "globaltech-enterprises",
        "display_name": "GitHub Organization"
    }
    
    # Cross-cloud resources with different security postures
    
    # AWS Production - Well secured
    aws_prod_db = {
        "resource_id": uuid4(),
        "account_id": aws_prod_account["account_id"],
        "provider": "aws",
        "resource_type": "rds_instance",
        "external_id": "prod-app-database",
        "name": "Production Application Database",
        "parent_external_id": None,
        "created_at": now - timedelta(days=400)
    }
    
    # AWS Dev - Poorly secured, cost-optimized
    aws_dev_instance = {
        "resource_id": uuid4(),
        "account_id": aws_dev_account["account_id"],
        "provider": "aws",
        "resource_type": "ec2_instance", 
        "external_id": "i-dev-testing-server",
        "name": "Development Testing Server",
        "parent_external_id": None,
        "created_at": now - timedelta(days=45)
    }
    
    # GCP - Mixed security posture
    gcp_bucket = {
        "resource_id": uuid4(),
        "account_id": gcp_account["account_id"],
        "provider": "gcp",
        "resource_type": "storage_bucket",
        "external_id": "globaltech-ml-datasets",
        "name": "ML Training Datasets",
        "parent_external_id": None,
        "created_at": now - timedelta(days=200)
    }
    
    # GitHub - Source code and secrets
    github_repo = {
        "resource_id": uuid4(),
        "account_id": github_account["account_id"],
        "provider": "github",
        "resource_type": "repository",
        "external_id": "mobile-app-backend",
        "name": "Mobile App Backend",
        "parent_external_id": None,
        "created_at": now - timedelta(days=300)
    }
    
    # Cross-provider identity issues
    federated_user = {
        "principal_id": uuid4(),
        "account_id": aws_prod_account["account_id"],
        "provider": "aws",
        "principal_type": "user",
        "external_id": "john.developer@globaltech.com",
        "email": "john.developer@globaltech.com",
        "display_name": "John Developer",
        "is_human": True
    }
    
    orphaned_service_account = {
        "principal_id": uuid4(),
        "account_id": gcp_account["account_id"],
        "provider": "gcp",
        "principal_type": "service_account",
        "external_id": "legacy-migration-sa@globaltech-cloud-2024.iam.gserviceaccount.com",
        "email": "legacy-migration-sa@globaltech-cloud-2024.iam.gserviceaccount.com",
        "display_name": "Legacy Migration Service Account",
        "is_human": False
    }
    
    # Config snapshots showing security inconsistencies
    config_snapshots = [
        # AWS Prod - Well configured
        {
            "snapshot_id": uuid4(),
            "resource_id": aws_prod_db["resource_id"],
            "captured_at": now - timedelta(hours=1),
            "config_sha": b'aws_prod_db_secure_config',
            "normalized_config": {
                "encryption_enabled": True,
                "backup_encryption": True,
                "ssl_enabled": True,
                "publicly_accessible": False,
                "vpc_security_groups": ["sg-restrictive-db-access"],
                "audit_logging": True,
                "multi_az": True,
                "automated_backups": True,
                "backup_retention_days": 30,
                "security_score": 95
            },
            "collector_version": "1.2.0"
        },
        # AWS Dev - Cost-optimized, less secure
        {
            "snapshot_id": uuid4(),
            "resource_id": aws_dev_instance["resource_id"],
            "captured_at": now - timedelta(hours=2),
            "config_sha": b'aws_dev_instance_config',
            "normalized_config": {
                "instance_type": "t2.micro",  # Cost optimized
                "public_ip": True,
                "security_groups": ["sg-default"],  # Default, permissive
                "key_pair": "dev-team-shared",  # Shared key
                "ebs_encryption": False,
                "detailed_monitoring": False,  # Cost saving
                "termination_protection": False,
                "iam_instance_profile": None,  # No role attached
                "security_score": 25
            },
            "collector_version": "1.2.0"
        },
        # GCP - Mixed configuration
        {
            "snapshot_id": uuid4(),
            "resource_id": gcp_bucket["resource_id"],
            "captured_at": now - timedelta(hours=3),
            "config_sha": b'gcp_bucket_config',
            "normalized_config": {
                "public_access": False,
                "uniform_bucket_level_access": True,
                "encryption": {
                    "default_kms_key": "projects/globaltech-cloud-2024/locations/global/keyRings/ml-ring/cryptoKeys/dataset-key"
                },
                "versioning_enabled": False,  # Cost saving
                "lifecycle_policy": None,  # No cleanup rules
                "access_logs": False,  # Missing audit trail
                "contains_sensitive_data": True,
                "data_classification": ["Training_Data", "Customer_Behavior"],
                "security_score": 60
            },
            "collector_version": "1.2.0"
        }
    ]
    
    # Multi-cloud security findings
    findings = [
        {
            "finding_id": uuid4(),
            "org_id": org_id,
            "account_id": aws_dev_account["account_id"],
            "provider": "aws",
            "rule_id": uuid4(),
            "rule_version": 1,
            "resource_id": aws_dev_instance["resource_id"],
            "principal_id": None,
            "first_seen": now - timedelta(days=30),
            "last_seen": now - timedelta(hours=1),
            "status": "open",
            "severity": "high",
            "fingerprint": "dev-environment-security-gaps",
            "title": "Development Environment Security Gaps",
            "summary": "Development AWS account has significant security gaps including public instances, shared keys, and disabled monitoring. This creates risk of lateral movement to production.",
            "evidence": {
                "security_score": 25,
                "production_security_score": 95,
                "gap_analysis": {
                    "encryption": "Disabled in dev, enabled in prod",
                    "monitoring": "Minimal in dev, comprehensive in prod", 
                    "access_controls": "Permissive in dev, restrictive in prod",
                    "networking": "Public access in dev, private in prod"
                },
                "cost_vs_security": {
                    "monthly_savings": "$2,400",
                    "security_risk_increase": "340%"
                },
                "lateral_movement_risk": "High - shared credentials and network access"
            }
        },
        {
            "finding_id": uuid4(),
            "org_id": org_id,
            "account_id": gcp_account["account_id"],
            "provider": "gcp",
            "rule_id": uuid4(),
            "rule_version": 1,
            "resource_id": None,
            "principal_id": orphaned_service_account["principal_id"],
            "first_seen": now - timedelta(days=60),
            "last_seen": now - timedelta(hours=4),
            "status": "open", 
            "severity": "medium",
            "fingerprint": "orphaned-cross-cloud-service-account",
            "title": "Orphaned Service Account with Cross-Cloud Access",
            "summary": "Legacy migration service account has not been used for 60+ days but retains broad permissions across GCP and potential federated access to AWS resources.",
            "evidence": {
                "last_used": "60+ days ago",
                "permissions": [
                    "storage.admin",
                    "compute.instanceAdmin", 
                    "iam.serviceAccountUser"
                ],
                "cross_cloud_access": {
                    "aws_role_arn": "arn:aws:iam::555555555555:role/GCPFederatedRole",
                    "federation_trust": "Active but unused"
                },
                "created_for": "Data migration project (completed)",
                "cleanup_blocked_by": "Unclear ownership and dependencies"
            }
        },
        {
            "finding_id": uuid4(),
            "org_id": org_id,
            "account_id": github_account["account_id"],
            "provider": "github",
            "rule_id": uuid4(),
            "rule_version": 1,
            "resource_id": github_repo["resource_id"],
            "principal_id": None,
            "first_seen": now - timedelta(days=15),
            "last_seen": now - timedelta(hours=2),
            "status": "open",
            "severity": "critical",
            "fingerprint": "hardcoded-cloud-credentials-in-repo",
            "title": "Hardcoded Cloud Credentials in Repository",
            "summary": "Mobile app backend repository contains hardcoded AWS and GCP credentials in configuration files, creating cross-cloud access risk.",
            "evidence": {
                "credential_types": [
                    "AWS Access Keys",
                    "GCP Service Account Keys", 
                    "Database Connection Strings"
                ],
                "files_affected": [
                    "config/production.json",
                    "scripts/deploy.sh",
                    "k8s/secrets.yaml"
                ],
                "commit_history": "Credentials exposed for 15 days",
                "repository_access": "47 developers",
                "blast_radius": {
                    "aws_resources_accessible": 234,
                    "gcp_resources_accessible": 89,
                    "estimated_damage": "Complete multi-cloud compromise"
                }
            }
        },
        {
            "finding_id": uuid4(),
            "org_id": org_id,
            "account_id": aws_prod_account["account_id"],
            "provider": "aws",
            "rule_id": uuid4(),
            "rule_version": 1,
            "resource_id": None,
            "principal_id": federated_user["principal_id"],
            "first_seen": now - timedelta(days=45),
            "last_seen": now - timedelta(hours=6),
            "status": "open",
            "severity": "medium",
            "fingerprint": "inconsistent-multi-cloud-identity-policies",
            "title": "Inconsistent Multi-Cloud Identity Policies", 
            "summary": "User has different access levels across cloud providers with inconsistent MFA and session management policies, creating security and compliance gaps.",
            "evidence": {
                "aws_access": {
                    "mfa_required": True,
                    "session_duration": "1 hour",
                    "permissions": "Developer role - limited"
                },
                "gcp_access": {
                    "mfa_required": False,  # Inconsistent
                    "session_duration": "12 hours",  # Too long
                    "permissions": "Editor role - broad access"
                },
                "github_access": {
                    "mfa_required": True,
                    "session_duration": "No limit",
                    "permissions": "Admin - repository management"
                },
                "policy_inconsistencies": [
                    "MFA requirements vary by provider",
                    "Session durations are inconsistent", 
                    "Permission models don't align",
                    "No unified identity governance"
                ]
            }
        }
    ]
    
    return {
        "scenario_name": "Multi-Cloud Security Review",
        "organization": org,
        "accounts": [aws_prod_account, aws_dev_account, gcp_account, github_account],
        "principals": [federated_user, orphaned_service_account],
        "resources": [aws_prod_db, aws_dev_instance, gcp_bucket, github_repo],
        "config_snapshots": config_snapshots,
        "findings": findings,
        "cloud_analysis": {
            "providers": ["AWS", "GCP", "GitHub"],
            "security_maturity": {
                "aws_prod": "Advanced",
                "aws_dev": "Basic", 
                "gcp": "Intermediate",
                "github": "Intermediate"
            },
            "identity_federation": {
                "aws_gcp_trust": "Configured but unused",
                "github_sso": "Not implemented",
                "unified_directory": False
            },
            "cost_vs_security": {
                "monthly_cloud_spend": "$45,000",
                "security_tooling_cost": "$8,500",
                "potential_optimization": "$12,000/month",
                "security_investment_needed": "$15,000/month"
            }
        },
        "investigation_notes": {
            "priority": "P1 - Strategic Review",
            "business_impact": "Multi-cloud security inconsistencies increase risk",
            "review_scope": "Complete multi-cloud security posture assessment",
            "stakeholders": ["CISO", "Cloud Architects", "DevOps Teams", "Finance"],
            "timeline": "4-6 weeks comprehensive review",
            "deliverables": [
                "Cross-cloud security policy standardization",
                "Identity federation strategy",
                "Cost-optimized security improvements",
                "Resource sprawl cleanup plan"
            ]
        },
        "agent_prompts": [
            "Compare security postures across our cloud providers",
            "What are the biggest security gaps in our multi-cloud setup?",
            "Show me identity and access inconsistencies across providers",
            "Identify resources that could be better secured cost-effectively",
            "What's our cross-cloud attack surface and blast radius?",
            "Generate a standardized security policy for all cloud providers",
            "Show me orphaned or unused resources across all accounts",
            "What federation and SSO improvements should we prioritize?"
        ]
    }

def print_multi_cloud_summary(scenario: Dict[str, Any]):
    """Print multi-cloud security review summary."""
    print(f"=== {scenario['scenario_name']} ===")
    print(f"Organization: {scenario['organization']['name']}")
    
    cloud_analysis = scenario['cloud_analysis']
    print(f"Cloud Providers: {', '.join(cloud_analysis['providers'])}")
    print(f"Monthly Spend: ${cloud_analysis['cost_vs_security']['monthly_cloud_spend']:,}")
    print()
    
    print("Security Maturity by Provider:")
    for provider, maturity in cloud_analysis['security_maturity'].items():
        print(f"  • {provider.upper()}: {maturity}")
    print()
    
    findings_by_severity = {}
    for finding in scenario['findings']:
        severity = finding['severity']
        if severity not in findings_by_severity:
            findings_by_severity[severity] = []
        findings_by_severity[severity].append(finding['title'])
    
    print("Key Findings:")
    for severity in ['critical', 'high', 'medium', 'low']:
        if severity in findings_by_severity:
            print(f"  {severity.upper()}:")
            for title in findings_by_severity[severity]:
                print(f"    • {title}")
    print()
    
    print("Strategic Recommendations:")
    print(f"  • Timeline: {scenario['investigation_notes']['timeline']}")
    print(f"  • Security Investment Needed: ${cloud_analysis['cost_vs_security']['security_investment_needed']}")
    print(f"  • Potential Monthly Optimization: ${cloud_analysis['cost_vs_security']['potential_optimization']}")

if __name__ == "__main__":
    scenario = generate_multi_cloud_review_scenario()
    print_multi_cloud_summary(scenario)
