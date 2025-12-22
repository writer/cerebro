#!/usr/bin/env python3
"""Compliance Violation Investigation Scenario

This scenario demonstrates compliance violations across multiple frameworks:
- PCI DSS: Credit card data handling violations
- SOX: Financial controls and audit trail gaps
- GDPR: Data privacy and retention violations
- HIPAA: Healthcare data exposure (if applicable)

Key Violations:
- Unencrypted databases containing PII/PHI
- Excessive data retention beyond policy
- Missing audit trails for privileged access
- Cross-border data transfers without consent
- Inadequate access controls for sensitive data
"""

from datetime import datetime, timedelta
from uuid import uuid4
from typing import List, Dict, Any


def generate_compliance_violation_scenario() -> Dict[str, Any]:
    """Generate compliance violation scenario across multiple frameworks."""

    now = datetime.now()

    # Organization
    org_id = uuid4()
    org = {
        "org_id": org_id,
        "name": "MedFinance Solutions",
        "created_at": datetime.now() - timedelta(days=2000),
    }

    # Multi-region accounts
    aws_us_account = {
        "account_id": uuid4(),
        "org_id": org_id,
        "provider": "aws",
        "external_id": "111111111111",
        "display_name": "AWS US East Production",
    }

    aws_eu_account = {
        "account_id": uuid4(),
        "org_id": org_id,
        "provider": "aws",
        "external_id": "222222222222",
        "display_name": "AWS EU Frankfurt",
    }

    gcp_account = {
        "account_id": uuid4(),
        "org_id": org_id,
        "provider": "gcp",
        "external_id": "medfinance-analytics-2024",
        "display_name": "GCP Analytics",
    }

    # Problem Resources

    # 1. Unencrypted database with PII/PHI
    unencrypted_db = {
        "resource_id": uuid4(),
        "account_id": aws_us_account["account_id"],
        "provider": "aws",
        "resource_type": "rds_instance",
        "external_id": "legacy-patient-billing-db",
        "name": "Legacy Patient Billing Database",
        "parent_external_id": None,
        "created_at": now - timedelta(days=1200),
    }

    # 2. Credit card data warehouse
    cc_warehouse = {
        "resource_id": uuid4(),
        "account_id": aws_us_account["account_id"],
        "provider": "aws",
        "resource_type": "redshift_cluster",
        "external_id": "payment-analytics-warehouse",
        "name": "Payment Analytics Warehouse",
        "parent_external_id": None,
        "created_at": now - timedelta(days=800),
    }

    # 3. Over-retained EU customer data
    eu_data_lake = {
        "resource_id": uuid4(),
        "account_id": aws_eu_account["account_id"],
        "provider": "aws",
        "resource_type": "s3_bucket",
        "external_id": "eu-customer-analytics-archive",
        "name": "EU Customer Analytics Archive",
        "parent_external_id": None,
        "created_at": now - timedelta(days=1500),
    }

    # 4. Public analytics bucket
    public_bucket = {
        "resource_id": uuid4(),
        "account_id": gcp_account["account_id"],
        "provider": "gcp",
        "resource_type": "storage_bucket",
        "external_id": "public-analytics-reports",
        "name": "Public Analytics Reports",
        "parent_external_id": None,
        "created_at": now - timedelta(days=400),
    }

    # Problematic Users/Service Accounts
    admin_user = {
        "principal_id": uuid4(),
        "account_id": aws_us_account["account_id"],
        "provider": "aws",
        "principal_type": "user",
        "external_id": "dev.admin",
        "email": "dev.admin@medfinance.com",
        "display_name": "Development Admin",
        "is_human": True,
    }

    analytics_service = {
        "principal_id": uuid4(),
        "account_id": gcp_account["account_id"],
        "provider": "gcp",
        "principal_type": "service_account",
        "external_id": "analytics-pipeline@medfinance-analytics-2024.iam.gserviceaccount.com",
        "email": "analytics-pipeline@medfinance-analytics-2024.iam.gserviceaccount.com",
        "display_name": "Analytics Pipeline Service Account",
        "is_human": False,
    }

    # Config Snapshots showing violations
    config_snapshots = [
        # Unencrypted RDS instance
        {
            "snapshot_id": uuid4(),
            "resource_id": unencrypted_db["resource_id"],
            "captured_at": now - timedelta(hours=1),
            "config_sha": b"unencrypted_db_config_hash",
            "normalized_config": {
                "encryption_enabled": False,
                "backup_encryption": False,
                "ssl_enabled": False,
                "data_classification": ["PII", "PHI", "Payment_Card_Data"],
                "retention_days": 2555,  # 7 years - excessive
                "vpc_security_group_ids": ["sg-12345678"],
                "publicly_accessible": False,
                "audit_logging": False,
                "compliance_violations": {
                    "pci_dss": ["4.1.1", "3.4.1", "10.2.1"],
                    "hipaa": ["164.312(a)(2)(iv)", "164.312(e)(1)"],
                    "gdpr": ["Article 32", "Article 25"],
                },
            },
            "collector_version": "1.2.0",
        },
        # Public bucket with sensitive data
        {
            "snapshot_id": uuid4(),
            "resource_id": public_bucket["resource_id"],
            "captured_at": now - timedelta(hours=2),
            "config_sha": b"public_bucket_config_hash",
            "normalized_config": {
                "public_access": True,
                "iam_policy": {
                    "bindings": [
                        {"role": "roles/storage.objectViewer", "members": ["allUsers"]}
                    ]
                },
                "contains_sensitive_data": True,
                "data_classification": ["Customer_Analytics", "Revenue_Data"],
                "cross_border_transfers": True,
                "gdpr_consent": False,
                "compliance_violations": {
                    "gdpr": ["Article 6", "Article 44", "Article 49"],
                    "sox": ["Section 404", "PCAOB AS 2201"],
                },
            },
            "collector_version": "1.2.0",
        },
    ]

    # Compliance Violations as Findings
    findings = [
        {
            "finding_id": uuid4(),
            "org_id": org_id,
            "account_id": aws_us_account["account_id"],
            "provider": "aws",
            "rule_id": uuid4(),
            "rule_version": 1,
            "resource_id": unencrypted_db["resource_id"],
            "principal_id": None,
            "first_seen": now - timedelta(days=30),
            "last_seen": now - timedelta(hours=1),
            "status": "open",
            "severity": "critical",
            "fingerprint": "pci-dss-unencrypted-cardholder-data",
            "title": "PCI DSS Violation: Unencrypted Cardholder Data",
            "summary": "Database storing payment card data lacks encryption at rest and in transit, violating PCI DSS requirements 3.4.1 and 4.1.1. Contains 125,000 credit card records.",
            "evidence": {
                "pci_dss_violations": ["3.4.1", "4.1.1", "10.2.1", "8.2.1"],
                "cardholder_data_records": 125000,
                "encryption_status": {
                    "at_rest": False,
                    "in_transit": False,
                    "backup": False,
                },
                "audit_logging": False,
                "access_controls": "Insufficient",
                "compliance_score": 15,  # Out of 100
                "merchant_level": 1,
                "annual_transaction_volume": 12000000,
                "potential_fine": "$500,000 - $5,000,000",
            },
        },
        {
            "finding_id": uuid4(),
            "org_id": org_id,
            "account_id": aws_eu_account["account_id"],
            "provider": "aws",
            "rule_id": uuid4(),
            "rule_version": 1,
            "resource_id": eu_data_lake["resource_id"],
            "principal_id": None,
            "first_seen": now - timedelta(days=60),
            "last_seen": now - timedelta(hours=3),
            "status": "open",
            "severity": "high",
            "fingerprint": "gdpr-excessive-data-retention",
            "title": "GDPR Violation: Excessive Data Retention",
            "summary": "EU customer data retained for 7+ years exceeds lawful basis and retention policy. Contains PII for 89,000 EU data subjects without valid consent for extended processing.",
            "evidence": {
                "gdpr_violations": ["Article 5(1)(e)", "Article 6", "Article 7"],
                "data_subjects_affected": 89000,
                "retention_period_days": 2555,
                "policy_max_days": 1095,
                "excess_retention_days": 1460,
                "consent_status": "Expired/Invalid",
                "data_categories": [
                    "Personal identifiers",
                    "Financial data",
                    "Health data",
                ],
                "cross_border_transfers": "US without adequacy decision",
                "dpo_notification": False,
                "potential_fine": "€20,000,000 or 4% of annual turnover",
            },
        },
        {
            "finding_id": uuid4(),
            "org_id": org_id,
            "account_id": gcp_account["account_id"],
            "provider": "gcp",
            "rule_id": uuid4(),
            "rule_version": 1,
            "resource_id": public_bucket["resource_id"],
            "principal_id": None,
            "first_seen": now - timedelta(days=7),
            "last_seen": now - timedelta(hours=2),
            "status": "open",
            "severity": "critical",
            "fingerprint": "public-sensitive-data-exposure",
            "title": "Public Exposure of Sensitive Business Data",
            "summary": "GCP storage bucket containing financial analytics and customer revenue data is publicly accessible, violating SOX controls and exposing confidential business information.",
            "evidence": {
                "sox_violations": ["Section 302", "Section 404"],
                "public_access": True,
                "data_exposed": {
                    "revenue_reports": 47,
                    "customer_analytics": 234,
                    "financial_forecasts": 12,
                },
                "potential_insider_trading": True,
                "market_sensitive_info": True,
                "discovered_by": "External security researcher",
                "exposure_duration_days": 127,
                "download_attempts": "Unknown - no logging",
            },
        },
        {
            "finding_id": uuid4(),
            "org_id": org_id,
            "account_id": aws_us_account["account_id"],
            "provider": "aws",
            "rule_id": uuid4(),
            "rule_version": 1,
            "resource_id": unencrypted_db["resource_id"],
            "principal_id": admin_user["principal_id"],
            "first_seen": now - timedelta(days=90),
            "last_seen": now - timedelta(hours=4),
            "status": "open",
            "severity": "high",
            "fingerprint": "hipaa-insufficient-access-controls",
            "title": "HIPAA Violation: Insufficient PHI Access Controls",
            "summary": "Development admin has unrestricted access to patient health information without business justification. Violates HIPAA minimum necessary standard.",
            "evidence": {
                "hipaa_violations": ["164.502(b)", "164.514(d)", "164.308(a)(4)"],
                "phi_records_accessible": 78000,
                "role_justification": "None documented",
                "access_review_date": "Never",
                "audit_trail": "Incomplete",
                "patient_consent": "Not verified",
                "breach_risk": "High - full database access",
                "covered_entity_obligations": "Failed",
            },
        },
    ]

    return {
        "scenario_name": "Multi-Framework Compliance Violations",
        "organization": org,
        "accounts": [aws_us_account, aws_eu_account, gcp_account],
        "principals": [admin_user, analytics_service],
        "resources": [unencrypted_db, cc_warehouse, eu_data_lake, public_bucket],
        "config_snapshots": config_snapshots,
        "findings": findings,
        "compliance_frameworks": {
            "pci_dss": {
                "current_compliance_level": "Non-compliant",
                "violations": 4,
                "merchant_level": 1,
                "next_assessment": now + timedelta(days=90),
                "potential_fines": "$500K - $5M",
                "remediation_deadline": now + timedelta(days=30),
            },
            "gdpr": {
                "current_compliance_level": "Non-compliant",
                "violations": 3,
                "data_subjects_at_risk": 89000,
                "supervisory_authority": "Irish DPC",
                "potential_fines": "€20M or 4% annual turnover",
                "notification_deadline": now + timedelta(hours=72),
            },
            "sox": {
                "current_compliance_level": "Material weakness",
                "violations": 2,
                "next_audit": now + timedelta(days=120),
                "auditor": "Ernst & Young",
                "ceo_certification_risk": "High",
                "remediation_required": True,
            },
            "hipaa": {
                "current_compliance_level": "Non-compliant",
                "violations": 1,
                "covered_entity": True,
                "business_associates": 12,
                "breach_notification_required": True,
                "ocr_reporting_deadline": now + timedelta(days=60),
            },
        },
        "investigation_notes": {
            "priority": "P0 - Regulatory Emergency",
            "business_impact": "Potential regulatory fines exceeding $25M",
            "stakeholders": ["Legal", "Compliance", "CISO", "CFO", "CEO", "Board"],
            "external_notifications": [
                "Payment card brands (PCI DSS)",
                "EU supervisory authority (GDPR)",
                "SEC (SOX)",
                "HHS OCR (HIPAA)",
            ],
            "remediation_timeline": "30-90 days critical path",
            "business_continuity_risk": "High - potential payment processing suspension",
        },
        "agent_prompts": [
            "What are the most critical compliance violations that need immediate attention?",
            "Show me all resources storing sensitive data without proper controls",
            "Generate a prioritized remediation plan for compliance violations",
            "Which violations require external notifications and by when?",
            "What is our potential financial exposure from these violations?",
            "Show me the data flow for EU customer data and GDPR compliance gaps",
            "Identify all resources containing payment card data and their security status",
            "What access controls need to be implemented for HIPAA compliance?",
        ],
    }


def print_compliance_dashboard(scenario: Dict[str, Any]):
    """Print compliance dashboard summary."""
    print(f"=== {scenario['scenario_name']} ===")
    print(f"Organization: {scenario['organization']['name']}")
    print()

    frameworks = scenario["compliance_frameworks"]
    print("Compliance Status:")
    for framework, details in frameworks.items():
        status = details["current_compliance_level"]
        violations = details["violations"]
        print(f"  • {framework.upper()}: {status} ({violations} violations)")
    print()

    print("Critical Findings by Framework:")
    framework_findings = {}
    for finding in scenario["findings"]:
        severity = finding["severity"]
        title = finding["title"]
        if "PCI DSS" in title:
            framework = "PCI DSS"
        elif "GDPR" in title:
            framework = "GDPR"
        elif "SOX" in title or "Public Exposure" in title:
            framework = "SOX"
        elif "HIPAA" in title:
            framework = "HIPAA"
        else:
            framework = "Other"

        if framework not in framework_findings:
            framework_findings[framework] = []
        framework_findings[framework].append(f"[{severity.upper()}] {title}")

    for framework, findings in framework_findings.items():
        print(f"  {framework}:")
        for finding in findings:
            print(f"    • {finding}")
    print()

    print("Priority Actions:")
    print(f"  • {scenario['investigation_notes']['priority']}")
    print(f"  • Potential fines: {scenario['investigation_notes']['business_impact']}")
    print(f"  • Timeline: {scenario['investigation_notes']['remediation_timeline']}")


if __name__ == "__main__":
    scenario = generate_compliance_violation_scenario()
    print_compliance_dashboard(scenario)
