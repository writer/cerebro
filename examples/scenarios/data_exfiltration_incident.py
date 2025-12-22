#!/usr/bin/env python3
"""Data Exfiltration Incident Scenario

This scenario simulates a sophisticated data exfiltration attack involving:
- Compromised employee credentials
- Lateral movement across cloud accounts
- Unusual data access patterns
- Suspicious data downloads and transfers
- Timeline reconstruction for forensics

Timeline:
- Day -30: Initial phishing attack, credential compromise
- Day -7: Lateral movement to cloud accounts
- Day -3: Discovery of sensitive data repositories
- Day -1: Large data downloads begin
- Day 0: Incident detection and response
"""

from datetime import datetime, timedelta
from uuid import uuid4
from typing import List, Dict, Any
import random


def generate_data_exfiltration_scenario() -> Dict[str, Any]:
    """Generate data exfiltration incident scenario with timeline."""

    now = datetime.now()
    incident_start = now - timedelta(days=30)

    # Organization
    org_id = uuid4()
    org = {
        "org_id": org_id,
        "name": "FinanceFlow Corp",
        "created_at": datetime.now() - timedelta(days=1200),
    }

    # Accounts
    aws_account = {
        "account_id": uuid4(),
        "org_id": org_id,
        "provider": "aws",
        "external_id": "987654321098",
        "display_name": "AWS Production",
    }

    github_account = {
        "account_id": uuid4(),
        "org_id": org_id,
        "provider": "github",
        "external_id": "financeflow-corp",
        "display_name": "GitHub Organization",
    }

    # Compromised User
    compromised_user = {
        "principal_id": uuid4(),
        "account_id": aws_account["account_id"],
        "provider": "aws",
        "principal_type": "user",
        "external_id": "sarah.martinez",
        "email": "sarah.martinez@financeflow.com",
        "display_name": "Sarah Martinez",
        "is_human": True,
    }

    # Attacker's Shadow Account (created after compromise)
    shadow_user = {
        "principal_id": uuid4(),
        "account_id": aws_account["account_id"],
        "provider": "aws",
        "principal_type": "user",
        "external_id": "backup-service-user",
        "email": "backup-svc@financeflow.com",
        "display_name": "Backup Service User",
        "is_human": False,  # Disguised as service account
    }

    # Critical Resources
    customer_database = {
        "resource_id": uuid4(),
        "account_id": aws_account["account_id"],
        "provider": "aws",
        "resource_type": "rds_instance",
        "external_id": "prod-customer-data",
        "name": "Production Customer Database",
        "parent_external_id": None,
        "created_at": now - timedelta(days=800),
    }

    financial_bucket = {
        "resource_id": uuid4(),
        "account_id": aws_account["account_id"],
        "provider": "aws",
        "resource_type": "s3_bucket",
        "external_id": "financeflow-financial-reports",
        "name": "Financial Reports Archive",
        "parent_external_id": None,
        "created_at": now - timedelta(days=600),
    }

    # Timeline of Suspicious Activities (Audit Events)
    audit_events = []

    # Phase 1: Initial Compromise (Day -30)
    audit_events.extend(
        [
            {
                "event_id": uuid4(),
                "account_id": aws_account["account_id"],
                "provider": "aws",
                "occurred_at": incident_start,
                "actor_external_id": "sarah.martinez",
                "action": "ConsoleLogin",
                "resource_external_id": None,
                "raw": {
                    "eventName": "ConsoleLogin",
                    "sourceIPAddress": "185.220.101.42",  # Tor exit node
                    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "responseElements": {"ConsoleLogin": "Success"},
                    "additionalEventData": {
                        "LoginTo": "https://console.aws.amazon.com"
                    },
                    "suspicious_indicators": [
                        "tor_ip",
                        "unusual_location",
                        "off_hours",
                    ],
                },
            },
            {
                "event_id": uuid4(),
                "account_id": aws_account["account_id"],
                "provider": "aws",
                "occurred_at": incident_start + timedelta(minutes=15),
                "actor_external_id": "sarah.martinez",
                "action": "CreateUser",
                "resource_external_id": "backup-service-user",
                "raw": {
                    "eventName": "CreateUser",
                    "sourceIPAddress": "185.220.101.42",
                    "responseElements": {
                        "user": {"userName": "backup-service-user", "path": "/"}
                    },
                    "requestParameters": {"userName": "backup-service-user"},
                    "suspicious_indicators": [
                        "shadow_account_creation",
                        "privilege_escalation",
                    ],
                },
            },
        ]
    )

    # Phase 2: Reconnaissance (Day -25 to -7)
    for day_offset in range(-25, -7):
        event_time = incident_start + timedelta(days=abs(day_offset))
        audit_events.append(
            {
                "event_id": uuid4(),
                "account_id": aws_account["account_id"],
                "provider": "aws",
                "occurred_at": event_time,
                "actor_external_id": "backup-service-user",
                "action": "ListBuckets",
                "resource_external_id": None,
                "raw": {
                    "eventName": "ListBuckets",
                    "sourceIPAddress": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
                    "responseElements": {
                        "buckets": [
                            "financeflow-financial-reports",
                            "customer-data-backup",
                        ]
                    },
                    "suspicious_indicators": [
                        "data_discovery",
                        "systematic_enumeration",
                    ],
                },
            }
        )

    # Phase 3: Data Access (Day -3 to -1)
    large_download_events = []
    for hour in range(0, 48):  # 48 hours of intensive downloading
        event_time = now - timedelta(days=3) + timedelta(hours=hour)
        large_download_events.append(
            {
                "event_id": uuid4(),
                "account_id": aws_account["account_id"],
                "provider": "aws",
                "occurred_at": event_time,
                "actor_external_id": "backup-service-user",
                "action": "GetObject",
                "resource_external_id": f"financeflow-financial-reports/q{random.randint(1,4)}-2024-financial-data.zip",
                "raw": {
                    "eventName": "GetObject",
                    "sourceIPAddress": f"10.{random.randint(1,3)}.{random.randint(1,254)}.{random.randint(1,254)}",
                    "responseElements": {
                        "bytesTransferred": random.randint(50000000, 500000000)
                    },  # 50MB - 500MB
                    "requestParameters": {
                        "bucketName": "financeflow-financial-reports"
                    },
                    "suspicious_indicators": [
                        "bulk_download",
                        "sensitive_data_access",
                        "off_hours",
                    ],
                },
            }
        )

    audit_events.extend(large_download_events)

    # Critical Findings
    findings = [
        {
            "finding_id": uuid4(),
            "org_id": org_id,
            "account_id": aws_account["account_id"],
            "provider": "aws",
            "rule_id": uuid4(),
            "rule_version": 1,
            "resource_id": None,
            "principal_id": shadow_user["principal_id"],
            "first_seen": incident_start + timedelta(minutes=15),
            "last_seen": now - timedelta(hours=2),
            "status": "open",
            "severity": "critical",
            "fingerprint": "shadow-account-creation-compromise",
            "title": "Shadow Account Created During Compromise",
            "summary": "Suspicious user account 'backup-service-user' created immediately after anomalous login from Tor exit node. Account shows signs of being used for persistent access.",
            "evidence": {
                "creation_source_ip": "185.220.101.42",
                "creation_method": "ConsoleLogin + CreateUser",
                "tor_exit_node": True,
                "time_delta_minutes": 15,
                "subsequent_activity": "Extensive data enumeration and download",
                "data_accessed_gb": 12.5,
                "persistence_indicators": True,
            },
        },
        {
            "finding_id": uuid4(),
            "org_id": org_id,
            "account_id": aws_account["account_id"],
            "provider": "aws",
            "rule_id": uuid4(),
            "rule_version": 1,
            "resource_id": financial_bucket["resource_id"],
            "principal_id": shadow_user["principal_id"],
            "first_seen": now - timedelta(days=3),
            "last_seen": now - timedelta(hours=2),
            "status": "open",
            "severity": "critical",
            "fingerprint": "bulk-sensitive-data-exfiltration",
            "title": "Bulk Download of Sensitive Financial Data",
            "summary": "Shadow account downloaded 12.5GB of financial reports and customer data over 48-hour period, indicating potential data exfiltration attack.",
            "evidence": {
                "total_bytes_downloaded": 13421772800,  # 12.5GB
                "files_accessed": 247,
                "time_span_hours": 48,
                "data_classification": "PII + Financial",
                "download_pattern": "systematic_bulk",
                "affected_customers": 45000,
                "regulatory_impact": ["PCI DSS", "SOX", "GDPR"],
            },
        },
        {
            "finding_id": uuid4(),
            "org_id": org_id,
            "account_id": aws_account["account_id"],
            "provider": "aws",
            "rule_id": uuid4(),
            "rule_version": 1,
            "resource_id": customer_database["resource_id"],
            "principal_id": compromised_user["principal_id"],
            "first_seen": incident_start,
            "last_seen": now,
            "status": "open",
            "severity": "high",
            "fingerprint": "anomalous-database-access-pattern",
            "title": "Anomalous Database Access Pattern",
            "summary": "Legitimate user 'sarah.martinez' showing highly unusual database access patterns coinciding with account compromise timeline.",
            "evidence": {
                "baseline_queries_per_day": 12,
                "incident_period_queries_per_day": 156,
                "query_complexity_increase": "340%",
                "new_table_access": [
                    "customer_financial_profiles",
                    "account_balances",
                    "transaction_history",
                ],
                "time_pattern": "off_hours_concentrated",
                "data_volume_accessed": "450MB/day vs 15MB/day baseline",
            },
        },
    ]

    return {
        "scenario_name": "Data Exfiltration Incident",
        "organization": org,
        "accounts": [aws_account, github_account],
        "principals": [compromised_user, shadow_user],
        "resources": [customer_database, financial_bucket],
        "audit_events": audit_events,
        "findings": findings,
        "timeline": {
            "incident_start": incident_start,
            "compromise_detection": now - timedelta(hours=6),
            "response_initiated": now - timedelta(hours=4),
            "current_status": "Active Investigation",
        },
        "investigation_notes": {
            "priority": "P0 - Active Incident",
            "business_impact": "Potential data breach affecting 45,000 customers",
            "estimated_data_loss": "12.5GB financial and customer data",
            "regulatory_notifications": "Required within 72 hours (GDPR)",
            "forensic_priorities": [
                "Preserve audit logs and system images",
                "Identify full scope of compromised accounts",
                "Determine if data left environment",
                "Assess customer impact",
                "Implement containment measures",
            ],
        },
        "agent_prompts": [
            "What is the timeline of this security incident?",
            "Show me all accounts and resources accessed during the breach",
            "Identify the attack pattern and lateral movement",
            "What sensitive data was potentially exfiltrated?",
            "Generate an incident response plan",
            "Which customers are affected and what notifications are required?",
            "Show me all audit events from the shadow account",
            "What containment actions should be taken immediately?",
        ],
    }


def print_incident_timeline(scenario: Dict[str, Any]):
    """Print a timeline view of the incident."""
    print(f"=== {scenario['scenario_name']} Timeline ===")
    print(f"Organization: {scenario['organization']['name']}")
    print(f"Incident Status: {scenario['timeline']['current_status']}")
    print(f"Data at Risk: {scenario['investigation_notes']['estimated_data_loss']}")
    print()

    # Sort events by time
    events = sorted(scenario["audit_events"], key=lambda x: x["occurred_at"])

    print("Key Timeline Events:")
    print(
        f"  Day -30: Initial compromise via Tor ({events[0]['raw']['sourceIPAddress']})"
    )
    print(f"  Day -30: Shadow account created ({events[1]['resource_external_id']})")
    print(f"  Day -25 to -7: Reconnaissance and data discovery")
    print(f"  Day -3 to -1: Bulk data exfiltration (12.5GB)")
    print(f"  Day 0: Incident detection and response")
    print()

    print("Critical Findings:")
    for finding in scenario["findings"]:
        impact = ""
        if "affected_customers" in finding["evidence"]:
            impact = (
                f" (affects {finding['evidence']['affected_customers']:,} customers)"
            )
        print(f"  • [{finding['severity'].upper()}] {finding['title']}{impact}")


if __name__ == "__main__":
    scenario = generate_data_exfiltration_scenario()
    print_incident_timeline(scenario)
