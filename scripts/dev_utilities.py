#!/usr/bin/env python3
"""Development Utilities for Cerebro Agents

This module provides utilities for agent development and testing:
- Quick agent session setup
- Scenario reset and cleanup
- Mock data generation
- Development helpers

Usage:
    python scripts/dev_utilities.py session --scenario critical_iam
    python scripts/dev_utilities.py reset --confirm
    python scripts/dev_utilities.py mock --type findings --count 50
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
from uuid import uuid4
import random

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cerebro.core import models
from cerebro.core.database import Base
from cerebro.core.config import settings
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Create synchronous engine and session for scripts
sync_engine = create_engine(settings.database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=sync_engine)


class AgentSessionManager:
    """Manages agent development and testing sessions."""

    def __init__(self):
        self.session_dir = Path.home() / ".cerebro" / "agent_sessions"
        self.session_dir.mkdir(parents=True, exist_ok=True)

    def create_session(
        self, scenario: str, org_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a new agent session with scenario context."""
        session_id = f"dev-session-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        # Load scenario data for context
        with SessionLocal() as db:
            if org_name:
                org = (
                    db.query(models.Organization)
                    .filter(models.Organization.name == org_name)
                    .first()
                )
                if not org:
                    raise ValueError(f"Organization '{org_name}' not found")
            else:
                # Use first org in database
                org = db.query(models.Organization).first()
                if not org:
                    raise ValueError(
                        "No organizations found. Run generate_test_data.py first"
                    )

            # Get context data
            accounts = (
                db.query(models.Account)
                .filter(models.Account.org_id == org.org_id)
                .all()
            )

            findings = (
                db.query(models.Finding)
                .filter(models.Finding.org_id == org.org_id)
                .order_by(models.Finding.severity == "critical")
                .limit(10)
                .all()
            )

            session_context = {
                "session_id": session_id,
                "created_at": datetime.now().isoformat(),
                "scenario": scenario,
                "organization": {
                    "org_id": str(org.org_id),
                    "name": org.name,
                    "account_count": len(accounts),
                },
                "context": {
                    "critical_findings": len(
                        [f for f in findings if f.severity == "critical"]
                    ),
                    "high_findings": len([f for f in findings if f.severity == "high"]),
                    "total_findings": len(findings),
                    "providers": list(set(a.provider for a in accounts)),
                },
                "sample_prompts": self._get_scenario_prompts(scenario),
                "quick_commands": [
                    f"Show me critical findings for {org.name}",
                    "What are the most urgent security issues?",
                    "Generate a security posture report",
                    "Show me recent security events",
                    "Identify attack paths in our environment",
                ],
            }

        # Save session
        session_file = self.session_dir / f"{session_id}.json"
        with open(session_file, "w") as f:
            json.dump(session_context, f, indent=2, default=str)

        print(f"🎬 Created agent session: {session_id}")
        print(f"📁 Session file: {session_file}")
        print(f"🏢 Organization: {org.name}")
        print(
            f"🚨 Critical findings: {session_context['context']['critical_findings']}"
        )
        print()
        print("Quick start commands:")
        for cmd in session_context["quick_commands"][:3]:
            print(f"  • {cmd}")

        return session_context

    def _get_scenario_prompts(self, scenario: str) -> List[str]:
        """Get scenario-specific prompts."""
        prompts = {
            "critical_iam": [
                "Show me service accounts with administrative access",
                "Identify unused permissions that can be removed",
                "What's the blast radius if this service account is compromised?",
                "Generate a remediation plan for overprivileged service accounts",
            ],
            "data_exfiltration": [
                "What is the timeline of this security incident?",
                "Show me all audit events from suspicious accounts",
                "Identify the attack pattern and lateral movement",
                "What sensitive data was potentially exfiltrated?",
            ],
            "compliance_violation": [
                "What are the most critical compliance violations?",
                "Show me all resources storing sensitive data without proper controls",
                "Which violations require external notifications and by when?",
                "Generate a prioritized remediation plan for compliance violations",
            ],
        }
        return prompts.get(
            scenario,
            [
                "Analyze the security posture of this organization",
                "Show me the most critical security findings",
                "What are the top security risks to investigate?",
            ],
        )

    def list_sessions(self) -> List[Dict[str, Any]]:
        """List all saved agent sessions."""
        sessions = []
        for session_file in self.session_dir.glob("*.json"):
            try:
                with open(session_file) as f:
                    session = json.load(f)
                    sessions.append(
                        {
                            "session_id": session["session_id"],
                            "created_at": session["created_at"],
                            "scenario": session.get("scenario", "unknown"),
                            "organization": session["organization"]["name"],
                            "findings": session["context"]["total_findings"],
                        }
                    )
            except Exception as e:
                print(f"Warning: Could not load session {session_file}: {e}")

        return sorted(sessions, key=lambda x: x["created_at"], reverse=True)

    def load_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Load a saved agent session."""
        session_file = self.session_dir / f"{session_id}.json"
        if not session_file.exists():
            return None

        with open(session_file) as f:
            return json.load(f)


class MockDataGenerator:
    """Generates mock data for testing and development."""

    def __init__(self, session):
        self.session = session
        self.providers = ["aws", "gcp", "github", "google_workspace"]
        self.severities = ["critical", "high", "medium", "low", "info"]
        self.statuses = ["open", "suppressed", "accepted_risk", "fixed"]

    def generate_findings(
        self, count: int = 10, org_id: Optional[str] = None
    ) -> List[models.Finding]:
        """Generate mock findings."""
        if not org_id:
            org = self.session.query(models.Organization).first()
            if not org:
                raise ValueError("No organizations found")
            org_id = org.org_id

        # Get available accounts
        accounts = (
            self.session.query(models.Account)
            .filter(models.Account.org_id == org_id)
            .all()
        )

        if not accounts:
            raise ValueError("No accounts found for organization")

        findings = []
        finding_templates = [
            ("Unencrypted S3 Bucket", "S3 bucket {resource} lacks encryption at rest"),
            (
                "Overprivileged IAM Role",
                "IAM role {resource} has excessive permissions",
            ),
            (
                "Public Database Access",
                "Database {resource} allows public network access",
            ),
            (
                "Weak Password Policy",
                "Account {resource} has insufficient password requirements",
            ),
            ("Missing MFA", "User {resource} lacks multi-factor authentication"),
            ("Expired Certificate", "SSL certificate for {resource} has expired"),
            (
                "Vulnerable Software",
                "Instance {resource} running vulnerable software version",
            ),
            (
                "Excessive Data Retention",
                "Dataset {resource} retained beyond policy limits",
            ),
            ("Cross-Border Data Transfer", "Data transfer to {resource} lacks consent"),
            (
                "Missing Audit Logging",
                "Service {resource} has insufficient audit logging",
            ),
        ]

        for i in range(count):
            account = random.choice(accounts)
            title_template, summary_template = random.choice(finding_templates)

            resource_name = f"{account.provider}-resource-{random.randint(1000, 9999)}"

            finding = models.Finding(
                finding_id=uuid4(),
                org_id=org_id,
                account_id=account.account_id,
                provider=account.provider,
                rule_id=uuid4(),  # Mock rule ID
                rule_version=1,
                resource_id=None,  # Simplified - no actual resources
                principal_id=None,
                first_seen=datetime.now() - timedelta(days=random.randint(1, 90)),
                last_seen=datetime.now() - timedelta(hours=random.randint(1, 24)),
                status=random.choice(self.statuses),
                severity=random.choice(self.severities),
                fingerprint=f"mock-finding-{i}-{uuid4().hex[:8]}",
                title=title_template.format(resource=resource_name),
                summary=summary_template.format(resource=resource_name),
                evidence={
                    "mock_data": True,
                    "generated_at": datetime.now().isoformat(),
                    "risk_score": random.randint(1, 100),
                    "affected_users": random.randint(1, 1000),
                    "compliance_frameworks": random.sample(
                        ["PCI DSS", "GDPR", "SOX", "HIPAA", "CIS"], random.randint(1, 3)
                    ),
                },
            )
            findings.append(finding)

        return findings

    def generate_audit_events(
        self, count: int = 50, account_id: Optional[str] = None
    ) -> List[models.AuditEvent]:
        """Generate mock audit events."""
        if not account_id:
            account = self.session.query(models.Account).first()
            if not account:
                raise ValueError("No accounts found")
            account_id = account.account_id

        account = (
            self.session.query(models.Account)
            .filter(models.Account.account_id == account_id)
            .first()
        )

        events = []
        event_templates = [
            ("Login", {"eventName": "ConsoleLogin", "result": "Success"}),
            ("CreateUser", {"eventName": "CreateUser", "userName": "test-user"}),
            (
                "AssumeRole",
                {
                    "eventName": "AssumeRole",
                    "roleArn": "arn:aws:iam::123456789012:role/TestRole",
                },
            ),
            (
                "PutBucketPolicy",
                {"eventName": "PutBucketPolicy", "bucketName": "test-bucket"},
            ),
            ("CreateRole", {"eventName": "CreateRole", "roleName": "test-role"}),
            ("DeleteUser", {"eventName": "DeleteUser", "userName": "old-user"}),
            (
                "ModifyDBInstance",
                {"eventName": "ModifyDBInstance", "dbInstanceId": "prod-db"},
            ),
        ]

        for i in range(count):
            action, raw_data = random.choice(event_templates)

            event = models.AuditEvent(
                event_id=uuid4(),
                account_id=account_id,
                provider=account.provider,
                occurred_at=datetime.now()
                - timedelta(minutes=random.randint(1, 10080)),  # Last week
                actor_external_id=f"user-{random.randint(1, 100)}",
                action=action,
                resource_external_id=f"resource-{random.randint(1000, 9999)}",
                raw={
                    **raw_data,
                    "mock_data": True,
                    "sourceIPAddress": f"10.0.{random.randint(1,255)}.{random.randint(1,255)}",
                    "userAgent": "aws-cli/2.0.0 Python/3.8.0",
                },
            )
            events.append(event)

        return events


class ScenarioManager:
    """Manages test scenarios and cleanup operations."""

    def __init__(self):
        self.session = SessionLocal()

    def reset_scenario(self, scenario_name: Optional[str] = None):
        """Reset/clean scenario data."""
        if scenario_name:
            # Clean specific scenario data - simplified approach
            print(f"🧹 Cleaning scenario: {scenario_name}")
            # In a real implementation, you'd track which data belongs to which scenario
            self._clean_recent_data()
        else:
            print("🧹 Cleaning all test data...")
            self._clean_all_data()

    def _clean_recent_data(self):
        """Clean recently created test data (last 24 hours)."""
        cutoff = datetime.now() - timedelta(hours=24)

        # Clean findings from last 24 hours
        recent_findings = self.session.query(models.Finding).filter(
            models.Finding.first_seen > cutoff
        )
        count = recent_findings.count()
        recent_findings.delete()

        self.session.commit()
        print(f"✅ Cleaned {count} recent findings")

    def _clean_all_data(self):
        """Clean all test data."""
        # Delete in reverse dependency order
        tables = [
            models.EvidenceArtifact,
            models.Finding,
            models.Suppression,
            models.AuditEvent,
            models.IamEdge,
            models.ConfigSnapshot,
            models.Rule,
            models.Policy,
            models.Resource,
            models.Principal,
            models.Account,
            models.Organization,
        ]

        total_deleted = 0
        for table in tables:
            count = self.session.query(table).count()
            self.session.query(table).delete()
            total_deleted += count

        self.session.commit()
        print(f"✅ Cleaned {total_deleted} total records")


def main():
    parser = argparse.ArgumentParser(description="Cerebro Development Utilities")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Session management
    session_parser = subparsers.add_parser("session", help="Manage agent sessions")
    session_parser.add_argument("--scenario", help="Scenario to load")
    session_parser.add_argument("--org", help="Organization name")
    session_parser.add_argument(
        "--list", action="store_true", help="List saved sessions"
    )
    session_parser.add_argument("--load", help="Load saved session by ID")

    # Mock data generation
    mock_parser = subparsers.add_parser("mock", help="Generate mock data")
    mock_parser.add_argument(
        "--type", choices=["findings", "events", "all"], default="all"
    )
    mock_parser.add_argument(
        "--count", type=int, default=10, help="Number of items to generate"
    )
    mock_parser.add_argument("--org", help="Organization name")

    # Scenario management
    reset_parser = subparsers.add_parser("reset", help="Reset/clean scenarios")
    reset_parser.add_argument("--scenario", help="Specific scenario to clean")
    reset_parser.add_argument("--confirm", action="store_true", help="Confirm deletion")

    args = parser.parse_args()

    if args.command == "session":
        manager = AgentSessionManager()

        if args.list:
            sessions = manager.list_sessions()
            print("📋 Saved Agent Sessions:")
            for session in sessions:
                print(
                    f"  {session['session_id']} - {session['scenario']} - {session['organization']}"
                )

        elif args.load:
            session = manager.load_session(args.load)
            if session:
                print(f"📂 Loaded session: {args.load}")
                print(json.dumps(session, indent=2, default=str))
            else:
                print(f"❌ Session not found: {args.load}")

        else:
            scenario = args.scenario or "general"
            manager.create_session(scenario, args.org)

    elif args.command == "mock":
        with SessionLocal() as db:
            generator = MockDataGenerator(db)

            if args.type in ["findings", "all"]:
                findings = generator.generate_findings(args.count, args.org)
                for finding in findings:
                    db.add(finding)
                print(f"✅ Generated {len(findings)} mock findings")

            if args.type in ["events", "all"]:
                events = generator.generate_audit_events(args.count)
                for event in events:
                    db.add(event)
                print(f"✅ Generated {len(events)} mock audit events")

            db.commit()

    elif args.command == "reset":
        if not args.confirm:
            print("⚠️  This will delete data. Use --confirm to proceed.")
            return

        manager = ScenarioManager()
        manager.reset_scenario(args.scenario)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
