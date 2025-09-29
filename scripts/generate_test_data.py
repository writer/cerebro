#!/usr/bin/env python3
"""Test Data Generator for Cerebro

This script generates realistic test data for Cerebro development and testing.
It can create individual scenarios or populate the database with comprehensive test data.

Usage:
    python scripts/generate_test_data.py --scenario all
    python scripts/generate_test_data.py --scenario critical_iam
    python scripts/generate_test_data.py --clean-first
    python scripts/generate_test_data.py --interactive
"""

import argparse
import asyncio
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import uuid

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cerebro.core import models
from cerebro.core.database import Base
from cerebro.core.config import settings
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session


def import_scenario_modules():
    """Import scenario modules dynamically."""
    scenarios_path = Path(__file__).parent.parent / "examples" / "scenarios"
    sys.path.insert(0, str(scenarios_path))
    
    try:
        from critical_iam_scenario import generate_critical_iam_scenario
        from data_exfiltration_incident import generate_data_exfiltration_scenario  
        from compliance_violation import generate_compliance_violation_scenario
        from multi_cloud_review import generate_multi_cloud_review_scenario
        from attack_path_scenario import generate_attack_path_scenario
        return {
            'critical_iam': generate_critical_iam_scenario,
            'data_exfiltration': generate_data_exfiltration_scenario,
            'compliance_violation': generate_compliance_violation_scenario,
            'multi_cloud_review': generate_multi_cloud_review_scenario,
            'attack_path': generate_attack_path_scenario
        }
    except ImportError as e:
        print(f"Error importing scenarios: {e}")
        return {}


class TestDataGenerator:
    """Generates and loads test data into Cerebro database."""
    
    def __init__(self, session: Session):
        self.session = session
        self.scenario_generators = import_scenario_modules()

# Create synchronous engine and session for scripts
sync_engine = create_engine(settings.database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=sync_engine)
    
    def clean_database(self):
        """Clean all test data from database."""
        print("🧹 Cleaning existing test data...")
        
        # Delete in reverse dependency order
        self.session.query(models.EvidenceArtifact).delete()
        self.session.query(models.Finding).delete()
        self.session.query(models.Suppression).delete()
        self.session.query(models.AuditEvent).delete()
        self.session.query(models.IamEdge).delete()
        self.session.query(models.ConfigSnapshot).delete()
        self.session.query(models.Rule).delete()
        self.session.query(models.Policy).delete()
        self.session.query(models.Resource).delete()
        self.session.query(models.Principal).delete()
        self.session.query(models.Account).delete()
        self.session.query(models.Organization).delete()
        
        self.session.commit()
        print("✅ Database cleaned")
    
    def load_organization(self, org_data: Dict[str, Any]) -> models.Organization:
        """Load organization data."""
        org = models.Organization(**org_data)
        self.session.add(org)
        return org
    
    def load_accounts(self, accounts_data: List[Dict[str, Any]]) -> List[models.Account]:
        """Load account data."""
        accounts = []
        for account_data in accounts_data:
            account = models.Account(**account_data)
            self.session.add(account)
            accounts.append(account)
        return accounts
    
    def load_principals(self, principals_data: List[Dict[str, Any]]) -> List[models.Principal]:
        """Load principal data."""
        principals = []
        for principal_data in principals_data:
            principal = models.Principal(**principal_data)
            self.session.add(principal)
            principals.append(principal)
        return principals
    
    def load_resources(self, resources_data: List[Dict[str, Any]]) -> List[models.Resource]:
        """Load resource data.""" 
        resources = []
        for resource_data in resources_data:
            resource = models.Resource(**resource_data)
            self.session.add(resource)
            resources.append(resource)
        return resources
    
    def load_config_snapshots(self, snapshots_data: List[Dict[str, Any]]):
        """Load configuration snapshot data."""
        for snapshot_data in snapshots_data:
            snapshot = models.ConfigSnapshot(**snapshot_data)
            self.session.add(snapshot)
    
    def load_iam_edges(self, edges_data: List[Dict[str, Any]]):
        """Load IAM edge data."""
        for edge_data in edges_data:
            edge = models.IamEdge(**edge_data)
            self.session.add(edge)
    
    def load_audit_events(self, events_data: List[Dict[str, Any]]):
        """Load audit event data."""
        for event_data in events_data:
            event = models.AuditEvent(**event_data)
            self.session.add(event)
    
    def load_rules(self, rules_data: List[Dict[str, Any]]):
        """Load rule data."""
        for rule_data in rules_data:
            rule = models.Rule(**rule_data)
            self.session.add(rule)
    
    def load_findings(self, findings_data: List[Dict[str, Any]]):
        """Load finding data."""
        for finding_data in findings_data:
            finding = models.Finding(**finding_data)
            self.session.add(finding)
    
    def generate_scenario(self, scenario_name: str) -> bool:
        """Generate and load a specific scenario."""
        if scenario_name not in self.scenario_generators:
            print(f"❌ Unknown scenario: {scenario_name}")
            print(f"Available scenarios: {list(self.scenario_generators.keys())}")
            return False
        
        print(f"🎬 Generating scenario: {scenario_name}")
        scenario_data = self.scenario_generators[scenario_name]()
        
        try:
            # Load data in dependency order
            org = self.load_organization(scenario_data['organization'])
            accounts = self.load_accounts(scenario_data['accounts'])
            principals = self.load_principals(scenario_data.get('principals', []))
            resources = self.load_resources(scenario_data.get('resources', []))
            
            # Commit base entities first
            self.session.commit()
            
            # Load dependent data
            if 'config_snapshots' in scenario_data:
                self.load_config_snapshots(scenario_data['config_snapshots'])
            
            if 'iam_edges' in scenario_data:
                self.load_iam_edges(scenario_data['iam_edges'])
            
            if 'audit_events' in scenario_data:
                self.load_audit_events(scenario_data['audit_events'])
            
            if 'rules' in scenario_data:
                self.load_rules(scenario_data['rules'])
            
            if 'findings' in scenario_data:
                self.load_findings(scenario_data['findings'])
            
            # Final commit
            self.session.commit()
            
            print(f"✅ Successfully loaded scenario: {scenario_name}")
            print(f"   Organization: {scenario_data['organization']['name']}")
            print(f"   Accounts: {len(scenario_data['accounts'])}")
            print(f"   Findings: {len(scenario_data.get('findings', []))}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error loading scenario {scenario_name}: {e}")
            self.session.rollback()
            return False
    
    def generate_all_scenarios(self):
        """Generate all available scenarios."""
        print("🎭 Generating all test scenarios...")
        success_count = 0
        
        for scenario_name in self.scenario_generators:
            if self.generate_scenario(scenario_name):
                success_count += 1
            print()  # Add spacing between scenarios
        
        print(f"✅ Successfully generated {success_count}/{len(self.scenario_generators)} scenarios")
    
    def generate_baseline_data(self):
        """Generate baseline organizations and accounts for general testing."""
        print("📊 Generating baseline test data...")
        
        # Test Organization 1 - Small Startup
        startup_org = models.Organization(
            org_id=uuid.uuid4(),
            name="StartupCorp",
            created_at=datetime.now()
        )
        self.session.add(startup_org)
        
        startup_aws = models.Account(
            account_id=uuid.uuid4(),
            org_id=startup_org.org_id,
            provider="aws",
            external_id="999999999999",
            display_name="StartupCorp AWS"
        )
        self.session.add(startup_aws)
        
        # Test Organization 2 - Large Enterprise
        enterprise_org = models.Organization(
            org_id=uuid.uuid4(),
            name="GlobalEnterprise Inc",
            created_at=datetime.now()
        )
        self.session.add(enterprise_org)
        
        # Multiple accounts for enterprise
        for i, (provider, ext_id, name) in enumerate([
            ("aws", "100000000001", "AWS Production"),
            ("aws", "100000000002", "AWS Development"),
            ("gcp", "enterprise-prod-2024", "GCP Production"),
            ("github", "globalenterprise", "GitHub Organization"),
        ]):
            account = models.Account(
                account_id=uuid.uuid4(),
                org_id=enterprise_org.org_id,
                provider=provider,
                external_id=ext_id,
                display_name=name
            )
            self.session.add(account)
        
        self.session.commit()
        print("✅ Baseline data generated")


def interactive_mode():
    """Run interactive test data generation."""
    print("🎯 Cerebro Test Data Generator - Interactive Mode")
    print("=" * 50)
    
    generator_funcs = import_scenario_modules()
    
    while True:
        print("\nAvailable actions:")
        print("1. Generate all scenarios")
        print("2. Generate specific scenario")
        print("3. Generate baseline data only")
        print("4. Clean database")
        print("5. Show scenario preview")
        print("6. Exit")
        
        choice = input("\nEnter your choice (1-6): ").strip()
        
        if choice == "1":
            with SessionLocal() as session:
                generator = TestDataGenerator(session)
                generator.generate_all_scenarios()
        
        elif choice == "2":
            print(f"\nAvailable scenarios: {list(generator_funcs.keys())}")
            scenario = input("Enter scenario name: ").strip()
            with SessionLocal() as session:
                generator = TestDataGenerator(session)
                generator.generate_scenario(scenario)
        
        elif choice == "3":
            with SessionLocal() as session:
                generator = TestDataGenerator(session)
                generator.generate_baseline_data()
        
        elif choice == "4":
            confirm = input("Are you sure you want to clean all data? (yes/no): ")
            if confirm.lower() == 'yes':
                with SessionLocal() as session:
                    generator = TestDataGenerator(session)
                    generator.clean_database()
        
        elif choice == "5":
            print(f"\nAvailable scenarios: {list(generator_funcs.keys())}")
            scenario = input("Enter scenario name for preview: ").strip()
            if scenario in generator_funcs:
                data = generator_funcs[scenario]()
                print(f"\nScenario: {data['scenario_name']}")
                print(f"Organization: {data['organization']['name']}")
                print(f"Accounts: {len(data.get('accounts', []))}")
                print(f"Findings: {len(data.get('findings', []))}")
                if 'investigation_notes' in data:
                    print(f"Priority: {data['investigation_notes'].get('priority', 'N/A')}")
        
        elif choice == "6":
            print("👋 Goodbye!")
            break
        
        else:
            print("❌ Invalid choice, please try again.")


def main():
    parser = argparse.ArgumentParser(description="Generate test data for Cerebro")
    parser.add_argument(
        "--scenario",
        choices=["all", "critical_iam", "data_exfiltration", "compliance_violation", "multi_cloud_review", "attack_path", "baseline"],
        help="Scenario to generate"
    )
    parser.add_argument("--clean-first", action="store_true", help="Clean database before generating data")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be generated without loading")
    
    args = parser.parse_args()
    
    if args.interactive:
        interactive_mode()
        return
    
    # Check database connection
    try:
        with SessionLocal() as session:
            session.execute("SELECT 1")
        print("✅ Database connection successful")
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        print("Make sure PostgreSQL is running and migrations are applied")
        return
    
    with SessionLocal() as session:
        generator = TestDataGenerator(session)
        
        if args.clean_first:
            generator.clean_database()
        
        if args.dry_run:
            print("🔍 Dry run mode - showing what would be generated:")
            scenario_funcs = import_scenario_modules()
            for name, func in scenario_funcs.items():
                data = func()
                print(f"\n{name}:")
                print(f"  Organization: {data['organization']['name']}")
                print(f"  Accounts: {len(data.get('accounts', []))}")
                print(f"  Findings: {len(data.get('findings', []))}")
            return
        
        if args.scenario == "all":
            generator.generate_all_scenarios()
        elif args.scenario == "baseline":
            generator.generate_baseline_data()
        elif args.scenario:
            generator.generate_scenario(args.scenario)
        else:
            print("No scenario specified. Use --help for options or --interactive for interactive mode.")


if __name__ == "__main__":
    main()
