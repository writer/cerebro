#!/usr/bin/env python3
"""Setup script for Cerebro development environment."""

import asyncio
import sys
from pathlib import Path

# Add src to path so we can import cerebro
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cerebro.core.database import async_session_factory, engine
from cerebro.core.models import Organization, Account, Rule, Policy
from cerebro.rules.library import RuleLibrary


async def create_sample_data():
    """Create sample data for development."""
    async with async_session_factory() as db:
        # Create sample organization
        org = Organization(name="Acme Corp")
        db.add(org)
        await db.commit()
        await db.refresh(org)
        print(f"Created organization: {org.name}")
        
        # Create sample accounts
        github_account = Account(
            org_id=org.org_id,
            provider="github",
            external_id="acme-corp",
            display_name="Acme Corp GitHub"
        )
        
        aws_account = Account(
            org_id=org.org_id,
            provider="aws",
            external_id="123456789012",
            display_name="Acme Corp Production AWS"
        )
        
        db.add_all([github_account, aws_account])
        await db.commit()
        print(f"Created accounts: GitHub, AWS")
        
        # Create sample policy
        policy = Policy(
            org_id=org.org_id,
            name="Security Baseline",
            description="Basic security requirements for all resources",
            framework="CIS"
        )
        db.add(policy)
        await db.commit()
        await db.refresh(policy)
        
        # Load prebuilt rules
        rule_templates = RuleLibrary.get_all_rules()
        
        for template in rule_templates[:5]:  # Add first 5 rules
            rule = Rule(
                policy_id=policy.policy_id,
                name=template.name,
                description=template.description,
                provider=template.provider,
                resource_types=template.resource_types,
                expression_lang="cel",
                expression=template.expression,
                severity=template.severity,
                cis=template.framework_mappings.get("cis", []),
                nist_800_53=template.framework_mappings.get("nist_800_53", []),
                cwe=template.framework_mappings.get("cwe", [])
            )
            db.add(rule)
        
        await db.commit()
        print(f"Created {len(rule_templates[:5])} security rules")
        
        print("\n🎉 Sample data created successfully!")
        print(f"Organization ID: {org.org_id}")
        print(f"Policy ID: {policy.policy_id}")


async def run_database_migration():
    """Run database migration."""
    from alembic.config import Config
    from alembic import command
    
    # Run migration
    print("Running database migration...")
    alembic_cfg = Config("alembic.ini")
    command.upgrade(alembic_cfg, "head")
    print("✅ Database migration completed")


async def main():
    """Main setup function."""
    print("🚀 Setting up Cerebro development environment...\n")
    
    try:
        # Run migration
        await run_database_migration()
        
        # Create sample data
        await create_sample_data()
        
        print("\n✅ Setup completed successfully!")
        print("\nNext steps:")
        print("1. Start the API server: uvicorn cerebro.api.main:app --reload")
        print("2. View API docs: http://localhost:8000/docs")
        print("3. Use CLI: python -m cerebro.cli --help")
        
    except Exception as e:
        print(f"❌ Setup failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
