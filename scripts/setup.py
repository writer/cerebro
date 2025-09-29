#!/usr/bin/env python3
"""Setup script for Cerebro development environment."""

import asyncio
import sys
from pathlib import Path

# Add src to path so we can import cerebro
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from cerebro.core.database import async_session_factory, engine
from cerebro.core.models import Organization, Account, Rule, Policy
from cerebro.core.user_service import UserService
from cerebro.rules.library import RuleLibrary
from cerebro.rules.rule_service import RuleService


async def create_sample_data():
    """Create sample data for development."""
    async with async_session_factory() as db:
        # Initialize user service
        user_service = UserService(db)
        
        # Create default scopes
        await user_service.create_default_scopes()
        print("Created default scopes")
        
        # Create admin user with generated password
        try:
            admin_user = await user_service.create_admin_user(
                username="admin",
                email="admin@cerebro.local"
                # password will be auto-generated and logged
            )
            print(f"Created admin user: {admin_user.username}")
        except ValueError as e:
            print(f"Admin user already exists: {e}")
        
        # Create analyst user with generated password  
        try:
            import secrets
            import string
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
            analyst_password = ''.join(secrets.choice(alphabet) for _ in range(16))
            
            analyst_user = await user_service.create_user(
                username="analyst",
                email="analyst@cerebro.local", 
                password=analyst_password,
                scopes=["read:findings", "read:rules", "read:organizations", "read:resources"]
            )
            print(f"Created analyst user: {analyst_user.username}")
            print(f"Analyst password: {analyst_password}")
        except ValueError as e:
            print(f"Analyst user already exists: {e}")
        
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
        
        # Initialize rule service and create rules from library
        rule_service = RuleService(db)
        rule_mapping = await rule_service.ensure_library_rules_exist(org.org_id)
        print(f"Created {len(rule_mapping)} security rules from library")
        
        # Sync rules with producers
        producer_sync_result = await rule_service.sync_rules_with_producers(org.org_id)
        print(f"Synced with producers: {producer_sync_result}")
        
        print("\n🎉 Sample data created successfully!")
        print(f"Organization ID: {org.org_id}")
        print(f"Admin user: admin / admin123!")
        print(f"Analyst user: analyst / analyst123!")
        print(f"Total rules: {len(rule_mapping) + producer_sync_result['created']}")


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
