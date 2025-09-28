"""Collector manager for orchestrating collection runs."""

from typing import Any, Dict, List, Optional
from datetime import datetime
import logging
import asyncio

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from cerebro.core.models import Account, Organization
from cerebro.providers import GitHubProvider, AWSProvider, GCPProvider, GoogleWorkspaceProvider
from .collector import ConfigCollector, CollectionResult

logger = logging.getLogger(__name__)


class CollectorManager:
    """Manages collection runs across multiple accounts and providers."""
    
    def __init__(self, db_session: AsyncSession):
        """Initialize collector manager."""
        self.db = db_session
        self.collector = ConfigCollector(db_session)
    
    async def collect_organization(
        self,
        org_id: str,
        providers: Optional[List[str]] = None,
        resource_types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Collect data for all accounts in an organization."""
        start_time = datetime.utcnow()
        
        # Get organization
        stmt = select(Organization).where(Organization.org_id == org_id)
        org = await self.db.scalar(stmt)
        
        if not org:
            raise ValueError(f"Organization {org_id} not found")
        
        # Get accounts to collect
        stmt = select(Account).where(Account.org_id == org.org_id)
        if providers:
            stmt = stmt.where(Account.provider.in_(providers))
        
        accounts = await self.db.scalars(stmt)
        account_list = list(accounts)
        
        if not account_list:
            return {
                "organization": org.name,
                "accounts_processed": 0,
                "results": [],
                "duration_seconds": 0,
                "errors": ["No accounts found for collection"]
            }
        
        # Collect data for each account
        results = []
        errors = []
        
        for account in account_list:
            try:
                result = await self.collect_account(
                    account=account,
                    resource_types=resource_types
                )
                results.append(result)
            except Exception as e:
                error_msg = f"Failed to collect account {account.external_id}: {e}"
                logger.error(error_msg)
                errors.append(error_msg)
        
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        return {
            "organization": org.name,
            "accounts_processed": len(results),
            "results": results,
            "duration_seconds": duration,
            "errors": errors,
            "summary": {
                "total_resources": sum(r.resources_discovered for r in results),
                "total_principals": sum(r.principals_discovered for r in results),
                "total_configs": sum(r.config_snapshots for r in results),
                "total_iam_edges": sum(r.iam_edges for r in results),
            }
        }
    
    async def collect_account(
        self,
        account: Account,
        resource_types: Optional[List[str]] = None
    ) -> CollectionResult:
        """Collect data for a single account."""
        provider = self._create_provider(account)
        return await self.collector.collect_account(provider, account, resource_types)
    
    def _create_provider(self, account: Account):
        """Create provider instance for account."""
        if account.provider == "github":
            return GitHubProvider(
                account_id=account.account_id,
                org_name=account.external_id
            )
        elif account.provider == "aws":
            return AWSProvider(
                account_id=account.account_id,
                aws_account_id=account.external_id
            )
        elif account.provider == "gcp":
            return GCPProvider(
                account_id=account.account_id,
                project_id=account.external_id
            )
        elif account.provider == "google_workspace":
            return GoogleWorkspaceProvider(
                account_id=account.account_id,
                domain=account.external_id
            )
        else:
            raise ValueError(f"Unknown provider: {account.provider}")
    
    async def schedule_collection(
        self,
        org_id: str,
        providers: Optional[List[str]] = None,
        interval_hours: int = 24
    ) -> None:
        """Schedule periodic collection (simple implementation)."""
        # This is a basic implementation. In production, you'd use a proper scheduler
        while True:
            try:
                logger.info(f"Starting scheduled collection for org {org_id}")
                result = await self.collect_organization(org_id, providers)
                logger.info(f"Scheduled collection completed: {result['summary']}")
            except Exception as e:
                logger.error(f"Scheduled collection failed: {e}")
            
            # Wait for next collection
            await asyncio.sleep(interval_hours * 3600)
