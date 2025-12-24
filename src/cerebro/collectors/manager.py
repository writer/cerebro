"""Collector manager for orchestrating collection runs.

The manager coordinates high‑level collection workflows.  Whereas
``ConfigCollector`` handles the per‑account ingestion flow, this module decides
*which* accounts to process for an organisation, instantiates the appropriate
provider implementations, and aggregates the results for API consumers.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from cerebro.core.models import Account, Organization
from cerebro.providers import (
    GitHubProvider,
    AWSProvider,
    GCPProvider,
    GoogleWorkspaceProvider,
)
from .collector import ConfigCollector, CollectionResult

logger = logging.getLogger(__name__)


class CollectorManager:
    """Entry point for initiating collection runs across providers and accounts."""

    def __init__(self, db_session: AsyncSession):
        """Create a manager bound to a database session."""
        self.db = db_session
        self.collector = ConfigCollector(db_session)

    async def collect_organization(
        self,
        org_id: str,
        providers: Optional[List[str]] = None,
        resource_types: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Collect data for every account belonging to an organisation.

        Parameters
        ----------
        org_id:
            Organisation identifier whose accounts should be processed.
        providers:
            Optional allow‑list of provider identifiers; if supplied only matching
            accounts are collected.
        resource_types:
            Optional allow‑list of resource types to forward to the collector.

        Returns
        -------
        dict
            A JSON‑serialisable payload mirroring the :class:`CollectionResult`
            structure for consumers of the REST API.
        """
        start_time = datetime.utcnow()

        # Get organization
        org_stmt = select(Organization).where(Organization.org_id == org_id)
        org = await self.db.scalar(org_stmt)

        if not org:
            raise ValueError(f"Organization {org_id} not found")

        # Get accounts to collect
        account_stmt = select(Account).where(Account.org_id == org.org_id)
        if providers:
            account_stmt = account_stmt.where(Account.provider.in_(providers))

        accounts = await self.db.scalars(account_stmt)
        account_list = list(accounts)

        if not account_list:
            return {
                "organization": org.name,
                "accounts_processed": 0,
                "results": [],
                "duration_seconds": 0,
                "errors": ["No accounts found for collection"],
            }

        # Collect data for each account
        results = []
        errors = []

        for account in account_list:
            try:
                result = await self.collect_account(
                    account=account, resource_types=resource_types
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
            },
        }

    async def collect_account(
        self, account: Account, resource_types: Optional[List[str]] = None
    ) -> CollectionResult:
        """Collect data for a single account."""
        provider = self._create_provider(account)
        return await self.collector.collect_account(provider, account, resource_types)

    def _create_provider(self, account: Account):
        """Instantiate the correct provider implementation for an account."""
        if account.provider == "github":
            return GitHubProvider(
                account_id=account.account_id, org_name=account.external_id
            )
        elif account.provider == "aws":
            return AWSProvider(
                account_id=account.account_id, aws_account_id=account.external_id
            )
        elif account.provider == "gcp":
            return GCPProvider(
                account_id=account.account_id, project_id=account.external_id
            )
        elif account.provider == "google_workspace":
            return GoogleWorkspaceProvider(  # type: ignore[call-arg]
                account_id=account.account_id, domain=account.external_id
            )
        else:
            raise ValueError(f"Unknown provider: {account.provider}")

    async def schedule_collection(
        self,
        org_id: str,
        providers: Optional[List[str]] = None,
        interval_hours: int = 24,
    ) -> str:
        """Register a scheduled Celery beat task for recurring collection."""
        from celery.schedules import crontab

        # Calculate cron schedule for interval
        if interval_hours == 24:
            schedule = crontab(hour=2, minute=0)  # Daily at 2 AM
        elif interval_hours == 12:
            schedule = crontab(hour="2,14", minute=0)  # Twice daily
        elif interval_hours == 6:
            schedule = crontab(hour="2,8,14,20", minute=0)  # Every 6 hours
        else:
            # Custom interval - use periodic schedule
            from celery.schedules import schedule as celery_schedule

            schedule = celery_schedule(run_every=interval_hours * 3600)

        # Schedule the task
        from cerebro.tasks.celery_app import celery_app

        task_name = f"scheduled_collection_{org_id}_{'-'.join(providers or ['all'])}"

        celery_app.conf.beat_schedule[task_name] = {
            "task": "cerebro.tasks.collection_tasks.collect_organization_task",
            "schedule": schedule,
            "args": (org_id,),
            "kwargs": {"provider_filter": providers, "resource_types": None},
        }

        logger.info(
            f"Scheduled collection for org {org_id} every {interval_hours} hours"
        )
        return task_name
