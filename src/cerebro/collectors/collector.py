"""Configuration collector implementation.

This module contains the machinery that coordinates data ingestion from
third‑party providers.  It defines :class:`CollectionResult`, a structured
summary describing what was collected for an account, and
:class:`ConfigCollector`, which orchestrates the step‑by‑step harvesting of
resources, principals, configuration snapshots, and IAM edges using provider
SDKs and the bulk database helpers.
"""

import asyncio
import hashlib
import json
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from cerebro.core.models import (
    Account, Resource, Principal, ConfigSnapshot, IamEdge
)
from cerebro.providers.base import BaseProvider
from cerebro.core.config import settings
from cerebro.core.bulk_operations import BulkOperations, compute_config_hash
from cerebro.metrics.collection_metrics import collection_metrics

logger = logging.getLogger(__name__)


@dataclass
class CollectionResult:
    """Aggregate statistics produced during a collection run.

    The collector updates this structure as each phase completes so callers can
    surface helpful diagnostics (for example in API responses, telemetry
    counters, or administrator dashboards).

    Attributes
    ----------
    account_id:
        Primary key of the account that was processed.
    provider:
        Canonical provider identifier (``"github"``, ``"aws"`` …).
    resources_discovered:
        Number of resources upserted during the run.
    principals_discovered:
        Number of principals (users, groups, roles) upserted during the run.
    config_snapshots:
        Count of unique configuration snapshots stored.
    iam_edges:
        Number of IAM edges persisted after deduplication.
    errors:
        List collecting human‑readable error messages encountered mid‑flight.
    duration_seconds:
        Total wall clock duration of the run.
    """
    account_id: UUID
    provider: str
    resources_discovered: int = 0
    principals_discovered: int = 0
    config_snapshots: int = 0
    iam_edges: int = 0
    errors: List[str] = None
    duration_seconds: float = 0.0
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []


class ConfigCollector:
    """Collect resources, principals, configurations, and IAM edges for an account.

    The collector delegates to a :class:`~cerebro.providers.base.BaseProvider`
    implementation for provider‑specific API access, then normalises and stores
    the results using :class:`~cerebro.core.bulk_operations.BulkOperations`.
    Each public method returns a :class:`CollectionResult` detailing what was
    discovered so callers can attach rich telemetry or API responses.
    """
    
    def __init__(self, db_session: AsyncSession):
        """Initialise the collector with a database session.

        Parameters
        ----------
        db_session:
            Async SQLAlchemy session used for both reads and writes during a
            collection run.  The session is expected to be scoped per request so
            that the collector may safely commit or roll back without impacting
            other work.
        """
        self.db = db_session
        self.bulk_ops = BulkOperations(db_session)
        
    async def collect_account(
        self,
        provider: BaseProvider,
        account: Account,
        resource_types: Optional[List[str]] = None
    ) -> CollectionResult:
        """Collect all supported artefacts for an account.

        Parameters
        ----------
        provider:
            Provider implementation used to fetch source data.  The caller is
            responsible for instantiating it with whatever credentials are
            required.
        account:
            Account model instance that identifies which records to update.
        resource_types:
            Optional allow‑list limiting the set of resource types to collect
            (useful for incremental syncs).

        Returns
        -------
        CollectionResult
            Summarised statistics for the run including any errors that were
            encountered.  Errors are logged and recorded but do not raise unless
            the failure prevents continued processing.
        """
        start_time = datetime.utcnow()
        result = CollectionResult(
            account_id=account.account_id,
            provider=provider.name
        )
        
        try:
            logger.info(f"Starting collection for account {account.external_id}")
            
            # Authenticate provider
            if not await provider.authenticate():
                raise Exception("Provider authentication failed")
            
            # Collect resources
            await self._collect_resources(provider, account, resource_types, result)
            
            # Collect principals
            await self._collect_principals(provider, account, result)
            
            # Collect configurations
            await self._collect_configurations(provider, account, result)
            
            # Collect IAM edges
            await self._collect_iam_edges(provider, account, result)
            
            # Commit changes
            await self.db.commit()
            
            logger.info(f"Collection completed for account {account.external_id}: "
                       f"{result.resources_discovered} resources, "
                       f"{result.principals_discovered} principals, "
                       f"{result.config_snapshots} configs, "
                       f"{result.iam_edges} IAM edges")
            
        except Exception as e:
            logger.error(f"Collection failed for account {account.external_id}: {e}")
            result.errors.append(str(e))
            await self.db.rollback()
        
        result.duration_seconds = (datetime.utcnow() - start_time).total_seconds()
        return result
    
    async def _collect_resources(
        self,
        provider: BaseProvider,
        account: Account,
        resource_types: Optional[List[str]],
        result: CollectionResult
    ) -> None:
        """Collect and upsert resources exposed by the provider.

        This stage first requests an iterator from the provider, then uses the
        bulk upsert helper to persist batches, updating the ``result`` counters
        along the way.  Any provider errors are trapped so the collector can
        proceed with subsequent phases.
        """
        try:
            # Collect all resources first
            resources = []
            async for resource_info in provider.discover_resources(resource_types):
                resources.append({
                    "resource_type": resource_info.resource_type,
                    "external_id": resource_info.external_id,
                    "name": resource_info.name,
                    "parent_external_id": resource_info.parent_external_id,
                })
            
            if resources:
                # Bulk upsert resources
                bulk_result = await self.bulk_ops.bulk_upsert_resources(
                    account.account_id,
                    provider.name,
                    resources
                )
                result.resources_discovered += bulk_result["processed"]
                logger.info(f"Bulk processed {bulk_result['processed']} resources")
            
        except Exception as e:
            error_msg = f"Failed to collect resources: {e}"
            logger.error(error_msg)
            result.errors.append(error_msg)
    
    async def _collect_principals(
        self,
        provider: BaseProvider,
        account: Account,
        result: CollectionResult
    ) -> None:
        """Collect and upsert principals associated with the account.

        Principals include human users, service accounts, groups, and roles. The
        provider is responsible for flagging the type; the collector simply
        normalises and writes the records.
        """
        try:
            # Collect all principals first
            principals = []
            async for principal_info in provider.discover_principals():
                principals.append({
                    "principal_type": principal_info.principal_type,
                    "external_id": principal_info.external_id,
                    "email": principal_info.email,
                    "display_name": principal_info.display_name,
                    "is_human": principal_info.is_human,
                })
            
            if principals:
                # Bulk upsert principals
                bulk_result = await self.bulk_ops.bulk_upsert_principals(
                    account.account_id,
                    provider.name,
                    principals
                )
                result.principals_discovered += bulk_result["processed"]
                logger.info(f"Bulk processed {bulk_result['processed']} principals")
                
        except Exception as e:
            error_msg = f"Failed to collect principals: {e}"
            logger.error(error_msg)
            result.errors.append(error_msg)
    
    async def _collect_configurations(
        self,
        provider: BaseProvider,
        account: Account,
        result: CollectionResult
    ) -> None:
        """Collect per‑resource configuration snapshots with bounded concurrency."""
        with collection_metrics.time_collection(
            provider.name, str(account.account_id), "configurations"
        ):
            try:
                # Get all resources for this account
                stmt = select(Resource).where(
                    and_(
                        Resource.account_id == account.account_id,
                        Resource.provider == provider.name
                    )
                )
                resources = list(await self.db.scalars(stmt))
                
                if not resources:
                    logger.info("No resources found for configuration collection")
                    return
                
                logger.info(f"Starting concurrent config collection for {len(resources)} resources")
                
                # Create semaphore to limit concurrency
                semaphore = asyncio.Semaphore(settings.collection_concurrency_limit)
                
                # Collect configurations concurrently
                config_tasks = []
                for resource in resources:
                    task = self._fetch_single_config(semaphore, provider, resource)
                    config_tasks.append(task)
                
                # Wait for all config fetches to complete
                config_results = await asyncio.gather(*config_tasks, return_exceptions=True)
                
                # Process results and prepare for bulk insert
                snapshots_to_insert = []
                for i, config_result in enumerate(config_results):
                    resource = resources[i]
                    
                    if isinstance(config_result, Exception):
                        error_msg = f"Failed to collect config for resource {resource.external_id}: {config_result}"
                        logger.warning(error_msg)
                        result.errors.append(error_msg)
                        continue
                    
                    if config_result is None:
                        continue  # No config returned
                    
                    # Prepare snapshot for bulk insert
                    config_sha = compute_config_hash(config_result['normalized_config'])
                    snapshots_to_insert.append({
                        'resource_id': resource.resource_id,
                        'captured_at': config_result['captured_at'],
                        'config_sha': config_sha,
                        'normalized_config': config_result['normalized_config'],
                        'collector_version': "1.0.0"
                    })
                
                # Bulk insert new configurations
                if snapshots_to_insert:
                    with collection_metrics.time_bulk_operation("config_snapshots", len(snapshots_to_insert)):
                        inserted_count = await self.bulk_ops.bulk_insert_config_snapshots(
                            account.account_id, snapshots_to_insert
                        )
                        result.config_snapshots = inserted_count
                        collection_metrics.record_configs_collected(
                            provider.name, 
                            str(account.account_id),
                            "all",  # resource_type aggregated
                            inserted_count
                        )
                
                logger.info(f"Config collection completed: {result.config_snapshots} new snapshots")
                
            except Exception as e:
                error_msg = f"Failed to collect configurations: {e}"
                logger.error(error_msg)
                result.errors.append(error_msg)

    async def _fetch_single_config(
        self,
        semaphore: asyncio.Semaphore,
        provider: BaseProvider,
        resource: Resource
    ) -> Optional[Dict[str, Any]]:
        """Fetch configuration for a single resource respecting the concurrency cap."""
        async with semaphore:
            try:
                with collection_metrics.time_provider_api(provider.name, "get_config"):
                    # Create resource info object
                    resource_info = type('ResourceInfo', (), {
                        'external_id': resource.external_id,
                        'resource_type': resource.resource_type,
                        'name': resource.name
                    })()
                    
                    config_snapshot = await provider.get_resource_configuration(resource_info)
                    
                    return {
                        'captured_at': config_snapshot.captured_at,
                        'normalized_config': config_snapshot.normalized_config
                    }
                    
            except Exception as e:
                logger.debug(f"Config fetch failed for {resource.external_id}: {e}")
                # Let the caller handle the exception
                raise
    
    async def _collect_iam_edges(
        self,
        provider: BaseProvider,
        account: Account,
        result: CollectionResult
    ) -> None:
        """Collect IAM edges, ensuring principals/resources are preloaded for fast lookups."""
        with collection_metrics.time_collection(
            provider.name, str(account.account_id), "iam_edges"
        ):
            try:
                # Preload principal and resource lookup maps to avoid N+1 queries
                logger.info("Preloading principal and resource lookup maps")
                principal_map = await self.bulk_ops.preload_principal_map(
                    account.account_id, provider.name
                )
                resource_map = await self.bulk_ops.preload_resource_map(
                    account.account_id, provider.name
                )
                
                logger.info(f"Loaded {len(principal_map)} principals and {len(resource_map)} resources")
                
                # Collect IAM edges in batches
                edges_to_insert = []
                edge_count = 0
                
                async for iam_permission in provider.discover_iam_edges():
                    edge_count += 1
                    
                    # Look up principal ID
                    principal_id = principal_map.get(iam_permission.principal_external_id)
                    if not principal_id:
                        logger.debug(f"Principal not found in map: {iam_permission.principal_external_id}")
                        result.errors.append(f"Principal not found: {iam_permission.principal_external_id}")
                        continue
                    
                    # Look up resource ID (if specified)
                    resource_id = None
                    if iam_permission.resource_external_id:
                        resource_id = resource_map.get(iam_permission.resource_external_id)
                        if not resource_id:
                            logger.debug(f"Resource not found in map: {iam_permission.resource_external_id}")
                    
                    # Prepare edge for bulk insert
                    edge_data = {
                        'account_id': account.account_id,
                        'provider': provider.name,
                        'principal_id': principal_id,
                        'resource_id': resource_id,
                        'permission': iam_permission.permission,
                        'via': iam_permission.via,
                        'effective_at': iam_permission.effective_at or datetime.utcnow(),
                        'expires_at': iam_permission.expires_at,
                        'is_admin': iam_permission.is_admin or False
                    }
                    edges_to_insert.append(edge_data)
                    
                    # Flush batch when it reaches the configured size
                    if len(edges_to_insert) >= settings.iam_edge_batch_size:
                        with collection_metrics.time_bulk_operation("iam_edges", len(edges_to_insert)):
                            inserted = await self.bulk_ops.bulk_insert_iam_edges(edges_to_insert)
                            result.iam_edges += inserted
                        
                        edges_to_insert = []  # Reset for next batch
                
                # Insert remaining edges
                if edges_to_insert:
                    with collection_metrics.time_bulk_operation("iam_edges", len(edges_to_insert)):
                        inserted = await self.bulk_ops.bulk_insert_iam_edges(edges_to_insert)
                        result.iam_edges += inserted
                
                # Record metrics
                collection_metrics.record_iam_edges_collected(
                    provider.name, 
                    str(account.account_id),
                    result.iam_edges
                )
                
                logger.info(f"IAM edge collection completed: {result.iam_edges} new edges from {edge_count} discovered")
                
            except Exception as e:
                error_msg = f"Failed to collect IAM edges: {e}"
                logger.error(error_msg)
                result.errors.append(error_msg)
