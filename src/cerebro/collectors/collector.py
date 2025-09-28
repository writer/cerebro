"""Configuration collector implementation."""

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
from cerebro.core.bulk_operations import BulkOperations

logger = logging.getLogger(__name__)


@dataclass
class CollectionResult:
    """Result of a collection run."""
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
    """Collects configuration and IAM data from providers."""
    
    def __init__(self, db_session: AsyncSession):
        """Initialize collector."""
        self.db = db_session
        self.bulk_ops = BulkOperations(db_session)
        
    async def collect_account(
        self,
        provider: BaseProvider,
        account: Account,
        resource_types: Optional[List[str]] = None
    ) -> CollectionResult:
        """Collect all data for an account."""
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
        """Collect resources from provider using bulk operations."""
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
        """Collect principals from provider using bulk operations."""
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
        """Collect resource configurations."""
        try:
            # Get all resources for this account
            stmt = select(Resource).where(
                and_(
                    Resource.account_id == account.account_id,
                    Resource.provider == provider.name
                )
            )
            resources = await self.db.scalars(stmt)
            
            for resource in resources:
                try:
                    # Get configuration from provider
                    resource_info = type('ResourceInfo', (), {
                        'external_id': resource.external_id,
                        'resource_type': resource.resource_type,
                        'name': resource.name
                    })()
                    
                    config_snapshot = await provider.get_resource_configuration(resource_info)
                    
                    # Calculate config hash
                    config_json = json.dumps(config_snapshot.normalized_config, sort_keys=True)
                    config_sha = hashlib.sha256(config_json.encode()).digest()
                    
                    # Check if this exact configuration already exists
                    stmt = select(ConfigSnapshot).where(
                        and_(
                            ConfigSnapshot.resource_id == resource.resource_id,
                            ConfigSnapshot.config_sha == config_sha
                        )
                    )
                    existing_snapshot = await self.db.scalar(stmt)
                    
                    if not existing_snapshot:
                        # Create new config snapshot
                        snapshot = ConfigSnapshot(
                            resource_id=resource.resource_id,
                            captured_at=config_snapshot.captured_at,
                            config_sha=config_sha,
                            normalized_config=config_snapshot.normalized_config,
                            collector_version="1.0.0"
                        )
                        self.db.add(snapshot)
                        result.config_snapshots += 1
                        logger.debug(f"New config snapshot for resource: {resource.external_id}")
                
                except Exception as e:
                    error_msg = f"Failed to collect config for {resource.external_id}: {e}"
                    logger.warning(error_msg)
                    result.errors.append(error_msg)
            
        except Exception as e:
            error_msg = f"Failed to collect configurations: {e}"
            logger.error(error_msg)
            result.errors.append(error_msg)
    
    async def _collect_iam_edges(
        self,
        provider: BaseProvider,
        account: Account,
        result: CollectionResult
    ) -> None:
        """Collect IAM permissions."""
        try:
            async for iam_permission in provider.discover_iam_edges():
                # Get principal
                stmt = select(Principal).where(
                    and_(
                        Principal.account_id == account.account_id,
                        Principal.provider == provider.name,
                        Principal.external_id == iam_permission.principal_external_id
                    )
                )
                principal = await self.db.scalar(stmt)
                
                if not principal:
                    logger.warning(f"Principal not found: {iam_permission.principal_external_id}")
                    continue
                
                # Get resource (if specified)
                resource = None
                if iam_permission.resource_external_id:
                    stmt = select(Resource).where(
                        and_(
                            Resource.account_id == account.account_id,
                            Resource.provider == provider.name,
                            Resource.external_id == iam_permission.resource_external_id
                        )
                    )
                    resource = await self.db.scalar(stmt)
                
                # Create IAM edge (always append-only)
                iam_edge = IamEdge(
                    account_id=account.account_id,
                    provider=provider.name,
                    principal_id=principal.principal_id,
                    resource_id=resource.resource_id if resource else None,
                    permission=iam_permission.permission,
                    via=iam_permission.via,
                    effective_at=iam_permission.effective_at or datetime.utcnow(),
                    expires_at=iam_permission.expires_at,
                    is_admin=iam_permission.is_admin
                )
                self.db.add(iam_edge)
                result.iam_edges += 1
                
        except Exception as e:
            error_msg = f"Failed to collect IAM edges: {e}"
            logger.error(error_msg)
            result.errors.append(error_msg)
