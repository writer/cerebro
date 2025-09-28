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
            provider=provider.get_provider_name
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
        """Collect resources from provider."""
        try:
            async for resource_info in provider.discover_resources(resource_types):
                # Check if resource already exists
                stmt = select(Resource).where(
                    and_(
                        Resource.account_id == account.account_id,
                        Resource.provider == provider.get_provider_name,
                        Resource.resource_type == resource_info.resource_type,
                        Resource.external_id == resource_info.external_id
                    )
                )
                existing_resource = await self.db.scalar(stmt)
                
                if not existing_resource:
                    # Create new resource
                    resource = Resource(
                        account_id=account.account_id,
                        provider=provider.get_provider_name,
                        resource_type=resource_info.resource_type,
                        external_id=resource_info.external_id,
                        name=resource_info.name,
                        parent_external_id=resource_info.parent_external_id
                    )
                    self.db.add(resource)
                    result.resources_discovered += 1
                    logger.debug(f"Discovered new resource: {resource_info.external_id}")
                
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
        """Collect principals from provider."""
        try:
            async for principal_info in provider.discover_principals():
                # Check if principal already exists
                stmt = select(Principal).where(
                    and_(
                        Principal.account_id == account.account_id,
                        Principal.provider == provider.get_provider_name,
                        Principal.external_id == principal_info.external_id
                    )
                )
                existing_principal = await self.db.scalar(stmt)
                
                if not existing_principal:
                    # Create new principal
                    principal = Principal(
                        account_id=account.account_id,
                        provider=provider.get_provider_name,
                        principal_type=principal_info.principal_type,
                        external_id=principal_info.external_id,
                        email=principal_info.email,
                        display_name=principal_info.display_name,
                        is_human=principal_info.is_human
                    )
                    self.db.add(principal)
                    result.principals_discovered += 1
                    logger.debug(f"Discovered new principal: {principal_info.external_id}")
                
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
                    Resource.provider == provider.get_provider_name
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
                        Principal.provider == provider.get_provider_name,
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
                            Resource.provider == provider.get_provider_name,
                            Resource.external_id == iam_permission.resource_external_id
                        )
                    )
                    resource = await self.db.scalar(stmt)
                
                # Create IAM edge (always append-only)
                iam_edge = IamEdge(
                    account_id=account.account_id,
                    provider=provider.get_provider_name,
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
