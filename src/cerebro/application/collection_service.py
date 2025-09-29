"""Application service for configuration collection."""

from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime
import logging

from cerebro.domain.entities import CollectionJobEntity, ResourceEntity, PrincipalEntity, ConfigEntity, IamPermissionEntity
from cerebro.domain.ports import ProviderPort, RepositoryPort, IdentityStitcherPort, NotificationPort

logger = logging.getLogger(__name__)


class CollectionService:
    """Application service for orchestrating configuration collection."""
    
    def __init__(
        self,
        repository: RepositoryPort,
        identity_stitcher: IdentityStitcherPort,
        notification: Optional[NotificationPort] = None
    ):
        """Initialize collection service."""
        self.repository = repository
        self.identity_stitcher = identity_stitcher  
        self.notification = notification
    
    async def collect_account(
        self,
        account_id: UUID,
        org_id: UUID,
        provider: ProviderPort,
        resource_types: Optional[List[str]] = None
    ) -> CollectionJobEntity:
        """Collect all data for an account."""
        job = CollectionJobEntity(
            org_id=org_id,
            provider=provider.name,
            resource_types=resource_types or []
        )
        
        try:
            job.start()
            logger.info(f"Starting collection job {job.job_id} for provider {provider.name}")
            
            # Step 1: Discover and save resources
            resources = await self._collect_resources(provider, resource_types)
            if resources:
                resource_id_map = await self.repository.save_resources(account_id, resources)
                job.resources_collected = len(resources)
                logger.info(f"Collected {len(resources)} resources")
            else:
                resource_id_map = {}
            
            # Step 2: Discover and save principals  
            principals = await self._collect_principals(provider)
            if principals:
                principal_id_map = await self.repository.save_principals(account_id, principals)
                job.principals_collected = len(principals)
                logger.info(f"Collected {len(principals)} principals")
                
                # Step 3: Perform identity stitching
                await self._stitch_identities(org_id, principals)
            else:
                principal_id_map = {}
            
            # Step 4: Collect configurations
            configs = await self._collect_configurations(provider, resources)
            if configs:
                configs_saved = await self.repository.save_configurations(resource_id_map, configs)
                logger.info(f"Saved {configs_saved} configuration snapshots")
            
            # Step 5: Collect IAM permissions
            permissions = await self._collect_iam_permissions(provider, resources)
            if permissions:
                permissions_saved = await self.repository.save_iam_permissions(
                    account_id, resource_id_map, principal_id_map, permissions
                )
                logger.info(f"Saved {permissions_saved} IAM permissions")
            
            job.complete()
            
            # Send notification if configured
            if self.notification:
                await self._send_collection_notification(job)
                
        except Exception as e:
            logger.error(f"Collection job {job.job_id} failed: {e}")
            job.fail(str(e))
        
        return job
    
    async def _collect_resources(
        self,
        provider: ProviderPort,
        resource_types: Optional[List[str]]
    ) -> List[ResourceEntity]:
        """Collect resources from provider."""
        resources = []
        try:
            async for resource in provider.discover_resources(resource_types):
                resources.append(resource)
        except Exception as e:
            logger.error(f"Failed to collect resources from {provider.name}: {e}")
            raise
        
        return resources
    
    async def _collect_principals(
        self,
        provider: ProviderPort
    ) -> List[PrincipalEntity]:
        """Collect principals from provider."""
        principals = []
        try:
            async for principal in provider.discover_principals():
                principals.append(principal)
        except Exception as e:
            logger.error(f"Failed to collect principals from {provider.name}: {e}")
            raise
        
        return principals
    
    async def _collect_configurations(
        self,
        provider: ProviderPort,
        resources: List[ResourceEntity]
    ) -> List[ConfigEntity]:
        """Collect configurations for resources."""
        configs = []
        
        for resource in resources:
            try:
                config = await provider.get_resource_configuration(resource)
                configs.append(config)
            except Exception as e:
                logger.warning(f"Failed to get config for {resource.external_id}: {e}")
                continue
        
        return configs
    
    async def _collect_iam_permissions(
        self,
        provider: ProviderPort,
        resources: List[ResourceEntity]
    ) -> List[IamPermissionEntity]:
        """Collect IAM permissions."""
        permissions = []
        
        try:
            # Global permissions
            async for permission in provider.discover_iam_permissions():
                permissions.append(permission)
            
            # Resource-specific permissions
            for resource in resources:
                async for permission in provider.discover_iam_permissions(resource):
                    permissions.append(permission)
                    
        except Exception as e:
            logger.error(f"Failed to collect IAM permissions: {e}")
        
        return permissions
    
    async def _stitch_identities(
        self,
        org_id: UUID,
        principals: List[PrincipalEntity]
    ) -> None:
        """Perform identity stitching across providers."""
        try:
            clusters = await self.identity_stitcher.find_identity_clusters(org_id, principals)
            logger.info(f"Found {len(clusters)} identity clusters")
            
            # Save identity clusters to repository
            from cerebro.core.identity_cluster_repository import IdentityClusterRepository
            cluster_repo = IdentityClusterRepository(self.db)
            await cluster_repo.save_clusters(org_id, clusters)
            logger.info(f"Saved {len(clusters)} identity clusters to repository")
            
        except Exception as e:
            logger.error(f"Identity stitching failed: {e}")
    
    async def _send_collection_notification(self, job: CollectionJobEntity) -> None:
        """Send collection completion notification."""
        try:
            # TODO: Get notification recipients from configuration
            recipients = ["security-team@company.com"]
            await self.notification.send_collection_summary(job, recipients)
        except Exception as e:
            logger.warning(f"Failed to send collection notification: {e}")


class CollectionOrchestrator:
    """Orchestrates collection across multiple providers."""
    
    def __init__(
        self,
        collection_service: CollectionService,
        providers: Dict[str, ProviderPort]
    ):
        """Initialize collection orchestrator."""
        self.collection_service = collection_service
        self.providers = providers
    
    async def collect_organization(
        self,
        org_id: UUID,
        accounts: List[Dict[str, Any]],
        provider_filter: Optional[List[str]] = None
    ) -> List[CollectionJobEntity]:
        """Collect data for all accounts in an organization."""
        jobs = []
        
        for account in accounts:
            account_id = account["account_id"]
            provider_name = account["provider"]
            
            # Skip if provider filter is specified and doesn't match
            if provider_filter and provider_name not in provider_filter:
                continue
            
            # Skip if provider not available
            if provider_name not in self.providers:
                logger.warning(f"Provider {provider_name} not available")
                continue
            
            try:
                provider = self.providers[provider_name]
                job = await self.collection_service.collect_account(
                    account_id, org_id, provider
                )
                jobs.append(job)
                
            except Exception as e:
                logger.error(f"Failed to collect account {account_id}: {e}")
                # Create failed job record
                job = CollectionJobEntity(org_id=org_id, provider=provider_name)
                job.fail(str(e))
                jobs.append(job)
        
        return jobs
