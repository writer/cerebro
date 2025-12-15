"""Collection background tasks."""

from typing import List, Optional, Dict, Any
from uuid import UUID
import logging
import asyncio


from cerebro.tasks.celery_app import celery_app
from cerebro.core.database import async_session_factory
from cerebro.core.models import Account, Organization
from cerebro.application.collection_service import CollectionService
from cerebro.infrastructure.adapters import SQLAlchemyRepository
from cerebro.infrastructure.provider_registry import get_provider_registry

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name='cerebro.tasks.collection_tasks.collect_account_task')
def collect_account_task(
    self,
    account_id: str,
    org_id: str,
    provider_name: str,
    provider_config: Dict[str, Any],
    resource_types: Optional[List[str]] = None
):
    """Background task to collect data for a single account."""
    
    async def _collect():
        task_id = self.request.id
        logger.info(f"Starting collection task {task_id} for account {account_id}")
        
        try:
            # Update task state
            self.update_state(
                state='PROGRESS',
                meta={'status': 'Initializing', 'progress': 0}
            )
            
            async with async_session_factory() as db:
                # Get account and organization
                account = await db.get(Account, UUID(account_id))
                org = await db.get(Organization, UUID(org_id))
                
                if not account or not org:
                    raise ValueError("Account or organization not found")
                
                # Update progress
                self.update_state(
                    state='PROGRESS',
                    meta={'status': 'Creating provider', 'progress': 10}
                )
                
                # Create provider instance
                provider_registry = get_provider_registry()
                provider = provider_registry.create_provider(provider_name, **provider_config)
                
                # Initialize services
                repository = SQLAlchemyRepository(db)
                
                # Initialize identity stitcher if needed
                identity_stitcher = None
                if provider_config.get("enable_identity_stitching", False):
                    from cerebro.infrastructure.adapters import IdentityStitcherAdapter
                    identity_stitcher = IdentityStitcherAdapter(db)
                
                collection_service = CollectionService(repository, identity_stitcher)  # type: ignore
                
                # Update progress
                self.update_state(
                    state='PROGRESS',
                    meta={'status': 'Collecting data', 'progress': 20}
                )
                
                # Run collection
                job = await collection_service.collect_account(
                    UUID(account_id), UUID(org_id), provider, resource_types
                )
                
                # Update progress based on job status
                progress = 90 if job.status == 'completed' else 50
                self.update_state(
                    state='PROGRESS',
                    meta={
                        'status': f'Collection {job.status}',
                        'progress': progress,
                        'resources_collected': job.resources_collected,
                        'principals_collected': job.principals_collected,
                        'errors': job.errors
                    }
                )
                
                logger.info(f"Collection task {task_id} completed: {job.status}")
                
                return {
                    'job_id': str(job.job_id),
                    'status': job.status,
                    'resources_collected': job.resources_collected,
                    'principals_collected': job.principals_collected,
                    'errors': job.errors,
                    'duration_seconds': (
                        job.completed_at - job.started_at
                    ).total_seconds() if job.completed_at and job.started_at else None
                }
                
        except Exception as e:
            logger.error(f"Collection task {task_id} failed: {e}")
            self.update_state(
                state='FAILURE',
                meta={'error': str(e)}
            )
            raise
    
    # Run the async function
    return asyncio.run(_collect())


@celery_app.task(bind=True, name='cerebro.tasks.collection_tasks.collect_organization_task')
def collect_organization_task(
    self,
    org_id: str,
    provider_filter: Optional[List[str]] = None,
    resource_types: Optional[List[str]] = None
):
    """Background task to collect data for all accounts in an organization."""
    
    async def _collect():
        task_id = self.request.id
        logger.info(f"Starting organization collection task {task_id} for org {org_id}")
        
        try:
            self.update_state(
                state='PROGRESS',
                meta={'status': 'Loading accounts', 'progress': 0}
            )
            
            async with async_session_factory() as db:
                from sqlalchemy import select
                
                # Get organization and accounts
                org = await db.get(Organization, UUID(org_id))
                if not org:
                    raise ValueError("Organization not found")
                
                stmt = select(Account).where(Account.org_id == UUID(org_id))
                if provider_filter:
                    stmt = stmt.where(Account.provider.in_(provider_filter))
                
                accounts = list(await db.scalars(stmt))
                
                if not accounts:
                    return {'message': 'No accounts found for collection'}
                
                self.update_state(
                    state='PROGRESS',
                    meta={'status': f'Found {len(accounts)} accounts', 'progress': 10}
                )
                
                # Schedule individual account collection tasks
                account_tasks = []
                for i, account in enumerate(accounts):
                    # Prepare provider config based on account
                    provider_config = {
                        'account_id': str(account.account_id)
                    }
                    
                    if account.provider == 'github':
                        provider_config['org_name'] = account.external_id
                    elif account.provider == 'aws':
                        provider_config['aws_account_id'] = account.external_id
                    
                    # Schedule collection task
                    task = collect_account_task.delay(
                        str(account.account_id),
                        org_id,
                        account.provider,
                        provider_config,
                        resource_types
                    )
                    account_tasks.append({
                        'account_id': str(account.account_id),
                        'provider': account.provider,
                        'task_id': task.id
                    })
                    
                    progress = int(10 + (i / len(accounts)) * 90)
                    self.update_state(
                        state='PROGRESS',
                        meta={
                            'status': f'Scheduled collection for {i+1}/{len(accounts)} accounts',
                            'progress': progress
                        }
                    )
                
                logger.info(f"Organization collection task {task_id} scheduled {len(account_tasks)} account tasks")
                
                return {
                    'org_id': org_id,
                    'accounts_scheduled': len(account_tasks),
                    'account_tasks': account_tasks
                }
                
        except Exception as e:
            logger.error(f"Organization collection task {task_id} failed: {e}")
            self.update_state(
                state='FAILURE',
                meta={'error': str(e)}
            )
            raise
    
    return asyncio.run(_collect())


@celery_app.task(bind=True, name='cerebro.tasks.collection_tasks.batch_collect_resources')
def batch_collect_resources(
    self,
    provider_name: str,
    provider_config: Dict[str, Any],
    resource_external_ids: List[str]
):
    """Batch collect configurations for specific resources."""
    
    async def _collect():
        task_id = self.request.id
        logger.info(f"Starting batch resource collection {task_id} for {len(resource_external_ids)} resources")
        
        try:
            self.update_state(
                state='PROGRESS',
                meta={'status': 'Initializing provider', 'progress': 0}
            )
            
            # Create provider
            provider_registry = get_provider_registry()
            provider = provider_registry.create_provider(provider_name, **provider_config)
            
            # Authenticate
            if not await provider.authenticate():
                raise Exception("Provider authentication failed")
            
            collected = 0
            errors = []
            
            async with async_session_factory():
                for i, external_id in enumerate(resource_external_ids):
                    try:
                        # Create resource entity (simplified)
                        from cerebro.domain.entities import ResourceEntity
                        resource = ResourceEntity(
                            external_id=external_id,
                            resource_type="unknown",  # Would need to be passed in
                            provider=provider_name
                        )
                        
                        # Get configuration
                        await provider.get_resource_configuration(resource)
                        
                        # Save configuration (simplified)
                        # In real implementation, would need resource ID mapping
                        collected += 1
                        
                        progress = int((i / len(resource_external_ids)) * 100)
                        self.update_state(
                            state='PROGRESS',
                            meta={
                                'status': f'Collected {collected}/{len(resource_external_ids)}',
                                'progress': progress,
                                'errors': len(errors)
                            }
                        )
                        
                    except Exception as e:
                        logger.warning(f"Failed to collect {external_id}: {e}")
                        errors.append(f"{external_id}: {str(e)}")
            
            logger.info(f"Batch collection {task_id} completed: {collected} collected, {len(errors)} errors")
            
            return {
                'collected': collected,
                'errors': errors,
                'total': len(resource_external_ids)
            }
            
        except Exception as e:
            logger.error(f"Batch collection task {task_id} failed: {e}")
            self.update_state(
                state='FAILURE',
                meta={'error': str(e)}
            )
            raise
    
    return asyncio.run(_collect())
