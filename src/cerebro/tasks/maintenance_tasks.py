"""Maintenance background tasks."""

from typing import List, Optional
import logging
import asyncio
from datetime import datetime, timedelta

from cerebro.tasks.celery_app import celery_app
from cerebro.core.database import async_session_factory
from cerebro.core.bulk_operations import BulkOperations

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name='cerebro.tasks.maintenance_tasks.cleanup_old_snapshots_task')
def cleanup_old_snapshots_task(self, days_old: int = 90):
    """Clean up configuration snapshots older than specified days."""
    
    async def _cleanup():
        task_id = self.request.id
        logger.info(f"Starting cleanup task {task_id} for snapshots older than {days_old} days")
        
        try:
            self.update_state(
                state='PROGRESS',
                meta={'status': 'Finding old snapshots', 'progress': 0}
            )
            
            async with async_session_factory() as db:
                from sqlalchemy import select, delete, text
                from cerebro.core.models import ConfigSnapshot
                
                # Calculate cutoff date
                cutoff_date = datetime.utcnow() - timedelta(days=days_old)
                
                # Count old snapshots
                count_stmt = select(ConfigSnapshot).where(
                    ConfigSnapshot.captured_at < cutoff_date
                )
                old_snapshots = await db.scalars(count_stmt)
                total_old = len(list(old_snapshots))
                
                if total_old == 0:
                    return {'message': 'No old snapshots to clean up'}
                
                self.update_state(
                    state='PROGRESS',
                    meta={'status': f'Found {total_old} old snapshots to delete', 'progress': 20}
                )
                
                # Delete in batches to avoid long-running transactions
                batch_size = 1000
                deleted = 0
                
                while True:
                    # Delete a batch
                    delete_stmt = delete(ConfigSnapshot).where(
                        ConfigSnapshot.captured_at < cutoff_date
                    ).limit(batch_size)
                    
                    result = await db.execute(delete_stmt)
                    batch_deleted = result.rowcount
                    
                    if batch_deleted == 0:
                        break
                    
                    deleted += batch_deleted
                    await db.commit()
                    
                    progress = min(int(20 + (deleted / total_old) * 70), 90)
                    self.update_state(
                        state='PROGRESS',
                        meta={
                            'status': f'Deleted {deleted}/{total_old} old snapshots',
                            'progress': progress
                        }
                    )
                
                # Vacuum analyze the table
                self.update_state(
                    state='PROGRESS',
                    meta={'status': 'Optimizing database', 'progress': 95}
                )
                
                # Note: VACUUM cannot run inside a transaction
                await db.commit()
                await db.close()
                
                # Create new connection for VACUUM
                async with async_session_factory() as vacuum_db:
                    await vacuum_db.execute(text("VACUUM ANALYZE config_snapshots"))
                    await vacuum_db.commit()
                
                logger.info(f"Cleanup task {task_id} completed: deleted {deleted} old snapshots")
                
                return {
                    'deleted': deleted,
                    'days_old': days_old,
                    'cutoff_date': cutoff_date.isoformat()
                }
                
        except Exception as e:
            logger.error(f"Cleanup task {task_id} failed: {e}")
            self.update_state(
                state='FAILURE',
                meta={'error': str(e)}
            )
            raise
    
    return asyncio.run(_cleanup())


@celery_app.task(bind=True, name='cerebro.tasks.maintenance_tasks.vacuum_analyze_task')
def vacuum_analyze_task(self, tables: Optional[List[str]] = None):
    """Run VACUUM ANALYZE on specified tables or all main tables."""
    
    async def _vacuum():
        task_id = self.request.id
        
        # Default tables to vacuum
        default_tables = [
            'config_snapshots',
            'iam_edges', 
            'findings',
            'resources',
            'principals'
        ]
        
        tables_to_vacuum = tables or default_tables
        
        logger.info(f"Starting vacuum task {task_id} for tables: {tables_to_vacuum}")
        
        try:
            self.update_state(
                state='PROGRESS',
                meta={'status': 'Starting vacuum analyze', 'progress': 0}
            )
            
            async with async_session_factory() as db:
                bulk_ops = BulkOperations(db)
                
                for i, table in enumerate(tables_to_vacuum):
                    try:
                        self.update_state(
                            state='PROGRESS',
                            meta={
                                'status': f'Vacuuming table {table}',
                                'progress': int((i / len(tables_to_vacuum)) * 100)
                            }
                        )
                        
                        await bulk_ops.vacuum_analyze_table(table)
                        
                    except Exception as e:
                        logger.warning(f"Failed to vacuum table {table}: {e}")
                
                logger.info(f"Vacuum task {task_id} completed for {len(tables_to_vacuum)} tables")
                
                return {
                    'tables_vacuumed': tables_to_vacuum,
                    'completed': True
                }
                
        except Exception as e:
            logger.error(f"Vacuum task {task_id} failed: {e}")
            self.update_state(
                state='FAILURE',
                meta={'error': str(e)}
            )
            raise
    
    return asyncio.run(_vacuum())


@celery_app.task(bind=True, name='cerebro.tasks.maintenance_tasks.update_identity_clusters_task')
def update_identity_clusters_task(self, org_id: str):
    """Update identity clusters for an organization."""
    
    async def _update():
        task_id = self.request.id
        logger.info(f"Starting identity cluster update task {task_id} for org {org_id}")
        
        try:
            from uuid import UUID
            from cerebro.core.models import Organization
            
            self.update_state(
                state='PROGRESS',
                meta={'status': 'Loading principals', 'progress': 0}
            )
            
            async with async_session_factory() as db:
                # Get organization
                org = await db.get(Organization, UUID(org_id))
                if not org:
                    raise ValueError("Organization not found")
                
                # Initialize identity stitcher adapter
                from cerebro.infrastructure.adapters import IdentityStitcherAdapter
                identity_stitcher = IdentityStitcherAdapter(db)
                
                self.update_state(
                    state='PROGRESS',
                    meta={'status': 'Finding identity clusters', 'progress': 20}
                )
                
                # Find identity clusters  
                # Note: The adapter will get principals from the DB using the org_id
                clusters = await identity_stitcher.find_identity_clusters(UUID(org_id), [])
                
                self.update_state(
                    state='PROGRESS',
                    meta={'status': f'Found {len(clusters)} identity clusters', 'progress': 80}
                )
                
                # TODO: Save clusters to database
                # For now, just log the results
                
                high_confidence_clusters = [c for c in clusters if c.confidence_score > 0.8]
                
                logger.info(f"Identity cluster task {task_id} completed: "
                           f"{len(clusters)} total clusters, "
                           f"{len(high_confidence_clusters)} high confidence")
                
                return {
                    'org_id': org_id,
                    'total_clusters': len(clusters),
                    'high_confidence_clusters': len(high_confidence_clusters),
                    'clusters': [
                        {
                            'cluster_id': cluster.cluster_id,
                            'confidence_score': cluster.confidence_score,
                            'principal_count': len(cluster.principals),
                            'evidence': cluster.stitching_evidence
                        }
                        for cluster in clusters
                    ]
                }
                
        except Exception as e:
            logger.error(f"Identity cluster task {task_id} failed: {e}")
            self.update_state(
                state='FAILURE',
                meta={'error': str(e)}
            )
            raise
    
    return asyncio.run(_update())


@celery_app.task(bind=True, name='cerebro.tasks.maintenance_tasks.health_check_task')
def health_check_task(self):
    """Health check task to verify system components."""
    
    async def _health_check():
        task_id = self.request.id
        logger.info(f"Starting health check task {task_id}")
        
        try:
            health_status = {}
            
            # Database check
            self.update_state(
                state='PROGRESS',
                meta={'status': 'Checking database', 'progress': 0}
            )
            
            try:
                async with async_session_factory() as db:
                    from sqlalchemy import text
                    await db.execute(text("SELECT 1"))
                    health_status['database'] = {'status': 'healthy', 'latency_ms': None}
            except Exception as e:
                health_status['database'] = {'status': 'unhealthy', 'error': str(e)}
            
            # Redis check
            self.update_state(
                state='PROGRESS',
                meta={'status': 'Checking Redis', 'progress': 33}
            )
            
            try:
                import redis
                from cerebro.core.config import settings
                redis_url = getattr(settings, 'redis_url', 'redis://localhost:6379/0')
                r = redis.from_url(redis_url)
                r.ping()
                health_status['redis'] = {'status': 'healthy'}
            except Exception as e:
                health_status['redis'] = {'status': 'unhealthy', 'error': str(e)}
            
            # Provider availability check
            self.update_state(
                state='PROGRESS',
                meta={'status': 'Checking providers', 'progress': 66}
            )
            
            try:
                from cerebro.infrastructure.provider_registry import get_provider_registry
                registry = get_provider_registry()
                providers = registry.list_providers()
                health_status['providers'] = {
                    'status': 'healthy',
                    'available_providers': providers,
                    'count': len(providers)
                }
            except Exception as e:
                health_status['providers'] = {'status': 'unhealthy', 'error': str(e)}
            
            # Overall health
            all_healthy = all(
                component['status'] == 'healthy' 
                for component in health_status.values()
            )
            
            health_status['overall'] = {
                'status': 'healthy' if all_healthy else 'degraded',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            logger.info(f"Health check task {task_id} completed: {'healthy' if all_healthy else 'degraded'}")
            
            return health_status
            
        except Exception as e:
            logger.error(f"Health check task {task_id} failed: {e}")
            self.update_state(
                state='FAILURE',
                meta={'error': str(e)}
            )
            raise
    
    return asyncio.run(_health_check())
