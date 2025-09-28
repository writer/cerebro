"""Celery application configuration."""

from celery import Celery
from kombu import Queue
import logging

from cerebro.core.config import settings

logger = logging.getLogger(__name__)

# Create Celery app
celery_app = Celery(
    "cerebro",
    broker=getattr(settings, 'redis_url', 'redis://localhost:6379/0'),
    backend=getattr(settings, 'redis_url', 'redis://localhost:6379/0'),
    include=[
        'cerebro.tasks.collection_tasks',
        'cerebro.tasks.finding_tasks', 
        'cerebro.tasks.maintenance_tasks'
    ]
)

# Celery configuration
celery_app.conf.update(
    # Task routing
    task_routes={
        'cerebro.tasks.collection_tasks.collect_account_task': {'queue': 'collection'},
        'cerebro.tasks.collection_tasks.collect_organization_task': {'queue': 'collection'},
        'cerebro.tasks.finding_tasks.generate_findings_task': {'queue': 'findings'},
        'cerebro.tasks.maintenance_tasks.*': {'queue': 'maintenance'},
    },
    
    # Queue definitions
    task_queues=(
        Queue('collection', routing_key='collection'),
        Queue('findings', routing_key='findings'),
        Queue('maintenance', routing_key='maintenance'),
        Queue('default', routing_key='default'),
    ),
    
    # Task execution settings
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    
    # Worker settings
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    worker_max_tasks_per_child=1000,
    
    # Task timing
    task_soft_time_limit=300,  # 5 minutes
    task_time_limit=600,       # 10 minutes hard limit
    
    # Result backend settings
    result_expires=3600,  # 1 hour
    
    # Monitoring
    worker_send_task_events=True,
    task_send_sent_event=True,
    
    # Error handling
    task_reject_on_worker_lost=True,
    task_ignore_result=False,
)

# Beat schedule (periodic tasks)
celery_app.conf.beat_schedule = {
    'cleanup-old-snapshots': {
        'task': 'cerebro.tasks.maintenance_tasks.cleanup_old_snapshots_task',
        'schedule': 86400.0,  # Daily
        'kwargs': {'days_old': 90}
    },
    'vacuum-analyze-tables': {
        'task': 'cerebro.tasks.maintenance_tasks.vacuum_analyze_task', 
        'schedule': 3600.0,  # Hourly
    },
}

logger.info("Celery app configured")
