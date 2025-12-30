"""Celery application configuration."""

import os

import structlog
from celery import Celery
from celery.schedules import crontab
from kombu import Queue

try:  # pragma: no cover - protect optional import during bootstrap
    from cerebro.core.config import settings
except Exception:  # pragma: no cover
    settings = None  # type: ignore[assignment]

if settings:
    from cerebro.core.observability import configure_service_observability

    role = os.getenv("CELERY_PROCESS_ROLE", "worker")
    configure_service_observability(service_name=f"cerebro-celery-{role}")

logger = structlog.get_logger(__name__)

# Create Celery app
celery_kwargs = {
    "broker": settings.effective_celery_broker_url if settings else None,
    "backend": settings.effective_celery_result_backend if settings else None,
    "include": [
        "cerebro.tasks.collection_tasks",
        "cerebro.tasks.finding_tasks",
        "cerebro.tasks.maintenance_tasks",
        "cerebro.tasks.notification_digest",
        "cerebro.tasks.self_play_tasks",
        "cerebro.tasks.analytics_tasks",
        "cerebro.tasks.warehouse_tasks",
        "cerebro.tasks.integration_tasks",
        "cerebro.tasks.integration_monitor",
        "cerebro.tasks.runtime_monitor",
        "cerebro.tasks.operational_alerts",
        "cerebro.tasks.serval_tasks",
        "cerebro.tasks.compliance_tasks",
        "cerebro.tasks.agent_self_service_tasks",
    ],
}

celery_app = Celery(
    "cerebro", **{k: v for k, v in celery_kwargs.items() if v is not None}
)

task_routes = {
    "cerebro.tasks.collection_tasks.collect_account_task": {"queue": "collection"},
    "cerebro.tasks.collection_tasks.collect_organization_task": {"queue": "collection"},
    "cerebro.tasks.finding_tasks.generate_findings_task": {"queue": "findings"},
    "cerebro.tasks.maintenance_tasks.*": {"queue": "maintenance"},
    "cerebro.tasks.analytics_tasks.*": {"queue": "analytics"},
    "cerebro.tasks.warehouse_tasks.*": {"queue": "analytics"},
    "cerebro.tasks.runtime_monitor.*": {"queue": "analytics"},
    "cerebro.tasks.agent_self_service.*": {"queue": "analytics"},
    "cerebro.tasks.operational.*": {"queue": "analytics"},
    "cerebro.tasks.integration.*": {"queue": "integrations"},
    "process_email_digests": {"queue": "notifications"},
}

task_queues = [
    Queue("collection", routing_key="collection"),
    Queue("findings", routing_key="findings"),
    Queue("maintenance", routing_key="maintenance"),
    Queue("analytics", routing_key="analytics"),
    Queue("integrations", routing_key="integrations"),
    Queue("notifications", routing_key="notifications"),
    Queue("default", routing_key="default"),
]

beat_schedule = {
    "cleanup-old-snapshots": {
        "task": "cerebro.tasks.maintenance_tasks.cleanup_old_snapshots_task",
        "schedule": 86400.0,  # Daily
        "kwargs": {"days_old": 90},
    },
    "vacuum-analyze-tables": {
        "task": "cerebro.tasks.maintenance_tasks.vacuum_analyze_task",
        "schedule": 3600.0,  # Hourly
    },
    "process-email-digests-daily": {
        "task": "process_email_digests",
        "schedule": crontab(hour=8, minute=0),  # Daily at 8 AM UTC
    },
    "collect-security-metrics-hourly": {
        "task": "cerebro.tasks.analytics_tasks.collect_security_metrics_all_orgs",
        "schedule": 3600.0,
    },
    "refresh-rule-controls-hourly": {
        "task": "cerebro.tasks.warehouse_tasks.refresh_rule_controls",
        "schedule": 3600.0,
        "options": {"queue": "analytics"},
    },
    "warehouse-data-quality-daily": {
        "task": "cerebro.tasks.warehouse_tasks.run_warehouse_data_quality_checks",
        "schedule": crontab(hour=6, minute=0),
        "options": {"queue": "analytics"},
    },
    "sync-sentinelone-activities": {
        "task": "cerebro.tasks.integration.sync_sentinelone",
        "schedule": 600.0,
        "options": {"queue": "integrations"},
    },
    "sync-kandji-inventory": {
        "task": "cerebro.tasks.integration.sync_kandji",
        "schedule": 3600.0,
        "options": {"queue": "integrations"},
    },
    "monitor-integration-sync": {
        "task": "cerebro.tasks.integration.monitor_sync_health",
        "schedule": 900.0,
        "options": {"queue": "integrations"},
    },
    "sync-serval-tickets": {
        "task": "cerebro.tasks.integration.sync_serval_tickets",
        "schedule": 900.0,
        "options": {"queue": "integrations"},
    },
    "monitor-runtime-health": {
        "task": "cerebro.tasks.runtime.monitor_health",
        "schedule": 300.0,
        "options": {"queue": "analytics"},
    },
    "monitor-operational-health": {
        "task": "cerebro.tasks.operational.evaluate_health",
        "schedule": 600.0,
        "options": {"queue": "analytics"},
    },
    "scan-pre-audit-schedules-daily": {
        "task": "cerebro.tasks.compliance.scan_due_pre_audit_schedules",
        "schedule": crontab(hour=5, minute=0),
        "options": {"queue": "analytics"},
    },
    "self-service-question-report-monthly": {
        "task": "cerebro.tasks.agent_self_service.generate_monthly_report",
        "schedule": crontab(hour=7, minute=0, day_of_month="1"),
        "options": {"queue": "analytics"},
    },
}

if settings and getattr(settings, "self_play_enabled", False):
    task_routes["cerebro.tasks.self_play_tasks.run_self_play_batch"] = {
        "queue": "self_play"
    }
    task_queues.append(Queue("self_play", routing_key="self_play"))
    beat_schedule["self-play-hourly"] = {
        "task": "cerebro.tasks.self_play_tasks.run_self_play_batch",
        "schedule": 3600.0,
    }
else:
    logger.info(
        "Self-play orchestration disabled; queue and beat schedule not registered"
    )

# Celery configuration
celery_app.conf.update(
    # Task routing
    task_routes=task_routes,
    # Queue definitions
    task_queues=tuple(task_queues),
    # Task execution settings
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # Worker settings
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    worker_max_tasks_per_child=1000,
    # Task timing
    task_soft_time_limit=300,  # 5 minutes
    task_time_limit=600,  # 10 minutes hard limit
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
celery_app.conf.beat_schedule = beat_schedule

if settings:
    logger.info("Celery app configured")
else:  # pragma: no cover
    logger.warning(
        "Celery app configured with partial settings; verify configuration at runtime"
    )
