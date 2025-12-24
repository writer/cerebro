"""Background task processing with Celery."""

from .agent_self_service_tasks import generate_self_service_question_report
from .analytics_tasks import (
    collect_security_metrics_all_orgs,
    collect_security_metrics_for_org,
)
from .celery_app import celery_app
from .collection_tasks import collect_account_task, collect_organization_task
from .finding_tasks import generate_findings_task
from .integration_monitor import monitor_sync_health
from .integration_tasks import sync_kandji, sync_sentinelone
from .maintenance_tasks import cleanup_old_snapshots_task
from .self_play_tasks import run_self_play_batch

__all__ = [
    "celery_app",
    "cleanup_old_snapshots_task",
    "collect_account_task",
    "collect_organization_task",
    "collect_security_metrics_all_orgs",
    "collect_security_metrics_for_org",
    "generate_findings_task",
    "generate_self_service_question_report",
    "monitor_sync_health",
    "run_self_play_batch",
    "sync_kandji",
    "sync_sentinelone",
]
