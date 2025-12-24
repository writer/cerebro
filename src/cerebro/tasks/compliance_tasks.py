"""Celery tasks coordinating compliance pre-audit health checks."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import UUID

import structlog

from cerebro.compliance.pre_audit_service import PreAuditHealthCheckService
from cerebro.tasks.celery_app import celery_app

logger = structlog.get_logger(__name__)
_service = PreAuditHealthCheckService()


@celery_app.task(name="cerebro.tasks.compliance.scan_due_pre_audit_schedules")
def scan_due_pre_audit_schedules() -> list[str]:
    """Identify schedules that require a pre-audit run and enqueue execution tasks."""

    now = datetime.now(UTC)
    schedules = asyncio.run(_service.due_schedules(as_of=now))

    for schedule in schedules:
        logger.info(
            "queueing_pre_audit_run",
            schedule_id=str(schedule.id),
            org_id=str(schedule.org_id),
        )
        run_pre_audit_health_check.delay(str(schedule.id))

    return [str(schedule.id) for schedule in schedules]


@celery_app.task(name="cerebro.tasks.compliance.run_pre_audit_health_check")
def run_pre_audit_health_check(schedule_id: str) -> str:
    """Execute the health check for a specific schedule."""

    logger.info("starting_pre_audit_run", schedule_id=schedule_id)
    asyncio.run(_service.run_for_schedule(UUID(schedule_id)))
    logger.info("completed_pre_audit_run", schedule_id=schedule_id)
    return schedule_id
