"""Celery tasks for self-service question analytics and reporting."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import structlog

from cerebro.agents.self_service import SelfServiceAnalytics
from cerebro.tasks.celery_app import celery_app

logger = structlog.get_logger(__name__)
_analytics = SelfServiceAnalytics()


@celery_app.task(name="cerebro.tasks.agent_self_service.generate_monthly_report")
def generate_self_service_question_report() -> int:
    """Generate monthly "Top 10 questions" reports for each organization."""

    as_of = datetime.now(UTC)
    reports = asyncio.run(_analytics.generate_monthly_reports(as_of=as_of))

    logger.info(
        "self_service_monthly_report_generated",
        generated=len(reports),
        timestamp=as_of.isoformat(),
    )

    return len(reports)
