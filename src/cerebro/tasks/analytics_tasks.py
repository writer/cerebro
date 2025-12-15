"""Analytics collection tasks."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, AsyncGenerator, Callable, Dict, List
from uuid import UUID

from celery import states

from cerebro.tasks.celery_app import celery_app
from cerebro.core.database import async_session_factory
from cerebro.core.models import Organization
from cerebro.core.warehouse import resolve_snowflake_database_url
from cerebro.core.warehouse_async import warehouse_async_session
from cerebro.analytics.time_series import (
    AggregationPeriod,
    MetricSnapshot,
    MetricType,
    TimeSeriesCollector,
)
from cerebro.analytics.risk_scoring import RiskScoringEngine, RiskFactor, OrganizationRiskScore
from cerebro.analytics.dashboard_repository import DashboardRepository

logger = logging.getLogger(__name__)


@asynccontextmanager
async def _analytics_read_session(db: Any) -> AsyncGenerator[Any, None]:
    if not resolve_snowflake_database_url():
        yield db
        return

    async with warehouse_async_session() as warehouse:
        yield warehouse


def _serialize_risk_factor(factor: RiskFactor) -> Dict[str, object]:
    return {
        "factor_name": factor.factor_name,
        "category": factor.category,
        "current_value": factor.current_value,
        "baseline_value": factor.baseline_value,
        "weight": factor.weight,
        "risk_contribution": factor.risk_contribution,
        "description": factor.description,
        "remediation_suggestions": factor.remediation_suggestions,
    }


def _serialize_risk_score(score: OrganizationRiskScore) -> Dict[str, object]:
    return {
        "risk_level": score.risk_level.value,
        "score_trend": score.score_trend,
        "trend_confidence": score.trend_confidence,
        "dimension_scores": {
            "vulnerability_exposure": score.vulnerability_score,
            "identity_hygiene": score.identity_score,
            "access_control": score.access_control_score,
            "compliance_posture": score.compliance_score,
            "operational_security": score.operational_score,
        },
        "top_risks": score.top_risks,
        "quick_wins": score.quick_wins,
        "strategic_initiatives": score.strategic_initiatives,
        "risk_factors": [_serialize_risk_factor(f) for f in score.risk_factors],
    }


async def _collect_security_metrics_for_org(org_id: UUID) -> Dict[str, object]:
    async with async_session_factory() as db:
        org = await db.get(Organization, org_id)
        if not org:
            raise ValueError("Organization not found")

        async with _analytics_read_session(db) as analytics_db:
            collector_reader = TimeSeriesCollector(analytics_db)
            snapshots = await collector_reader.collect_finding_metrics(org.org_id)

            risk_engine = RiskScoringEngine(analytics_db)
            risk_score = await risk_engine.calculate_organization_risk_score(org.org_id)

            repository = DashboardRepository(analytics_db)
            compliance_score = await repository.calculate_compliance_score(org.org_id)
            framework_compliance = await repository.get_compliance_by_framework(org.org_id)

        collector_writer = TimeSeriesCollector(db)

        stored_snapshots: List[str] = []
        for snapshot in snapshots:
            db_snapshot = await collector_writer.store_snapshot(
                org.org_id,
                snapshot,
                aggregation_period=AggregationPeriod.DAILY,
            )
            stored_snapshots.append(str(db_snapshot.snapshot_id))

        risk_snapshot = MetricSnapshot(
            timestamp=risk_score.calculation_date,
            metric_type=MetricType.OVERALL_RISK_SCORE.value,
            value=risk_score.overall_score,
            metadata={
                "category": "risk",
                "details": _serialize_risk_score(risk_score),
            },
        )

        db_risk_snapshot = await collector_writer.store_snapshot(
            org.org_id,
            risk_snapshot,
            aggregation_period=AggregationPeriod.DAILY,
        )
        stored_snapshots.append(str(db_risk_snapshot.snapshot_id))

        compliance_snapshot = MetricSnapshot(
            timestamp=datetime.utcnow(),
            metric_type=MetricType.COMPLIANCE_SCORE.value,
            value=compliance_score,
            metadata={
                "category": "compliance",
                "framework_breakdown": framework_compliance,
            },
        )

        db_compliance_snapshot = await collector_writer.store_snapshot(
            org.org_id,
            compliance_snapshot,
            aggregation_period=AggregationPeriod.DAILY,
        )
        stored_snapshots.append(str(db_compliance_snapshot.snapshot_id))

        return {
            "org_id": str(org.org_id),
            "snapshots_created": stored_snapshots,
            "risk_score": risk_snapshot.value,
        }


async def _collect_security_metrics_with_retry(
    org_id: UUID,
    *,
    max_attempts: int = 3,
    retry_backoff: float = 2.0,
    initial_delay: float = 1.0,
    update_state_cb: Callable[[str, Dict[str, object]], None] | None = None,
) -> Dict[str, object]:
    """Collect metrics with retry support for transient failures."""

    attempt = 0
    delay = initial_delay
    while True:
        try:
            return await _collect_security_metrics_for_org(org_id)
        except Exception as exc:
            attempt += 1
            logger.warning(
                "Metric collection attempt %s/%s failed for org %s: %s",
                attempt,
                max_attempts,
                org_id,
                exc,
            )

            if update_state_cb is not None:
                update_state_cb(
                    "RETRY",
                    {
                        "org_id": str(org_id),
                        "attempt": attempt,
                        "max_attempts": max_attempts,
                        "error": str(exc),
                    },
                )

            if attempt >= max_attempts:
                raise

            await asyncio.sleep(delay)
            delay *= retry_backoff


async def _collect_security_metrics_for_all_orgs(
    *,
    max_attempts: int = 3,
    update_state_cb: Callable[[str, Dict[str, object]], None] | None = None,
) -> Dict[str, object]:
    """Collect metrics for every organization with retry and progress callbacks."""

    async with async_session_factory() as db:
        from sqlalchemy import select

        org_ids = list(await db.scalars(select(Organization.org_id)))

    results: List[Dict[str, object]] = []
    total = len(org_ids)

    for index, org_id in enumerate(org_ids, start=1):
        if update_state_cb is not None:
            update_state_cb(
                states.STARTED,
                {
                    "status": f"Collecting metrics {index}/{total}",
                    "org_id": str(org_id),
                },
            )

        try:
            result = await _collect_security_metrics_with_retry(
                org_id,
                max_attempts=max_attempts,
                update_state_cb=update_state_cb,
            )
            results.append(result)
        except Exception as exc:  # pragma: no cover - surfaced via result payload
            logger.exception("Metric collection failed for org %s", org_id)
            error_meta = {"org_id": str(org_id), "error": str(exc)}
            if update_state_cb is not None:
                update_state_cb(states.FAILURE, error_meta)
            results.append(error_meta)

    return {"processed": total, "results": results}


@celery_app.task(
    bind=True,
    name="cerebro.tasks.analytics_tasks.collect_security_metrics_for_org",
)
def collect_security_metrics_for_org(self, org_id: str) -> Dict[str, object]:
    """Collect and persist security analytics for a single organization."""

    async def _run() -> Dict[str, object]:
        try:
            self.update_state(
                state=states.STARTED,
                meta={"status": "Collecting security metrics"},
            )

            result = await _collect_security_metrics_with_retry(
                UUID(org_id),
                update_state_cb=lambda state, meta: self.update_state(
                    state=state,
                    meta={"status": meta.get("status", "Retrying"), **meta},
                ),
            )

            self.update_state(
                state=states.SUCCESS,
                meta={"status": "Completed", **result},
            )
            return result
        except Exception as exc:  # pragma: no cover - surfaced through Celery
            logger.exception("Metric collection failed for org %s", org_id)
            self.update_state(state=states.FAILURE, meta={"error": str(exc)})
            raise

    return asyncio.run(_run())


@celery_app.task(
    bind=True,
    name="cerebro.tasks.analytics_tasks.collect_security_metrics_all_orgs",
)
def collect_security_metrics_all_orgs(self) -> Dict[str, object]:
    """Collect security analytics for every organization."""

    async def _run() -> Dict[str, object]:
        return await _collect_security_metrics_for_all_orgs(
            update_state_cb=lambda state, meta: self.update_state(
                state=state,
                meta=meta,
            )
        )

    return asyncio.run(_run())
