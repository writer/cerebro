"""Operational health aggregation helpers."""

from __future__ import annotations

import asyncio
from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.agents.models import (
    AgentMessage,
    AgentSession,
    ToolInvocation,
    ToolInvocationStatus,
)
from cerebro.analytics.runtime_health import summarize_runtime_health
from cerebro.automation.telemetry_health import fetch_telemetry_health
from cerebro.core.config import settings
from cerebro.core.database import engine as core_engine
from cerebro.integrations.freshness import IntegrationFreshnessService
from cerebro.integrations.state import IntegrationIssueEventRepository
from cerebro.metrics import api_metrics


def _coerce_float_list(value: Any) -> list[float]:
    samples: list[float] = []
    if isinstance(value, list):
        for item in value:
            try:
                samples.append(float(item))
            except (TypeError, ValueError):
                continue
    return samples[-10:]


def _derive_confidence(status: str) -> str:
    normalized = status.lower()
    if normalized == "fresh":
        return "high"
    if normalized == "stale":
        return "medium"
    if normalized in {"error", "disabled"}:
        return "low"
    return "unknown"


def _build_schedule_index(schedule_conf: dict[str, Any]) -> dict[str, Any]:
    return {
        str(details.get("task")): details.get("schedule")
        for details in schedule_conf.values()
        if isinstance(details, dict) and details.get("task")
    }


def _resolve_task_for_integration(
    integration: str, tasks: Iterable[str]
) -> str | None:
    integration_key = integration.split(".")[0].lower()
    for task in tasks:
        if not isinstance(task, str):
            continue
        if integration_key in task.lower():
            return task
    explicit_map = {
        "sentinelone.activities": "cerebro.tasks.integration.sync_sentinelone",
        "kandji.vulnerabilities": "cerebro.tasks.integration.sync_kandji",
    }
    return explicit_map.get(integration)


def _compute_next_scheduled(
    integration: str,
    schedule_index: dict[str, Any],
) -> datetime | None:
    task_name = _resolve_task_for_integration(integration, schedule_index.keys())
    if not task_name:
        return None
    schedule_obj = schedule_index.get(task_name)
    if schedule_obj is None:
        return None

    now = datetime.now(UTC)
    delta: timedelta | None = None
    if isinstance(schedule_obj, (int, float)):
        delta = timedelta(seconds=float(schedule_obj))
    elif isinstance(schedule_obj, timedelta):
        delta = schedule_obj
    elif hasattr(schedule_obj, "remaining_estimate"):
        try:
            remaining = schedule_obj.remaining_estimate(datetime.utcnow())
            if isinstance(remaining, timedelta):
                delta = remaining
        except (
            Exception
        ):  # pragma: no cover - Celery schedule introspection best effort
            delta = None
    elif hasattr(schedule_obj, "run_every") and isinstance(
        schedule_obj.run_every, timedelta
    ):
        delta = schedule_obj.run_every

    if delta is None:
        return None
    return now + delta


def _get_integration_stale_threshold(integration: str) -> int:
    overrides = getattr(settings, "operational_integration_stale_overrides", {}) or {}
    normalized = integration.lower()
    for key, value in overrides.items():
        if not isinstance(key, str):
            continue
        try:
            hours = int(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
        if key.lower() in normalized:
            return max(1, hours)
    return max(1, settings.operational_integration_stale_hours)


async def gather_celery_status() -> dict[str, Any]:
    """Return Celery worker and queue status summary."""

    from cerebro.tasks.celery_app import celery_app  # Imported lazily to avoid cycles

    def _inspect() -> dict[str, Any]:
        try:
            inspect = celery_app.control.inspect()
            active = inspect.active() or {}
            reserved = inspect.reserved() or {}
            stats = inspect.stats() or {}
            registered = inspect.registered() or {}

            workers: list[dict[str, Any]] = []
            total_active = 0
            total_reserved = 0

            for worker_name, worker_stats in stats.items():
                active_count = len(active.get(worker_name, []))
                reserved_count = len(reserved.get(worker_name, []))
                total_active += active_count
                total_reserved += reserved_count

                host = (
                    worker_name.split("@", 1)[1] if "@" in worker_name else worker_name
                )
                short_name = worker_name.split("@", 1)[0]
                health_status = "healthy" if "rusage" in worker_stats else "degraded"

                failed_tasks = 0
                task_stats = worker_stats.get("tasks")
                if isinstance(task_stats, dict):
                    for metrics in task_stats.values():
                        if isinstance(metrics, dict):
                            failure_count = metrics.get("failures") or metrics.get(
                                "failed"
                            )
                            try:
                                failed_tasks += int(failure_count or 0)
                            except (TypeError, ValueError):
                                continue

                workers.append(
                    {
                        "name": short_name,
                        "host": host,
                        "status": health_status,
                        "active_tasks": active_count,
                        "reserved_tasks": reserved_count,
                        "total_completed": worker_stats.get("total", 0),
                        "registered_tasks": len(registered.get(worker_name, [])),
                        "failed_tasks": failed_tasks,
                    }
                )

            return {
                "workers": workers,
                "summary": {
                    "total_workers": len(workers),
                    "healthy_workers": sum(
                        1 for worker in workers if worker["status"] == "healthy"
                    ),
                    "total_active_tasks": total_active,
                    "total_reserved_tasks": total_reserved,
                    "total_queue_depth": total_active + total_reserved,
                    "failed_tasks": sum(
                        worker.get("failed_tasks", 0) for worker in workers
                    ),
                },
            }
        except Exception as exc:  # pragma: no cover - defensive guard
            return {
                "workers": [],
                "summary": {
                    "total_workers": 0,
                    "healthy_workers": 0,
                    "total_active_tasks": 0,
                    "total_reserved_tasks": 0,
                    "total_queue_depth": 0,
                },
                "error": str(exc),
            }

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _inspect)


async def _collect_integration_health(db: AsyncSession) -> dict[str, Any]:
    freshness_service = IntegrationFreshnessService(db)
    freshness_items = await freshness_service.list_freshness()

    repo = IntegrationIssueEventRepository(db)
    since = datetime.now(UTC) - timedelta(hours=24)
    recent_events = await repo.list_events(since=since)

    event_counts: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    for event in recent_events:
        key = (event.integration, event.scope)
        event_counts[key][event.severity] += 1

    from cerebro.tasks.celery_app import celery_app

    schedule_conf = getattr(celery_app.conf, "beat_schedule", {}) or {}
    schedule_index = _build_schedule_index(schedule_conf)

    items: list[dict[str, Any]] = []
    stale_count = 0
    error_count = 0

    for entry in freshness_items:
        if entry.status == "stale":
            stale_count += 1
        if entry.status == "error":
            error_count += 1

        events = event_counts.get((entry.integration, entry.scope), Counter())
        metadata = dict(entry.metadata or {})
        duration_samples = _coerce_float_list(metadata.get("duration_samples", []))
        duration_average = (
            sum(duration_samples) / len(duration_samples)
            if duration_samples
            else metadata.get("last_duration_seconds")
        )
        recent_errors = metadata.get("recent_errors", [])
        if isinstance(recent_errors, list):
            filtered_errors = [err for err in recent_errors if isinstance(err, dict)]
        else:
            filtered_errors = []

        next_sync = _compute_next_scheduled(entry.integration, schedule_index)
        threshold_hours = _get_integration_stale_threshold(entry.integration)
        error_count = sum(
            count
            for severity, count in events.items()
            if str(severity).lower() in {"error", "critical"}
        )

        items.append(
            {
                "integration": entry.integration,
                "scope": entry.scope,
                "status": entry.status,
                "last_synced_at": (
                    entry.last_synced_at.isoformat() if entry.last_synced_at else None
                ),
                "age_seconds": entry.age_seconds,
                "age_human": entry.age_human,
                "warning": entry.warning,
                "metadata": metadata,
                "issues_last_24h": dict(events),
                "next_scheduled_at": next_sync.isoformat() if next_sync else None,
                "duration_average_seconds": duration_average,
                "duration_samples": duration_samples,
                "recent_errors": filtered_errors,
                "status_confidence": _derive_confidence(entry.status),
                "confidence_level": entry.confidence,
                "error_count_24h": error_count,
                "stale_threshold_hours": threshold_hours,
            }
        )

    return {
        "items": items,
        "summary": {
            "total": len(items),
            "stale": stale_count,
            "error": error_count,
        },
    }


async def _collect_database_health(db: AsyncSession) -> dict[str, Any]:
    pool_stats: dict[str, Any] = {}
    try:
        pool = core_engine.sync_engine.pool
        pool_stats = {
            "size": getattr(pool, "size", lambda: None)(),
            "checked_in": getattr(pool, "checkedin", lambda: None)(),
            "checked_out": getattr(pool, "checkedout", lambda: None)(),
            "overflow": getattr(pool, "overflow", lambda: None)(),
        }
        if pool_stats["size"]:
            checked_out = pool_stats.get("checked_out") or 0
            size = pool_stats.get("size") or 1
            pool_stats["utilization"] = checked_out / size
    except Exception:  # pragma: no cover - pool attributes vary by backend
        pool_stats = {}

    slow_queries: list[dict[str, Any]] = []
    table_sizes: list[dict[str, Any]] = []

    try:
        result = await db.execute(
            text(
                """
                SELECT pid, now() - query_start AS duration, query
                FROM pg_stat_activity
                WHERE state != 'idle'
                ORDER BY duration DESC
                LIMIT 5
                """
            )
        )
        for row in result:
            duration = row.duration
            duration_seconds = (
                duration.total_seconds() if hasattr(duration, "total_seconds") else None
            )
            slow_queries.append(
                {
                    "pid": row.pid,
                    "duration_seconds": duration_seconds,
                    "query": row.query,
                }
            )
    except Exception:
        slow_queries = []

    try:
        size_query = text(
            """
            SELECT relname, pg_total_relation_size(relid) AS size_bytes
            FROM pg_catalog.pg_statio_user_tables
            ORDER BY pg_total_relation_size(relid) DESC
            LIMIT 5
            """
        )
        result = await db.execute(size_query)
        for row in result:
            table_sizes.append(
                {
                    "table": row.relname,
                    "size_bytes": row.size_bytes,
                }
            )
    except Exception:
        table_sizes = []

    return {
        "pool": pool_stats,
        "slow_queries": slow_queries,
        "table_sizes": table_sizes,
    }


async def _collect_agent_health(db: AsyncSession) -> dict[str, Any]:
    now = datetime.now(UTC)
    hour_ago = now - timedelta(hours=1)
    day_ago = now - timedelta(hours=24)

    active_sessions_stmt = (
        select(func.count())
        .select_from(AgentSession)
        .where(AgentSession.is_active.is_(True))
    )
    active_sessions = (await db.execute(active_sessions_stmt)).scalar_one()

    messages_stmt = (
        select(func.count())
        .select_from(AgentMessage)
        .where(AgentMessage.created_at >= hour_ago)
    )
    messages_last_hour = (await db.execute(messages_stmt)).scalar_one()

    total_invocations_stmt = (
        select(func.count())
        .select_from(ToolInvocation)
        .where(ToolInvocation.started_at >= day_ago)
    )
    total_invocations = (await db.execute(total_invocations_stmt)).scalar_one()

    error_invocations_stmt = (
        select(func.count())
        .select_from(ToolInvocation)
        .where(
            ToolInvocation.started_at >= day_ago,
            ToolInvocation.status == ToolInvocationStatus.ERROR,
        )
    )
    error_invocations = (await db.execute(error_invocations_stmt)).scalar_one()

    error_rate = (error_invocations / total_invocations) if total_invocations else 0.0

    runtime_summaries = await summarize_runtime_health(db, hours=24)

    return {
        "active_sessions": active_sessions,
        "messages_per_hour": messages_last_hour,
        "tool_invocations_last_24h": total_invocations,
        "tool_error_rate": round(error_rate, 4),
        "runtime_health": runtime_summaries,
    }


async def _collect_usage_metrics(db: AsyncSession) -> dict[str, Any]:
    snapshot = await fetch_telemetry_health(window_days=7, db_session=db)
    usage = snapshot.to_dict()

    events_by_component = usage.get("events_by_component", {})
    events_by_type = usage.get("events_by_type", {})
    top_features = sorted(
        (
            {
                "component": component,
                "events": count,
            }
            for component, count in events_by_component.items()
            if component and component != "(none)"
        ),
        key=lambda item: item["events"],
        reverse=True,
    )[:5]

    unused_candidates = [
        component
        for component, count in events_by_component.items()
        if (component and component != "(none)" and count <= 3)
    ]

    def _sum_matching(source: dict[str, int], keywords: Iterable[str]) -> int:
        total = 0
        for key, value in source.items():
            try:
                normalized = key.lower()
            except AttributeError:
                continue
            if any(keyword in normalized for keyword in keywords):
                try:
                    total += int(value)
                except (TypeError, ValueError):
                    continue
        return total

    feature_breakdown = {
        "queries": _sum_matching(events_by_component, ["query", "sql"])
        + _sum_matching(events_by_type, ["query"]),
        "agent_sessions": _sum_matching(events_by_component, ["agent", "session"])
        + _sum_matching(events_by_type, ["agent_session", "agent.run"]),
        "findings_viewed": _sum_matching(
            events_by_component, ["finding", "review", "evidence"]
        )
        + _sum_matching(events_by_type, ["finding", "evidence"]),
    }

    usage_summary = {
        "snapshot": usage,
        "weekly_active_users": usage.get("unique_users", 0),
        "top_features": top_features,
        "unused_features": unused_candidates,
        "feature_breakdown": feature_breakdown,
    }

    return usage_summary


async def collect_operational_health(db: AsyncSession) -> dict[str, Any]:
    """Assemble a comprehensive operational health snapshot."""

    integrations = await _collect_integration_health(db)
    celery_status = await gather_celery_status()
    database = await _collect_database_health(db)
    agents = await _collect_agent_health(db)
    usage = await _collect_usage_metrics(db)

    api_snapshot = api_metrics.snapshot()

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "integrations": integrations,
        "jobs": celery_status,
        "database": database,
        "api": api_snapshot,
        "agents": agents,
        "usage": usage,
    }


async def collect_operational_alert_inputs(db: AsyncSession) -> dict[str, Any]:
    """Return the subset of health metrics required for alert evaluation."""

    integrations = await _collect_integration_health(db)
    celery_status = await gather_celery_status()
    database = await _collect_database_health(db)
    usage = await _collect_usage_metrics(db)

    return {
        "integrations": integrations,
        "jobs": celery_status,
        "database": database,
        "usage": usage,
    }
