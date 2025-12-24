"""Monitoring and operational health API endpoints."""

from typing import Any, Dict
from uuid import UUID
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from cerebro.api.auth import get_current_user, require_scopes, User
from cerebro.api.org_access import require_org_access
from cerebro.analytics.sql_dialect import (
    days_since_expr,
    get_dialect_name,
    timestamp_minus_days_expr,
)
from cerebro.analytics.operations import (
    gather_celery_status,
    collect_operational_health,
)
from cerebro.analytics.runtime_health import summarize_runtime_health
from cerebro.core.analytics_db import get_analytics_db
from cerebro.core.config import settings
from cerebro.core.database import get_db
from cerebro.core.models import Organization
from cerebro.core.warehouse import resolve_snowflake_database_url
from cerebro.core.warehouse_async import warehouse_async_session

router = APIRouter(dependencies=[Depends(get_current_user)])


@router.get("/organizations/{org_id}/sla-breaches")
async def get_sla_breach_analysis(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    analytics_db: Any = Depends(get_analytics_db),
    current_user: User = Depends(require_org_access(require_scopes("read:findings"))),
) -> Dict[str, Any]:
    """Get detailed SLA breach analysis with ownership."""

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    dialect = get_dialect_name(analytics_db)
    days_old_expr = days_since_expr(column_expr="f.first_seen", dialect=dialect)
    critical_cutoff = timestamp_minus_days_expr(days=7, dialect=dialect)
    high_cutoff = timestamp_minus_days_expr(days=14, dialect=dialect)
    medium_cutoff = timestamp_minus_days_expr(days=30, dialect=dialect)
    low_cutoff = timestamp_minus_days_expr(days=90, dialect=dialect)

    # Get SLA breaches by severity with details and ownership
    sla_breach_query = text(
        f"""
        SELECT
            f.finding_id,
            f.title,
            f.severity,
            f.status,
            f.first_seen,
            r.name as rule_name,
            r.owner,
            r.backup_owner,
            a.provider,
            {days_old_expr} as days_old,
            CASE f.severity
                WHEN 'critical' THEN 7
                WHEN 'high' THEN 14
                WHEN 'medium' THEN 30
                WHEN 'low' THEN 90
                ELSE 30
            END as sla_days
        FROM findings f
        JOIN rules r ON f.rule_id = r.rule_id
        JOIN accounts a ON f.account_id = a.account_id
        WHERE a.org_id = :org_id
            AND f.status = 'open'
            AND (
                (f.severity = 'critical' AND f.first_seen <= {critical_cutoff}) OR
                (f.severity = 'high' AND f.first_seen <= {high_cutoff}) OR
                (f.severity = 'medium' AND f.first_seen <= {medium_cutoff}) OR
                (f.severity = 'low' AND f.first_seen <= {low_cutoff})
            )
        ORDER BY
            CASE f.severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
            END,
            f.first_seen
    """
    )

    result = await analytics_db.execute(sla_breach_query, {"org_id": org_id})
    breaches = result.fetchall()

    # Organize by severity
    breaches_by_severity: dict[str, list[dict[str, Any]]] = {"critical": [], "high": [], "medium": [], "low": []}

    for breach in breaches:
        breach_data = {
            "finding_id": str(breach.finding_id),
            "title": breach.title,
            "rule_name": breach.rule_name,
            "provider": breach.provider,
            "days_old": int(breach.days_old),
            "sla_days": breach.sla_days,
            "days_overdue": int(breach.days_old) - breach.sla_days,
            "first_seen": breach.first_seen.isoformat(),
            "owner": breach.owner,
            "backup_owner": breach.backup_owner,
        }
        breaches_by_severity[breach.severity].append(breach_data)

    # Calculate summary statistics
    total_breaches = len(breaches)
    critical_breaches = len(breaches_by_severity["critical"])
    high_breaches = len(breaches_by_severity["high"])

    return {
        "summary": {
            "total_sla_breaches": total_breaches,
            "critical_breaches": critical_breaches,
            "high_breaches": high_breaches,
            "average_days_overdue": (
                round(
                    sum(int(b.days_old) - b.sla_days for b in breaches) / len(breaches),
                    1,
                )
                if breaches
                else 0
            ),
        },
        "breaches_by_severity": breaches_by_severity,
        "urgent_actions": [
            (
                f"{critical_breaches} critical findings > 7 days old"
                if critical_breaches > 0
                else None
            ),
            (
                f"{high_breaches} high findings > 14 days old"
                if high_breaches > 0
                else None
            ),
        ],
    }


@router.get("/heartbeat")
async def get_heartbeat_chips(
    current_user: User = Depends(require_scopes("read:findings")),
) -> Dict[str, Any]:
    """Get Celery heartbeat status chips for dashboard monitoring."""

    celery_status = await gather_celery_status()

    # Generate heartbeat chips
    now = datetime.now(timezone.utc)
    summary = celery_status["summary"]

    # Overall system status
    if summary["healthy_workers"] == 0:
        system_status = "critical"
        status_color = "#dc2626"
        status_message = "No workers available"
    elif summary["healthy_workers"] < summary["total_workers"]:
        system_status = "warning"
        status_color = "#ea580c"
        status_message = (
            f"{summary['healthy_workers']}/{summary['total_workers']} workers healthy"
        )
    else:
        system_status = "healthy"
        status_color = "#22c55e"
        status_message = f"All {summary['total_workers']} workers healthy"

    # Queue depth assessment
    queue_depth = summary["total_queue_depth"]
    if queue_depth > 100:
        queue_status = "high"
        queue_color = "#dc2626"
    elif queue_depth > 20:
        queue_status = "medium"
        queue_color = "#ea580c"
    else:
        queue_status = "low"
        queue_color = "#22c55e"

    heartbeat_chips = [
        {
            "type": "workers",
            "label": "Workers",
            "value": f"{summary['healthy_workers']}/{summary['total_workers']}",
            "status": system_status,
            "color": status_color,
            "message": status_message,
            "click_through_url": "/admin/workers",
            "last_updated": now.isoformat(),
        },
        {
            "type": "queue_depth",
            "label": "Queue Depth",
            "value": str(queue_depth),
            "status": queue_status,
            "color": queue_color,
            "message": f"{queue_depth} tasks pending",
            "click_through_url": "/admin/tasks",
            "last_updated": now.isoformat(),
        },
        {
            "type": "active_tasks",
            "label": "Active",
            "value": str(summary["total_active_tasks"]),
            "status": "info",
            "color": "#3b82f6",
            "message": f"{summary['total_active_tasks']} running tasks",
            "click_through_url": "/admin/tasks?status=active",
            "last_updated": now.isoformat(),
        },
    ]

    return {
        "heartbeat_chips": heartbeat_chips,
        "system_health": {
            "overall_status": system_status,
            "last_check": now.isoformat(),
            "workers_online": summary["healthy_workers"],
            "total_workers": summary["total_workers"],
            "queue_backlog": queue_depth > 20,
        },
        "worker_details": celery_status["workers"],
        "error": celery_status.get("error"),
    }


@router.get("/warehouse/health")
async def get_warehouse_health(
    current_user: User = Depends(require_scopes("read:findings")),
) -> Dict[str, Any]:
    """Get Snowflake warehouse operational health (jobs + derived table freshness)."""

    if not resolve_snowflake_database_url():
        env = (settings.environment or "development").lower()
        if env not in {"dev", "development", "test", "testing"}:
            raise HTTPException(
                status_code=503, detail="SNOWFLAKE_DATABASE_URL is not configured"
            )
        return {"configured": False, "error": "SNOWFLAKE_DATABASE_URL not configured"}

    try:
        async with warehouse_async_session() as warehouse:
            table_names = [
                "orgs",
                "accounts",
                "findings",
                "iam_edges",
                "rules",
                "rule_controls",
                "warehouse_job_runs",
                "security_metric_snapshots",
                "agent_runtime_events",
            ]

            job_status_query = text(
                """
                SELECT
                    job_name,
                    component,
                    status,
                    started_at,
                    finished_at,
                    row_count,
                    details
                FROM warehouse_job_runs
                WHERE job_name = :job_name
                ORDER BY started_at DESC
                LIMIT 1
                """
            )

            job_names = ["refresh_rule_controls", "warehouse_data_quality_checks"]
            jobs: Dict[str, Any] = {}
            for job_name in job_names:
                row = (
                    (await warehouse.execute(job_status_query, {"job_name": job_name}))
                    .mappings()
                    .first()
                )
                if row:
                    jobs[job_name] = {
                        "status": row.get("status"),
                        "component": row.get("component"),
                        "started_at": (
                            row.get("started_at").isoformat()  # type: ignore[union-attr]
                            if row.get("started_at")
                            else None
                        ),
                        "finished_at": (
                            row.get("finished_at").isoformat()  # type: ignore[union-attr]
                            if row.get("finished_at")
                            else None
                        ),
                        "row_count": row.get("row_count"),
                        "details": row.get("details"),
                    }
                else:
                    jobs[job_name] = None

            rule_controls_row = (
                (
                    await warehouse.execute(
                        text(
                            """
                        SELECT MAX(created_at) AS last_refreshed_at, COUNT(*) AS row_count
                        FROM rule_controls
                        """
                        )
                    )
                )
                .mappings()
                .first()
            )

            rule_controls = {
                "last_refreshed_at": (
                    rule_controls_row.get("last_refreshed_at").isoformat()  # type: ignore[union-attr]
                    if rule_controls_row and rule_controls_row.get("last_refreshed_at")
                    else None
                ),
                "row_count": (
                    int(rule_controls_row.get("row_count") or 0)
                    if rule_controls_row
                    else 0
                ),
            }

            # Use INFORMATION_SCHEMA to avoid expensive COUNT(*) on large tables.
            quoted_tables = ", ".join(f"'{name.upper()}'" for name in table_names)
            table_stats_rows = (
                (
                    await warehouse.execute(
                        text(
                            f"""
                        SELECT table_name, row_count, bytes, last_altered
                        FROM information_schema.tables
                        WHERE table_schema = CURRENT_SCHEMA()
                          AND table_name IN ({quoted_tables})
                        """
                        )
                    )
                )
                .mappings()
                .all()
            )

            table_stats: Dict[str, Any] = {
                row["table_name"].lower(): {
                    "row_count": int(row.get("row_count") or 0),
                    "bytes": int(row.get("bytes") or 0),
                    "last_altered": (
                        row.get("last_altered").isoformat()  # type: ignore[union-attr]
                        if row.get("last_altered")
                        else None
                    ),
                }
                for row in table_stats_rows
            }

            missing_tables = [name for name in table_names if name not in table_stats]

            overall_status = "healthy"
            if jobs.get("refresh_rule_controls") is None:
                overall_status = "degraded"
            elif jobs["refresh_rule_controls"]["status"] not in {"success", "warning"}:
                overall_status = "degraded"

            return {
                "configured": True,
                "dialect": getattr(warehouse, "dialect_name", "snowflake"),
                "overall_status": overall_status,
                "jobs": jobs,
                "derived_tables": {
                    "rule_controls": rule_controls,
                },
                "tables": table_stats,
                "missing_tables": missing_tables,
            }

    except Exception as exc:
        return {
            "configured": True,
            "error": f"Failed to query warehouse health: {exc}",
        }


@router.get("/operations/health")
async def get_operational_health(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:findings")),
) -> Dict[str, Any]:
    """Return the consolidated operational health snapshot."""

    snapshot = await collect_operational_health(db)
    return snapshot


@router.get("/runtime-health")
async def get_runtime_health_summary(
    hours: int = Query(24, ge=1, le=168, description="Lookback window in hours"),
    analytics_db: Any = Depends(get_analytics_db),
    current_user: User = Depends(require_scopes("read:findings")),
) -> Dict[str, Any]:
    """Summarize agent runtime health for operational dashboards."""

    summaries = await summarize_runtime_health(analytics_db, hours=hours)
    return {
        "window_hours": hours,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtimes": summaries,
    }
