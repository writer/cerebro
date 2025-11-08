"""Monitoring and operational health API endpoints."""

from typing import Dict, Any
from uuid import UUID
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from cerebro.api.auth import get_current_user, require_scopes, User
from cerebro.analytics.operations import gather_celery_status, collect_operational_health
from cerebro.analytics.runtime_health import summarize_runtime_health
from cerebro.core.database import get_db
from cerebro.core.models import Organization

router = APIRouter(dependencies=[Depends(get_current_user)])


@router.get("/organizations/{org_id}/sla-breaches")
async def get_sla_breach_analysis(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:findings"))
) -> Dict[str, Any]:
    """Get detailed SLA breach analysis with ownership."""

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Get SLA breaches by severity with details and ownership
    sla_breach_query = text("""
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
            EXTRACT(EPOCH FROM (NOW() - f.first_seen)) / 86400 as days_old,
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
                (f.severity = 'critical' AND f.first_seen <= NOW() - INTERVAL '7 days') OR
                (f.severity = 'high' AND f.first_seen <= NOW() - INTERVAL '14 days') OR
                (f.severity = 'medium' AND f.first_seen <= NOW() - INTERVAL '30 days') OR
                (f.severity = 'low' AND f.first_seen <= NOW() - INTERVAL '90 days')
            )
        ORDER BY
            CASE f.severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
            END,
            f.first_seen
    """)

    result = await db.execute(sla_breach_query, {"org_id": org_id})
    breaches = result.fetchall()

    # Organize by severity
    breaches_by_severity = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": []
    }

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
            "backup_owner": breach.backup_owner
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
            "average_days_overdue": round(sum(int(b.days_old) - b.sla_days for b in breaches) / len(breaches), 1) if breaches else 0
        },
        "breaches_by_severity": breaches_by_severity,
        "urgent_actions": [
            f"{critical_breaches} critical findings > 7 days old" if critical_breaches > 0 else None,
            f"{high_breaches} high findings > 14 days old" if high_breaches > 0 else None
        ]
    }


@router.get("/heartbeat")
async def get_heartbeat_chips(
    current_user: User = Depends(require_scopes("read:findings"))
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
        status_message = f"{summary['healthy_workers']}/{summary['total_workers']} workers healthy"
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
            "last_updated": now.isoformat()
        },
        {
            "type": "queue_depth",
            "label": "Queue Depth",
            "value": str(queue_depth),
            "status": queue_status,
            "color": queue_color,
            "message": f"{queue_depth} tasks pending",
            "click_through_url": "/admin/tasks",
            "last_updated": now.isoformat()
        },
        {
            "type": "active_tasks",
            "label": "Active",
            "value": str(summary["total_active_tasks"]),
            "status": "info",
            "color": "#3b82f6",
            "message": f"{summary['total_active_tasks']} running tasks",
            "click_through_url": "/admin/tasks?status=active",
            "last_updated": now.isoformat()
        }
    ]

    return {
        "heartbeat_chips": heartbeat_chips,
        "system_health": {
            "overall_status": system_status,
            "last_check": now.isoformat(),
            "workers_online": summary["healthy_workers"],
            "total_workers": summary["total_workers"],
            "queue_backlog": queue_depth > 20
        },
        "worker_details": celery_status["workers"],
        "error": celery_status.get("error")
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
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_scopes("read:findings")),
) -> Dict[str, Any]:
    """Summarize agent runtime health for operational dashboards."""

    summaries = await summarize_runtime_health(db, hours=hours)
    return {
        "window_hours": hours,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtimes": summaries,
    }