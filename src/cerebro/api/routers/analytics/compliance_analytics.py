"""Compliance analytics API endpoints."""

from typing import Any, Dict, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from cerebro.analytics.sql_dialect import (
    array_agg_ordered_expr,
    days_since_expr,
    get_dialect_name,
    timestamp_minus_days_expr,
)
from cerebro.core.analytics_db import get_analytics_db
from cerebro.core.database import get_db
from cerebro.core.models import Organization
from cerebro.api.auth import get_current_user, require_scopes, User
from cerebro.api.org_access import require_org_access

router = APIRouter(dependencies=[Depends(get_current_user)])


@router.get("/organizations/{org_id}/analytics/severity-breakdown")
async def get_severity_breakdown_chips(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    analytics_db: Any = Depends(get_analytics_db),
    current_user: User = Depends(require_org_access(require_scopes("read:findings"))),
) -> Dict[str, Any]:
    """Get severity breakdown chips with SLA breach counts for dashboard badges."""

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    dialect = get_dialect_name(analytics_db)
    critical_cutoff = timestamp_minus_days_expr(days=7, dialect=dialect)
    high_cutoff = timestamp_minus_days_expr(days=14, dialect=dialect)
    medium_cutoff = timestamp_minus_days_expr(days=30, dialect=dialect)
    low_cutoff = timestamp_minus_days_expr(days=90, dialect=dialect)

    # Get counts by severity and SLA breach status
    severity_query = text(
        f"""
        WITH finding_counts AS (
            SELECT
                f.severity,
                COUNT(*) as total_count,
                COUNT(CASE WHEN
                    ((f.severity = 'critical' AND f.first_seen <= {critical_cutoff}) OR
                     (f.severity = 'high' AND f.first_seen <= {high_cutoff}) OR
                     (f.severity = 'medium' AND f.first_seen <= {medium_cutoff}) OR
                     (f.severity = 'low' AND f.first_seen <= {low_cutoff}))
                     AND f.status = 'open'
                THEN 1 END) as sla_breach_count
            FROM findings f
            JOIN accounts a ON f.account_id = a.account_id
            WHERE a.org_id = :org_id AND f.status = 'open'
            GROUP BY f.severity
        )
        SELECT
            'critical' as severity,
            COALESCE(fc.total_count, 0) as total_count,
            COALESCE(fc.sla_breach_count, 0) as sla_breach_count
        FROM (SELECT 'critical' as severity) s
        LEFT JOIN finding_counts fc ON s.severity = fc.severity
        UNION ALL
        SELECT
            'high' as severity,
            COALESCE(fc.total_count, 0) as total_count,
            COALESCE(fc.sla_breach_count, 0) as sla_breach_count
        FROM (SELECT 'high' as severity) s
        LEFT JOIN finding_counts fc ON s.severity = fc.severity
        UNION ALL
        SELECT
            'medium' as severity,
            COALESCE(fc.total_count, 0) as total_count,
            COALESCE(fc.sla_breach_count, 0) as sla_breach_count
        FROM (SELECT 'medium' as severity) s
        LEFT JOIN finding_counts fc ON s.severity = fc.severity
        UNION ALL
        SELECT
            'low' as severity,
            COALESCE(fc.total_count, 0) as total_count,
            COALESCE(fc.sla_breach_count, 0) as sla_breach_count
        FROM (SELECT 'low' as severity) s
        LEFT JOIN finding_counts fc ON s.severity = fc.severity
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
            END
    """
    )

    result = await analytics_db.execute(severity_query, {"org_id": org_id})
    severity_data = result.fetchall()

    chips = []
    total_sla_breaches = 0

    # Map severity to short codes and colors
    severity_config = {
        "critical": {"code": "C", "color": "#dc2626", "bg_color": "#fee2e2"},
        "high": {"code": "H", "color": "#ea580c", "bg_color": "#fed7aa"},
        "medium": {"code": "M", "color": "#ca8a04", "bg_color": "#fef3c7"},
        "low": {"code": "L", "color": "#65a30d", "bg_color": "#ecfccb"},
    }

    for row in severity_data:
        config = severity_config[row.severity]
        total_sla_breaches += row.sla_breach_count

        chips.append(
            {
                "severity": row.severity,
                "code": config["code"],
                "total_count": row.total_count,
                "sla_breach_count": row.sla_breach_count,
                "color": config["color"],
                "background_color": config["bg_color"],
                "filter_url": f"/findings?severity={row.severity}&status=open",
                "sla_filter_url": f"/findings?severity={row.severity}&status=open&sla_breach=true",
            }
        )

    return {
        "severity_chips": chips,
        "total_sla_breaches": total_sla_breaches,
        "sla_breach_summary": {
            "count": total_sla_breaches,
            "filter_url": "/findings?status=open&sla_breach=true",
            "badge_text": f"SLA-breaching: {total_sla_breaches}",
        },
    }


@router.get("/organizations/{org_id}/compliance-evidence")
async def get_compliance_evidence_status(
    org_id: UUID,
    framework: Optional[str] = Query(
        None, description="Filter by compliance framework"
    ),
    db: AsyncSession = Depends(get_db),
    analytics_db: Any = Depends(get_analytics_db),
    current_user: User = Depends(require_org_access(require_scopes("read:findings"))),
) -> Dict[str, Any]:
    """Get compliance evidence freshness and ownership status."""

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    dialect = get_dialect_name(analytics_db)
    evidence_age_expr = days_since_expr(
        column_expr="MAX(cs.captured_at)", dialect=dialect
    )

    # Get evidence freshness by framework
    evidence_query = text(
        f"""
        WITH evidence_freshness AS (
            SELECT
                CASE
                    WHEN r.cis IS NOT NULL THEN 'CIS'
                    WHEN r.nist_800_53 IS NOT NULL THEN 'NIST'
                    ELSE 'OTHER'
                END as framework,
                r.rule_id,
                r.name as control_name,
                MAX(cs.captured_at) as last_evidence_collected,
                COUNT(DISTINCT f.finding_id) as open_violations,
                {evidence_age_expr} as evidence_age_days
            FROM rules r
            LEFT JOIN findings f ON r.rule_id = f.rule_id
                AND f.status = 'open'
                AND f.account_id IN (SELECT account_id FROM accounts WHERE org_id = :org_id)
            LEFT JOIN config_snapshots cs ON f.resource_id = cs.resource_id
            WHERE (r.cis IS NOT NULL OR r.nist_800_53 IS NOT NULL)
            GROUP BY r.rule_id, r.name,
                CASE
                    WHEN r.cis IS NOT NULL THEN 'CIS'
                    WHEN r.nist_800_53 IS NOT NULL THEN 'NIST'
                    ELSE 'OTHER'
                END
        )
        SELECT
            framework,
            COUNT(*) as total_controls,
            COUNT(CASE WHEN open_violations = 0 THEN 1 END) as compliant_controls,
            AVG(evidence_age_days) as avg_evidence_age_days,
            COUNT(CASE WHEN evidence_age_days > 30 THEN 1 END) as stale_evidence_controls
        FROM evidence_freshness
        WHERE (:framework IS NULL OR framework = :framework)
        GROUP BY framework
        ORDER BY framework
    """
    )

    result = await analytics_db.execute(
        evidence_query,
        {"org_id": org_id, "framework": framework.upper() if framework else None},
    )

    compliance_evidence = {}
    for row in result.fetchall():
        compliance_percentage = (
            (row.compliant_controls / row.total_controls * 100)
            if row.total_controls > 0
            else 0
        )

        compliance_evidence[row.framework] = {
            "total_controls": row.total_controls,
            "compliant_controls": row.compliant_controls,
            "compliance_percentage": round(compliance_percentage, 1),
            "avg_evidence_age_days": round(row.avg_evidence_age_days or 0, 1),
            "stale_evidence_controls": row.stale_evidence_controls,
            "evidence_freshness_status": (
                "fresh"
                if (row.avg_evidence_age_days or 0) < 7
                else "stale" if (row.avg_evidence_age_days or 0) > 30 else "aging"
            ),
        }

    return {
        "org_id": str(org_id),
        "frameworks": compliance_evidence,
        "summary": {
            "total_frameworks": len(compliance_evidence),
            "overall_compliance": (
                round(
                    sum(
                        data["compliance_percentage"]
                        for data in compliance_evidence.values()
                    )
                    / len(compliance_evidence),
                    1,
                )
                if compliance_evidence
                else 0
            ),
            "stale_evidence_count": sum(
                data["stale_evidence_controls"] for data in compliance_evidence.values()
            ),
        },
    }


@router.get("/organizations/{org_id}/analytics/evidence-freshness")
async def get_evidence_freshness_donut(
    org_id: UUID,
    db: AsyncSession = Depends(get_db),
    analytics_db: Any = Depends(get_analytics_db),
    current_user: User = Depends(require_org_access(require_scopes("read:findings"))),
) -> Dict[str, Any]:
    """Get evidence freshness donut chart data with click-through URLs."""

    org = await db.get(Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    dialect = get_dialect_name(analytics_db)
    evidence_age_expr = days_since_expr(
        column_expr="MAX(cs.captured_at)", dialect=dialect
    )
    sample_controls_expr = array_agg_ordered_expr(
        value_expr="control_name",
        order_by_expr="evidence_age_days DESC",
        dialect=dialect,
    )

    # Get evidence freshness categorization
    freshness_query = text(
        f"""
        WITH evidence_analysis AS (
            SELECT
                r.rule_id,
                r.name as control_name,
                r.cis,
                r.nist_800_53,
                MAX(cs.captured_at) as last_evidence_collected,
                {evidence_age_expr} as evidence_age_days
            FROM rules r
            LEFT JOIN findings f ON r.rule_id = f.rule_id
                AND f.account_id IN (SELECT account_id FROM accounts WHERE org_id = :org_id)
            LEFT JOIN config_snapshots cs ON f.resource_id = cs.resource_id
            WHERE (r.cis IS NOT NULL OR r.nist_800_53 IS NOT NULL)
            GROUP BY r.rule_id, r.name, r.cis, r.nist_800_53
        )
        SELECT
            CASE
                WHEN evidence_age_days IS NULL THEN 'missing'
                WHEN evidence_age_days <= 7 THEN 'fresh'
                WHEN evidence_age_days <= 30 THEN 'aging'
                ELSE 'stale'
            END as freshness_status,
            COUNT(*) as control_count,
            {sample_controls_expr} as sample_controls
        FROM evidence_analysis
        GROUP BY
            CASE
                WHEN evidence_age_days IS NULL THEN 'missing'
                WHEN evidence_age_days <= 7 THEN 'fresh'
                WHEN evidence_age_days <= 30 THEN 'aging'
                ELSE 'stale'
            END
        ORDER BY
            CASE
                WHEN freshness_status = 'missing' THEN 1
                WHEN freshness_status = 'stale' THEN 2
                WHEN freshness_status = 'aging' THEN 3
                WHEN freshness_status = 'fresh' THEN 4
            END
    """
    )

    result = await analytics_db.execute(freshness_query, {"org_id": org_id})
    freshness_data = result.fetchall()

    # Donut chart configuration with colors and click-through
    freshness_config = {
        "fresh": {"color": "#22c55e", "label": "Fresh (≤7 days)", "priority": 4},
        "aging": {"color": "#f59e0b", "label": "Aging (8-30 days)", "priority": 3},
        "stale": {"color": "#ef4444", "label": "Stale (>30 days)", "priority": 2},
        "missing": {"color": "#6b7280", "label": "Missing Evidence", "priority": 1},
    }

    donut_segments = []
    total_controls = sum(row.control_count for row in freshness_data)

    for row in freshness_data:
        config = freshness_config[row.freshness_status]
        percentage = (
            round((row.control_count / total_controls * 100), 1)
            if total_controls > 0
            else 0
        )

        donut_segments.append(
            {
                "status": row.freshness_status,
                "label": config["label"],
                "count": row.control_count,
                "percentage": percentage,
                "color": config["color"],
                "priority": config["priority"],
                "click_through_url": f"/compliance/controls?evidence_freshness={row.freshness_status}",
                "sample_controls": (
                    row.sample_controls[:5] if row.sample_controls else []
                ),
            }
        )

    # Sort by priority (most critical first)
    donut_segments.sort(key=lambda x: x["priority"])

    return {
        "org_id": str(org_id),
        "donut_data": {
            "segments": donut_segments,
            "total_controls": total_controls,
            "center_metric": {
                "value": total_controls,
                "label": "Total Controls",
                "subtitle": f"{sum(s['count'] for s in donut_segments if s['status'] in ['fresh', 'aging'])} monitored",
            },
        },
        "summary_stats": {
            "fresh_percentage": next(
                (s["percentage"] for s in donut_segments if s["status"] == "fresh"), 0
            ),
            "needs_attention": sum(
                s["count"]
                for s in donut_segments
                if s["status"] in ["stale", "missing"]
            ),
            "most_critical": donut_segments[0]["status"] if donut_segments else "fresh",
        },
        "quick_actions": [
            (
                f"Fix {sum(s['count'] for s in donut_segments if s['status'] == 'missing')} missing evidence collectors"
                if any(s["status"] == "missing" for s in donut_segments)
                else None
            ),
            (
                f"Refresh {sum(s['count'] for s in donut_segments if s['status'] == 'stale')} stale evidence sources"
                if any(s["status"] == "stale" for s in donut_segments)
                else None
            ),
        ],
    }
