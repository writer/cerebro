"""Compliance analytics for evidence tracking and control ownership."""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from .sql_dialect import array_has_elements_expr, days_since_expr, get_dialect_name

logger = logging.getLogger(__name__)


@dataclass
class EvidenceFreshnessReport:
    """Report on evidence freshness for compliance."""

    control_id: str
    control_name: str
    framework: str
    last_collected: Optional[datetime]
    age_days: float
    freshness_status: str  # "fresh", "aging", "stale", "missing"
    collection_frequency_required: int  # days
    next_collection_due: datetime


@dataclass
class ControlOwnership:
    """Control ownership and responsibility tracking."""

    control_id: str
    control_name: str
    owner: Optional[str]
    backup_owner: Optional[str]
    review_frequency: int  # days
    last_reviewed: Optional[datetime]
    next_review_due: datetime
    ownership_status: str  # "assigned", "unassigned", "review_overdue"


class ComplianceAnalyzer:
    """Analyzer for compliance evidence and control tracking."""

    def __init__(self, db_session: AsyncSession):
        """Initialize compliance analyzer."""
        self.db = db_session

    async def analyze_evidence_freshness(
        self, org_id: UUID, framework: Optional[str] = None
    ) -> List[EvidenceFreshnessReport]:
        """Analyze evidence freshness across compliance controls."""

        logger.info(f"Analyzing evidence freshness for org {org_id}")

        dialect = get_dialect_name(self.db)
        age_days_expr = days_since_expr(
            column_expr="MAX(cs.captured_at)", dialect=dialect
        )

        if dialect == "snowflake":
            evidence_query = text(
                f"""
                WITH rule_frameworks AS (
                    SELECT DISTINCT rule_id, framework
                    FROM rule_controls
                ),
                control_evidence AS (
                    SELECT
                        r.rule_id,
                        r.name as control_name,
                        rf.framework as framework,
                        MAX(cs.captured_at) as last_evidence_collected,
                        {age_days_expr} as age_days
                    FROM rules r
                    JOIN rule_frameworks rf ON r.rule_id = rf.rule_id
                    LEFT JOIN findings f ON r.rule_id = f.rule_id
                        AND f.account_id IN (SELECT account_id FROM accounts WHERE org_id = :org_id)
                    LEFT JOIN config_snapshots cs ON f.resource_id = cs.resource_id
                    WHERE (:framework IS NULL OR rf.framework = :framework)
                    GROUP BY r.rule_id, r.name, rf.framework
                )
                SELECT
                    rule_id,
                    control_name,
                    framework,
                    last_evidence_collected,
                    COALESCE(age_days, 999) as age_days,
                    CASE
                        WHEN last_evidence_collected IS NULL THEN 'missing'
                        WHEN age_days <= 7 THEN 'fresh'
                        WHEN age_days <= 30 THEN 'aging'
                        ELSE 'stale'
                    END as freshness_status
                FROM control_evidence
                ORDER BY age_days DESC, framework, control_name
                """
            )
        else:
            cis_nonempty = array_has_elements_expr(column_expr="r.cis", dialect=dialect)
            nist_nonempty = array_has_elements_expr(
                column_expr="r.nist_800_53", dialect=dialect
            )
            compliance_rule_predicate = f"({cis_nonempty} OR {nist_nonempty})"
            framework_expr = (
                f"CASE WHEN {cis_nonempty} THEN 'CIS' "
                f"WHEN {nist_nonempty} THEN 'NIST_800_53' "
                f"ELSE 'OTHER' END"
            )
            evidence_query = text(
                f"""
                WITH control_evidence AS (
                    SELECT 
                        r.rule_id,
                        r.name as control_name,
                        {framework_expr} as framework,
                        MAX(cs.captured_at) as last_evidence_collected,
                        {age_days_expr} as age_days
                    FROM rules r
                    LEFT JOIN findings f ON r.rule_id = f.rule_id
                        AND f.account_id IN (SELECT account_id FROM accounts WHERE org_id = :org_id)
                    LEFT JOIN config_snapshots cs ON f.resource_id = cs.resource_id
                    WHERE {compliance_rule_predicate}
                        AND (
                            :framework IS NULL OR
                            (:framework = 'CIS' AND {cis_nonempty}) OR
                            (:framework = 'NIST_800_53' AND {nist_nonempty})
                        )
                    GROUP BY r.rule_id, r.name, framework
                )
                SELECT 
                    rule_id,
                    control_name,
                    framework,
                    last_evidence_collected,
                    COALESCE(age_days, 999) as age_days,
                    CASE 
                        WHEN last_evidence_collected IS NULL THEN 'missing'
                        WHEN age_days <= 7 THEN 'fresh'
                        WHEN age_days <= 30 THEN 'aging'
                        ELSE 'stale'
                    END as freshness_status
                FROM control_evidence
                ORDER BY age_days DESC, framework, control_name
                """
            )

        result = await self.db.execute(
            evidence_query, {"org_id": org_id, "framework": framework}
        )

        reports = []
        for row in result.fetchall():
            # Determine collection frequency based on framework
            if row.framework == "CIS":
                frequency_days = 30
            elif row.framework == "NIST_800_53":
                frequency_days = 14
            else:
                frequency_days = 30

            # Calculate next collection due
            if row.last_evidence_collected:
                next_due = row.last_evidence_collected + timedelta(days=frequency_days)
            else:
                next_due = datetime.utcnow()  # Immediate

            reports.append(
                EvidenceFreshnessReport(
                    control_id=str(row.rule_id),
                    control_name=row.control_name,
                    framework=row.framework,
                    last_collected=row.last_evidence_collected,
                    age_days=row.age_days,
                    freshness_status=row.freshness_status,
                    collection_frequency_required=frequency_days,
                    next_collection_due=next_due,
                )
            )

        return reports

    async def track_control_ownership(self, org_id: UUID) -> List[ControlOwnership]:
        """Track control ownership and review status."""

        # For now, this returns a template since control ownership
        # would typically be stored in a separate governance system
        # In production, this would integrate with systems like:
        # - ServiceNow GRC
        # - Archer
        # - MetricStream
        # - Custom governance database

        ownership_data = []

        dialect = get_dialect_name(self.db)
        if dialect == "snowflake":
            rules_query = text(
                """
                SELECT r.rule_id, r.name, r.description
                FROM rules r
                WHERE EXISTS (
                    SELECT 1 FROM rule_controls rc WHERE rc.rule_id = r.rule_id
                )
                    AND r.is_active = true
                ORDER BY r.name
                """
            )
        else:
            # Get all compliance rules
            cis_nonempty = array_has_elements_expr(column_expr="cis", dialect=dialect)
            nist_nonempty = array_has_elements_expr(
                column_expr="nist_800_53", dialect=dialect
            )
            rules_query = text(
                f"""
                SELECT rule_id, name, description
                FROM rules
                WHERE ({cis_nonempty} OR {nist_nonempty})
                    AND is_active = true
                ORDER BY name
                """
            )

        result = await self.db.execute(rules_query)

        for row in result.fetchall():
            # Template ownership data - in production this would come from GRC system
            ownership_data.append(
                ControlOwnership(
                    control_id=str(row.rule_id),
                    control_name=row.name,
                    owner=None,  # Would be populated from GRC system
                    backup_owner=None,
                    review_frequency=90,  # 90 days
                    last_reviewed=None,
                    next_review_due=datetime.utcnow() + timedelta(days=90),
                    ownership_status="unassigned",  # Would be calculated from GRC data
                )
            )

        return ownership_data


class EvidenceFreshnessTracker:
    """Tracks evidence collection freshness for compliance."""

    def __init__(self, db_session: AsyncSession):
        """Initialize evidence freshness tracker."""
        self.db = db_session

    async def get_stale_evidence_summary(self, org_id: UUID) -> Dict[str, Any]:
        """Get summary of stale evidence requiring attention."""

        analyzer = ComplianceAnalyzer(self.db)
        evidence_reports = await analyzer.analyze_evidence_freshness(org_id)

        # Categorize by freshness
        freshness_counts = {"fresh": 0, "aging": 0, "stale": 0, "missing": 0}

        critical_stale = []
        for report in evidence_reports:
            freshness_counts[report.freshness_status] += 1

            # Flag critical stale evidence
            if report.freshness_status == "stale" and report.age_days > 60:
                critical_stale.append(
                    {
                        "control_name": report.control_name,
                        "framework": report.framework,
                        "age_days": int(report.age_days),
                        "last_collected": (
                            report.last_collected.isoformat()
                            if report.last_collected
                            else None
                        ),
                    }
                )

        return {
            "summary": freshness_counts,
            "total_controls": len(evidence_reports),
            "compliance_percentage": (
                round((freshness_counts["fresh"] / len(evidence_reports)) * 100, 1)
                if evidence_reports
                else 0
            ),
            "critical_stale_evidence": critical_stale,
            "action_required": len(critical_stale) > 0,
        }
