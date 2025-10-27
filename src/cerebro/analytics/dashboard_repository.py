"""Database access helpers for dashboard analytics queries."""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID
from typing import Dict

from .orientation import generate_orientation_summary


class DashboardRepository:
    """Encapsulates raw queries used by dashboard analytics."""

    def __init__(self, db_session: AsyncSession) -> None:
        self._db = db_session

    async def get_finding_count(self, org_id: UUID) -> int:
        query = text(
            "SELECT COUNT(*) FROM findings f JOIN accounts a ON f.account_id = a.account_id WHERE a.org_id = :org_id"
        )
        result = await self._db.execute(query, {"org_id": org_id})
        return result.scalar() or 0

    async def get_finding_count_by_severity(self, org_id: UUID, severity: str) -> int:
        query = text(
            """
            SELECT COUNT(*)
            FROM findings f
            JOIN accounts a ON f.account_id = a.account_id
            WHERE a.org_id = :org_id AND f.severity = :severity AND f.status = 'open'
            """
        )
        result = await self._db.execute(
            query, {"org_id": org_id, "severity": severity}
        )
        return result.scalar() or 0

    async def get_finding_count_by_status(self, org_id: UUID, status: str) -> int:
        query = text(
            """
            SELECT COUNT(*)
            FROM findings f
            JOIN accounts a ON f.account_id = a.account_id
            WHERE a.org_id = :org_id AND f.status = :status
            """
        )
        result = await self._db.execute(query, {"org_id": org_id, "status": status})
        return result.scalar() or 0

    async def count_sla_breaches(self, org_id: UUID) -> int:
        query = text(
            """
            SELECT COUNT(*)
            FROM findings f
            JOIN accounts a ON f.account_id = a.account_id
            WHERE a.org_id = :org_id
                AND f.status = 'open'
                AND (
                    (f.severity = 'critical' AND f.first_seen <= NOW() - INTERVAL '7 days') OR
                    (f.severity = 'high' AND f.first_seen <= NOW() - INTERVAL '14 days') OR
                    (f.severity = 'medium' AND f.first_seen <= NOW() - INTERVAL '30 days')
                )
            """
        )
        result = await self._db.execute(query, {"org_id": org_id})
        return result.scalar() or 0

    async def calculate_mttr(self, org_id: UUID) -> float:
        query = text(
            """
            SELECT AVG(EXTRACT(EPOCH FROM (last_seen - first_seen)) / 3600) as mttr_hours
            FROM findings f
            JOIN accounts a ON f.account_id = a.account_id
            WHERE a.org_id = :org_id
                AND f.status IN ('fixed', 'accepted_risk')
                AND f.first_seen >= NOW() - INTERVAL '90 days'
            """
        )
        result = await self._db.execute(query, {"org_id": org_id})
        return result.scalar() or 0.0

    async def count_new_findings(self, org_id: UUID) -> int:
        query = text(
            """
            SELECT COUNT(*)
            FROM findings f
            JOIN accounts a ON f.account_id = a.account_id
            WHERE a.org_id = :org_id
                AND f.first_seen >= NOW() - INTERVAL '24 hours'
            """
        )
        result = await self._db.execute(query, {"org_id": org_id})
        return result.scalar() or 0

    async def count_resolved_findings(self, org_id: UUID) -> int:
        query = text(
            """
            SELECT COUNT(*)
            FROM findings f
            JOIN accounts a ON f.account_id = a.account_id
            WHERE a.org_id = :org_id
                AND f.status IN ('fixed', 'accepted_risk')
                AND f.last_seen >= NOW() - INTERVAL '24 hours'
            """
        )
        result = await self._db.execute(query, {"org_id": org_id})
        return result.scalar() or 0

    async def count_total_assets(self, org_id: UUID) -> int:
        query = text(
            """
            SELECT COUNT(DISTINCT r.resource_id)
            FROM resources r
            JOIN accounts a ON r.account_id = a.account_id
            WHERE a.org_id = :org_id
            """
        )
        result = await self._db.execute(query, {"org_id": org_id})
        return result.scalar() or 0

    async def count_total_identities(self, org_id: UUID) -> int:
        query = text(
            """
            SELECT COUNT(DISTINCT p.principal_id)
            FROM principals p
            JOIN accounts a ON p.account_id = a.account_id
            WHERE a.org_id = :org_id AND p.is_human = true
            """
        )
        result = await self._db.execute(query, {"org_id": org_id})
        return result.scalar() or 0

    async def calculate_compliance_score(self, org_id: UUID) -> float:
        total_query = text(
            """
            SELECT COUNT(DISTINCT r.rule_id)
            FROM rules r
            WHERE r.cis IS NOT NULL OR r.nist_800_53 IS NOT NULL
            """
        )
        compliant_query = text(
            """
            SELECT COUNT(DISTINCT r.rule_id)
            FROM assessment_results ar
            JOIN rules r ON ar.rule_id = r.rule_id
            WHERE ar.org_id = :org_id
                AND ar.status = 'passed'
                AND (r.cis IS NOT NULL OR r.nist_800_53 IS NOT NULL)
            """
        )

        total_result = await self._db.execute(total_query)
        total_rules = total_result.scalar() or 0
        if total_rules == 0:
            return 100.0

        compliant_result = await self._db.execute(compliant_query, {"org_id": org_id})
        compliant_rules = compliant_result.scalar() or 0

        return round((compliant_rules / total_rules) * 100.0, 2)

    async def get_compliance_by_framework(self, org_id: UUID) -> Dict[str, Dict[str, float]]:
        """Return compliance counts grouped by framework."""

        frameworks_query = text(
            """
            SELECT
                framework,
                SUM(total_controls) as total_controls,
                SUM(compliant_controls) as compliant_controls
            FROM (
                SELECT 
                    SPLIT_PART(control, '.', 1) as framework,
                    COUNT(*) as total_controls,
                    COUNT(CASE WHEN f.finding_id IS NULL THEN 1 END) as compliant_controls
                FROM (
                    SELECT UNNEST(r.cis) as control, r.rule_id
                    FROM rules r
                    WHERE r.cis IS NOT NULL
                ) controls
                JOIN rules r ON r.rule_id = controls.rule_id
                LEFT JOIN findings f ON r.rule_id = f.rule_id
                    AND f.status = 'open'
                    AND f.account_id IN (
                        SELECT account_id FROM accounts WHERE org_id = :org_id
                    )
                GROUP BY framework

                UNION ALL

                SELECT 
                    SPLIT_PART(control, '.', 1) as framework,
                    COUNT(*) as total_controls,
                    COUNT(CASE WHEN f.finding_id IS NULL THEN 1 END) as compliant_controls
                FROM (
                    SELECT UNNEST(r.nist_800_53) as control, r.rule_id
                    FROM rules r
                    WHERE r.nist_800_53 IS NOT NULL
                ) controls
                JOIN rules r ON r.rule_id = controls.rule_id
                LEFT JOIN findings f ON r.rule_id = f.rule_id
                    AND f.status = 'open'
                    AND f.account_id IN (
                        SELECT account_id FROM accounts WHERE org_id = :org_id
                    )
                GROUP BY framework
            ) aggregated
            GROUP BY framework
            """
        )

        result = await self._db.execute(frameworks_query, {"org_id": org_id})

        framework_compliance: Dict[str, Dict[str, float]] = {}
        for row in result.fetchall():
            total = row.total_controls or 0
            compliant = row.compliant_controls or 0
            percentage = (compliant / total * 100) if total > 0 else 0
            percentage_value = float(percentage)

            framework_compliance[row.framework] = {
                "total_controls": int(total),
                "compliant_controls": int(compliant),
                "compliance_percentage": round(percentage_value, 1),
                "status": (
                    "compliant"
                    if percentage_value >= 90
                    else "partial"
                    if percentage_value >= 70
                    else "non_compliant"
                ),
            }

        return framework_compliance

    async def get_orientation_summary(self) -> dict:
        """Return trending telemetry summary for dashboard widgets."""

        return await generate_orientation_summary(window_hours=24, baseline_hours=168)
