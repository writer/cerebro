"""Database access helpers for dashboard analytics queries."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Set
from uuid import UUID, uuid4

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.models import IdentityRemediationAction

from .sql_dialect import (
    array_has_elements_expr,
    get_dialect_name,
    hours_between_expr,
    select_array_elements_subquery,
    timestamp_minus_days_expr,
)

from .orientation import generate_orientation_summary


logger = logging.getLogger(__name__)


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
        dialect = get_dialect_name(self._db)
        critical_cutoff = timestamp_minus_days_expr(days=7, dialect=dialect)
        high_cutoff = timestamp_minus_days_expr(days=14, dialect=dialect)
        medium_cutoff = timestamp_minus_days_expr(days=30, dialect=dialect)
        query = text(
            f"""
            SELECT COUNT(*)
            FROM findings f
            JOIN accounts a ON f.account_id = a.account_id
            WHERE a.org_id = :org_id
                AND f.status = 'open'
                AND (
                    (f.severity = 'critical' AND f.first_seen <= {critical_cutoff}) OR
                    (f.severity = 'high' AND f.first_seen <= {high_cutoff}) OR
                    (f.severity = 'medium' AND f.first_seen <= {medium_cutoff})
                )
            """
        )
        result = await self._db.execute(query, {"org_id": org_id})
        return result.scalar() or 0

    async def calculate_mttr(self, org_id: UUID) -> float:
        dialect = get_dialect_name(self._db)
        cutoff = timestamp_minus_days_expr(days=90, dialect=dialect)
        diff_hours_expr = hours_between_expr(
            start_expr="f.first_seen",
            end_expr="f.last_seen",
            dialect=dialect,
        )
        query = text(
            f"""
            SELECT AVG({diff_hours_expr}) as mttr_hours
            FROM findings f
            JOIN accounts a ON f.account_id = a.account_id
            WHERE a.org_id = :org_id
                AND f.status IN ('fixed', 'accepted_risk')
                AND f.first_seen >= {cutoff}
            """
        )
        result = await self._db.execute(query, {"org_id": org_id})
        return result.scalar() or 0.0

    async def count_new_findings(self, org_id: UUID) -> int:
        dialect = get_dialect_name(self._db)
        cutoff = timestamp_minus_days_expr(days=1, dialect=dialect)
        query = text(
            f"""
            SELECT COUNT(*)
            FROM findings f
            JOIN accounts a ON f.account_id = a.account_id
            WHERE a.org_id = :org_id
                AND f.first_seen >= {cutoff}
            """
        )
        result = await self._db.execute(query, {"org_id": org_id})
        return result.scalar() or 0

    async def count_resolved_findings(self, org_id: UUID) -> int:
        dialect = get_dialect_name(self._db)
        cutoff = timestamp_minus_days_expr(days=1, dialect=dialect)
        query = text(
            f"""
            SELECT COUNT(*)
            FROM findings f
            JOIN accounts a ON f.account_id = a.account_id
            WHERE a.org_id = :org_id
                AND f.status IN ('fixed', 'accepted_risk')
                AND f.last_seen >= {cutoff}
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
        dialect = get_dialect_name(self._db)
        if dialect == "snowflake":
            compliance_rule_predicate = "EXISTS (SELECT 1 FROM rule_controls rc WHERE rc.rule_id = r.rule_id)"
        else:
            cis_nonempty = array_has_elements_expr(column_expr="r.cis", dialect=dialect)
            nist_nonempty = array_has_elements_expr(column_expr="r.nist_800_53", dialect=dialect)
            compliance_rule_predicate = f"({cis_nonempty} OR {nist_nonempty})"

        total_query = text(
            f"""
            SELECT COUNT(DISTINCT r.rule_id)
            FROM rules r
            WHERE {compliance_rule_predicate}
            """
        )
        compliant_query = text(
            f"""
            SELECT COUNT(DISTINCT r.rule_id)
            FROM assessment_results ar
            JOIN rules r ON ar.rule_id = r.rule_id
            WHERE ar.org_id = :org_id
                AND ar.status = 'passed'
                AND {compliance_rule_predicate}
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

        dialect = get_dialect_name(self._db)
        if dialect == "snowflake":
            frameworks_query = text(
                """
                WITH open_rules AS (
                    SELECT f.rule_id
                    FROM findings f
                    JOIN accounts a ON f.account_id = a.account_id
                    WHERE a.org_id = :org_id
                        AND f.status = 'open'
                    GROUP BY f.rule_id
                )
                SELECT
                    rc.framework AS framework,
                    COUNT(*) AS total_controls,
                    SUM(CASE WHEN open_rules.rule_id IS NULL THEN 1 ELSE 0 END) AS compliant_controls
                FROM rule_controls rc
                LEFT JOIN open_rules ON rc.rule_id = open_rules.rule_id
                GROUP BY rc.framework
                """
            )
        else:
            cis_controls = select_array_elements_subquery(array_column="cis", dialect=dialect)
            nist_controls = select_array_elements_subquery(array_column="nist_800_53", dialect=dialect)

            frameworks_query = text(
                f"""
                WITH controls AS (
                    SELECT 'CIS' AS framework, rule_id
                    FROM (
                        {cis_controls}
                    ) cis

                    UNION ALL

                    SELECT 'NIST_800_53' AS framework, rule_id
                    FROM (
                        {nist_controls}
                    ) nist
                ),
                open_rules AS (
                    SELECT f.rule_id
                    FROM findings f
                    JOIN accounts a ON f.account_id = a.account_id
                    WHERE a.org_id = :org_id
                        AND f.status = 'open'
                    GROUP BY f.rule_id
                )
                SELECT
                    controls.framework AS framework,
                    COUNT(*) AS total_controls,
                    SUM(CASE WHEN open_rules.rule_id IS NULL THEN 1 ELSE 0 END) AS compliant_controls
                FROM controls
                LEFT JOIN open_rules ON controls.rule_id = open_rules.rule_id
                GROUP BY controls.framework
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

    async def get_remediation_actions(self, org_id: UUID) -> List[IdentityRemediationAction]:
        statement = (
            select(IdentityRemediationAction)
            .where(IdentityRemediationAction.org_id == org_id)
            .order_by(
                IdentityRemediationAction.status.asc(),
                IdentityRemediationAction.priority.desc(),
                IdentityRemediationAction.created_at.asc(),
            )
        )
        result = await self._db.execute(statement)
        return list(result.scalars().all())

    async def ensure_remediation_action(
        self,
        org_id: UUID,
        principal_id: UUID,
        summary: str,
        recommended_action: str,
        priority: str,
        evidence: List[str],
        initiated_by: Optional[UUID] = None,
    ) -> IdentityRemediationAction:
        statement = select(IdentityRemediationAction).where(
            IdentityRemediationAction.org_id == org_id,
            IdentityRemediationAction.principal_id == principal_id,
            IdentityRemediationAction.recommended_action == recommended_action,
        )
        result = await self._db.execute(statement)
        action = result.scalar_one_or_none()

        now = datetime.utcnow()

        if action is None:
            action = IdentityRemediationAction(
                org_id=org_id,
                principal_id=principal_id,
                summary=summary,
                recommended_action=recommended_action,
                priority=priority,
                status="pending",
                evidence=list(evidence),
                notes=[],
                created_by=initiated_by,
                updated_by=initiated_by,
                created_at=now,
                updated_at=now,
            )
            self._db.add(action)
            await self._db.flush()
            return action

        updated = False
        if action.summary != summary:
            action.summary = summary
            updated = True
        if action.priority != priority:
            action.priority = priority
            updated = True
        if action.evidence != evidence:
            action.evidence = list(evidence)
            updated = True

        if updated:
            action.updated_at = now
            action.updated_by = initiated_by or action.updated_by
            await self._db.flush()

        return action

    async def update_remediation_action_status(
        self,
        org_id: UUID,
        action_id: UUID,
        status: str,
        user_id: UUID,
        note: Optional[str] = None,
        user_display_name: Optional[str] = None,
    ) -> IdentityRemediationAction:
        action = await self._db.get(IdentityRemediationAction, action_id)
        if action is None or action.org_id != org_id:
            raise ValueError("Remediation action not found")

        now = datetime.utcnow()
        if status == "accepted":
            action.status = "accepted"
            action.accepted_at = now
            action.accepted_by = user_id
        elif status == "completed":
            action.status = "completed"
            action.completed_at = now
            action.completed_by = user_id
        else:
            raise ValueError("Invalid remediation status")

        action.updated_at = now
        action.updated_by = user_id

        if note:
            action.notes = list(action.notes or []) + [
                self._build_note_entry(user_id, note, user_display_name, now)
            ]

        await self._db.flush()
        return action

    async def update_remediation_actions_status_bulk(
        self,
        org_id: UUID,
        action_ids: Sequence[UUID],
        status: str,
        user_id: UUID,
        note: Optional[str] = None,
        user_display_name: Optional[str] = None,
    ) -> List[IdentityRemediationAction]:
        if not action_ids:
            raise ValueError("No remediation actions supplied")

        unique_ids: List[UUID] = []
        seen: Set[UUID] = set()
        for action_id in action_ids:
            if action_id not in seen:
                unique_ids.append(action_id)
                seen.add(action_id)

        result = await self._db.execute(
            select(IdentityRemediationAction).where(
                IdentityRemediationAction.action_id.in_(unique_ids),
                IdentityRemediationAction.org_id == org_id,
            )
        )
        actions = result.scalars().all()
        action_lookup = {action.action_id: action for action in actions}

        found_ids = set(action_lookup)
        missing = {action_id for action_id in unique_ids if action_id not in found_ids}
        if missing:
            raise ValueError("Remediation action not found")

        now = datetime.utcnow()
        updated: List[IdentityRemediationAction] = []
        for action_id in unique_ids:
            action = action_lookup[action_id]
            if status == "accepted":
                if action.status != "accepted":
                    action.status = "accepted"
                    action.accepted_at = now
                    action.accepted_by = user_id
            elif status == "completed":
                if action.status != "completed":
                    action.status = "completed"
                    action.completed_at = now
                    action.completed_by = user_id
            else:
                raise ValueError("Invalid remediation status")

            if note:
                action.notes = list(action.notes or []) + [
                    self._build_note_entry(user_id, note, user_display_name, now)
                ]

            action.updated_at = now
            action.updated_by = user_id
            updated.append(action)

        await self._db.flush()

        logger.info(
            "Updated %s remediation actions for org %s to %s",
            len(updated),
            org_id,
            status,
        )

        return updated

    async def add_remediation_note(
        self,
        org_id: UUID,
        action_id: UUID,
        user_id: UUID,
        note: str,
        user_display_name: Optional[str] = None,
    ) -> IdentityRemediationAction:
        action = await self._db.get(IdentityRemediationAction, action_id)
        if action is None or action.org_id != org_id:
            raise ValueError("Remediation action not found")

        now = datetime.utcnow()
        action.notes = list(action.notes or []) + [
            self._build_note_entry(user_id, note, user_display_name, now)
        ]
        action.updated_at = now
        action.updated_by = user_id
        await self._db.flush()
        return action

    @staticmethod
    def serialize_remediation_action(action: IdentityRemediationAction) -> Dict[str, Any]:
        return {
            "action_id": str(action.action_id),
            "principal_id": str(action.principal_id),
            "summary": action.summary,
            "recommended_action": action.recommended_action,
            "priority": action.priority,
            "status": action.status,
            "evidence": action.evidence or [],
            "notes": action.notes or [],
            "accepted_at": action.accepted_at.isoformat() if action.accepted_at else None,
            "accepted_by": str(action.accepted_by) if action.accepted_by else None,
            "completed_at": action.completed_at.isoformat() if action.completed_at else None,
            "completed_by": str(action.completed_by) if action.completed_by else None,
            "created_at": action.created_at.isoformat() if action.created_at else None,
            "updated_at": action.updated_at.isoformat() if action.updated_at else None,
            "source": "manual" if action.created_by else "analytics",
        }

    @staticmethod
    def serialize_remediation_actions(
        actions: Sequence[IdentityRemediationAction],
    ) -> List[Dict[str, Any]]:
        return [DashboardRepository.serialize_remediation_action(action) for action in actions]

    @staticmethod
    def _build_note_entry(
        user_id: UUID,
        note: str,
        user_display_name: Optional[str],
        timestamp: datetime,
    ) -> Dict[str, Any]:
        return {
            "note_id": str(uuid4()),
            "author_id": str(user_id),
            "author": user_display_name,
            "note": note,
            "created_at": timestamp.isoformat() + "Z",
        }

    async def get_findings_by_provider(
        self, org_id: UUID, provider: str, limit: int = 25
    ) -> List[Dict[str, Any]]:
        """Return detailed findings for a given provider."""

        provider_query = text(
            """
            SELECT
                f.finding_id,
                f.title,
                f.severity,
                f.status,
                f.first_seen,
                f.last_seen,
                f.resource_id,
                r.name AS rule_name
            FROM findings f
            JOIN accounts a ON f.account_id = a.account_id
            LEFT JOIN rules r ON f.rule_id = r.rule_id
            WHERE a.org_id = :org_id
              AND a.provider = :provider
            ORDER BY
                CASE f.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    ELSE 4
                END,
                f.first_seen DESC
            LIMIT :limit
            """
        )

        result = await self._db.execute(
            provider_query,
            {"org_id": org_id, "provider": provider, "limit": limit},
        )

        findings: List[Dict[str, Any]] = []
        for row in result.fetchall():
            findings.append(
                {
                    "finding_id": str(row.finding_id),
                    "title": row.title,
                    "severity": row.severity,
                    "status": row.status,
                    "first_seen": row.first_seen.isoformat() if row.first_seen else None,
                    "last_seen": row.last_seen.isoformat() if row.last_seen else None,
                    "resource_id": str(row.resource_id) if row.resource_id else None,
                    "rule_name": row.rule_name,
                }
            )

        return findings

    async def get_findings_breakdown_by_provider(self, org_id: UUID) -> List[Dict[str, Any]]:
        """Aggregate findings by provider with severity and SLA context."""

        dialect = get_dialect_name(self._db)
        last_24h_cutoff = timestamp_minus_days_expr(days=1, dialect=dialect)
        critical_cutoff = timestamp_minus_days_expr(days=7, dialect=dialect)
        high_cutoff = timestamp_minus_days_expr(days=14, dialect=dialect)
        medium_cutoff = timestamp_minus_days_expr(days=30, dialect=dialect)
        mttr_hours_expr = hours_between_expr(
            start_expr="f.first_seen",
            end_expr="f.last_seen",
            dialect=dialect,
        )

        provider_query = text(
            f"""
            SELECT
                a.provider,
                SUM(CASE WHEN f.status = 'open' THEN 1 ELSE 0 END) AS open_findings,
                SUM(CASE WHEN f.status = 'open' AND f.severity = 'critical' THEN 1 ELSE 0 END) AS critical_open,
                SUM(CASE WHEN f.status = 'open' AND f.severity = 'high' THEN 1 ELSE 0 END) AS high_open,
                SUM(CASE WHEN f.first_seen >= {last_24h_cutoff} THEN 1 ELSE 0 END) AS new_last_24h,
                SUM(
                    CASE
                        WHEN f.status = 'open'
                            AND (
                                (f.severity = 'critical' AND f.first_seen <= {critical_cutoff}) OR
                                (f.severity = 'high' AND f.first_seen <= {high_cutoff}) OR
                                (f.severity = 'medium' AND f.first_seen <= {medium_cutoff})
                            )
                        THEN 1 ELSE 0 END
                ) AS sla_breaches,
                AVG(
                    CASE
                        WHEN f.status IN ('fixed', 'accepted_risk') THEN {mttr_hours_expr}
                        ELSE NULL
                    END
                ) AS mttr_hours
            FROM findings f
            JOIN accounts a ON f.account_id = a.account_id
            WHERE a.org_id = :org_id
            GROUP BY a.provider
            ORDER BY open_findings DESC
            """
        )

        result = await self._db.execute(provider_query, {"org_id": org_id})

        breakdown: List[Dict[str, Any]] = []
        for row in result.fetchall():
            breakdown.append(
                {
                    "provider": row.provider,
                    "open_findings": int(row.open_findings or 0),
                    "critical_open": int(row.critical_open or 0),
                    "high_open": int(row.high_open or 0),
                    "new_last_24h": int(row.new_last_24h or 0),
                    "sla_breaches": int(row.sla_breaches or 0),
                    "mttr_hours": float(row.mttr_hours) if row.mttr_hours is not None else None,
                }
            )

        return breakdown

    async def get_orientation_summary(self) -> dict:
        """Return trending telemetry summary for dashboard widgets."""

        return await generate_orientation_summary(window_hours=24, baseline_hours=168)
