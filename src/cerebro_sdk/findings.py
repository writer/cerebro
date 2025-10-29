"""Finding and rule evaluation helpers for the Cerebro SDK."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.models import Finding, Organization
from cerebro.findings.manager import FindingManager, FindingResult
from cerebro.findings.evaluator import RuleEvaluator
from cerebro.rules.engine import rule_engine


@dataclass(slots=True)
class FindingRecord:
    finding_id: UUID
    org_id: UUID
    account_id: UUID
    rule_id: UUID
    status: str
    severity: str
    title: str
    summary: Optional[str]
    last_seen: datetime


class FindingService:
    """Provide convenience access to finding lifecycle operations."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def list_findings(
        self,
        org_id: UUID,
        *,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[FindingRecord]:
        stmt = select(Finding).where(Finding.org_id == org_id)
        if status:
            stmt = stmt.where(Finding.status == status)
        if severity:
            stmt = stmt.where(Finding.severity == severity)
        stmt = stmt.order_by(Finding.last_seen.desc()).offset(offset).limit(limit)

        rows = await self._db.scalars(stmt)
        return [self._to_record(row) for row in rows]

    async def get_finding(self, finding_id: UUID) -> Optional[FindingRecord]:
        stmt = select(Finding).where(Finding.finding_id == finding_id)
        finding = await self._db.scalar(stmt)
        if not finding:
            return None
        return self._to_record(finding)

    async def close_finding(self, finding_id: UUID, status: str = "fixed") -> bool:
        finding = await self._db.get(Finding, finding_id)
        if not finding:
            return False

        finding.status = status
        finding.last_seen = datetime.utcnow()
        await self._db.commit()
        return True

    async def generate_for_org(
        self,
        org_id: UUID,
        *,
        provider: Optional[str] = None,
        resource_types: Optional[Iterable[str]] = None,
    ) -> FindingResult:
        org = await self._db.get(Organization, org_id)
        if not org:
            raise ValueError(f"Organization {org_id} not found")

        evaluator = RuleEvaluator(self._db, rule_engine)
        manager = FindingManager(self._db, evaluator)
        return await manager.generate_findings(
            org,
            provider=provider,
            resource_types=list(resource_types) if resource_types else None,
        )

    @staticmethod
    def _to_record(finding: Finding) -> FindingRecord:
        return FindingRecord(
            finding_id=finding.finding_id,
            org_id=finding.org_id,
            account_id=finding.account_id,
            rule_id=finding.rule_id,
            status=finding.status,
            severity=finding.severity,
            title=finding.title,
            summary=finding.summary,
            last_seen=finding.last_seen,
        )
