"""Finding and rule evaluation helpers for the Cerebro SDK."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.models import Finding, Organization
from cerebro.findings.evaluator import RuleEvaluator
from cerebro.findings.manager import FindingManager, FindingResult
from cerebro.rules.engine import rule_engine
from cerebro_sdk.pagination import CursorPage, PageRequest, decode_cursor, encode_cursor


@dataclass
class FindingRecord:
    finding_id: UUID
    org_id: UUID
    account_id: UUID
    provider: str
    rule_id: UUID
    rule_version: int
    resource_id: UUID | None
    principal_id: UUID | None
    first_seen: datetime
    status: str
    severity: str
    fingerprint: str
    title: str
    summary: str | None
    last_seen: datetime
    evidence: dict[str, object] | None


class FindingService:
    """Provide convenience access to finding lifecycle operations."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def list_findings(
        self,
        org_id: UUID,
        *,
        status: str | None = None,
        severity: str | None = None,
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

    async def list_findings_page(
        self,
        org_id: UUID,
        *,
        status: str | None = None,
        severity: str | None = None,
        provider: str | None = None,
        page: PageRequest | None = None,
    ) -> CursorPage[FindingRecord]:
        request = page or PageRequest()
        limit = max(1, min(request.limit, 200))

        stmt = (
            select(Finding)
            .where(Finding.org_id == org_id)
            .order_by(Finding.last_seen.desc(), Finding.finding_id.desc())
        )
        if status:
            stmt = stmt.where(Finding.status == status)
        if severity:
            stmt = stmt.where(Finding.severity == severity)
        if provider:
            stmt = stmt.where(Finding.provider == provider)

        if request.cursor:
            cursor = decode_cursor(request.cursor)
            cursor_last_seen = cursor.payload.get("last_seen")
            cursor_finding_id = cursor.payload.get("finding_id")

            last_seen_dt: datetime | None = None
            if isinstance(cursor_last_seen, str):
                try:
                    last_seen_dt = datetime.fromisoformat(cursor_last_seen)
                except ValueError:
                    last_seen_dt = None

            finding_uuid: UUID | None = None
            if isinstance(cursor_finding_id, str):
                try:
                    finding_uuid = UUID(cursor_finding_id)
                except (ValueError, TypeError):
                    finding_uuid = None

            if last_seen_dt is not None and finding_uuid is not None:
                stmt = stmt.where(
                    or_(
                        Finding.last_seen < last_seen_dt,
                        and_(
                            Finding.last_seen == last_seen_dt,
                            Finding.finding_id < finding_uuid,
                        ),
                    )
                )

        stmt = stmt.limit(limit + 1)
        rows = list(await self._db.scalars(stmt))

        has_more = len(rows) > limit
        page_rows = rows[:limit]
        items = [self._to_record(row) for row in page_rows]

        next_cursor: str | None = None
        if has_more and page_rows:
            last = page_rows[-1]
            next_cursor = encode_cursor(
                {
                    "last_seen": last.last_seen.isoformat(),
                    "finding_id": str(last.finding_id),
                }
            )

        return CursorPage(items=items, next_cursor=next_cursor)

    async def get_finding(self, finding_id: UUID) -> FindingRecord | None:
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
        provider: str | None = None,
        resource_types: Iterable[str] | None = None,
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
            provider=finding.provider,
            rule_id=finding.rule_id,
            rule_version=finding.rule_version,
            resource_id=finding.resource_id,
            principal_id=finding.principal_id,
            first_seen=finding.first_seen,
            status=finding.status,
            severity=finding.severity,
            fingerprint=finding.fingerprint,
            title=finding.title,
            summary=finding.summary,
            last_seen=finding.last_seen,
            evidence=dict(finding.evidence) if finding.evidence else None,
        )
