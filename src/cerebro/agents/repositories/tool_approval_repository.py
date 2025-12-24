"""Persistence helpers for tool approvals."""

from __future__ import annotations

from contextlib import asynccontextmanager
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from cerebro.agents.models import ApprovalStatus, ToolApproval
from cerebro.core.database import async_session_factory


class ToolApprovalRepository:
    """Encapsulates read/write operations for tool approval workflows."""

    def __init__(self, session_factory=None) -> None:
        self._session_factory = session_factory or async_session_factory

    async def list_pending(
        self,
        org_id: UUID,
        *,
        limit: int,
        offset: int,
    ) -> tuple[list[ToolApproval], int]:
        async with self._session_factory() as db_session:
            stmt = (
                select(ToolApproval)
                .options(selectinload(ToolApproval.tool_invocation))
                .where(ToolApproval.org_id == org_id)
                .where(ToolApproval.status == ApprovalStatus.PENDING)
                .order_by(ToolApproval.requested_at.desc())
                .limit(limit)
                .offset(offset)
            )
            result = await db_session.execute(stmt)
            approvals = list(result.scalars())

            count_stmt = (
                select(func.count(ToolApproval.id))
                .where(ToolApproval.org_id == org_id)
                .where(ToolApproval.status == ApprovalStatus.PENDING)
            )
            total_result = await db_session.execute(count_stmt)
            total = int(total_result.scalar_one())

        return approvals, total

    async def get(
        self,
        approval_id: UUID,
        org_id: UUID,
    ) -> ToolApproval | None:
        async with self._session_factory() as db_session:
            stmt = (
                select(ToolApproval)
                .options(selectinload(ToolApproval.tool_invocation))
                .where(ToolApproval.id == approval_id)
                .where(ToolApproval.org_id == org_id)
            )
            result = await db_session.execute(stmt)
            return result.scalar_one_or_none()

    @asynccontextmanager
    async def approval_scope(
        self,
        approval_id: UUID,
        org_id: UUID,
    ):
        async with self._session_factory() as db_session:
            stmt = (
                select(ToolApproval)
                .options(selectinload(ToolApproval.tool_invocation))
                .where(ToolApproval.id == approval_id)
                .where(ToolApproval.org_id == org_id)
            )
            result = await db_session.execute(stmt)
            approval = result.scalar_one_or_none()
            yield approval, db_session
            await db_session.commit()
