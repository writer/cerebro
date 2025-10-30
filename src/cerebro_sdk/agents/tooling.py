"""Agent tooling and approval helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

from prometheus_client import CollectorRegistry
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.agents.models import AgentPolicySuggestion, ToolApproval, ToolInvocation

from cerebro_sdk.agents.base import AsyncManagerBase
from cerebro_sdk.agents.repositories import ToolingRepository
from cerebro_sdk.agents.types import (
    AgentInvalidStatusError,
    AgentNotFoundError,
    AgentPolicySuggestionRecord,
    ToolApprovalRecord,
    ToolInvocationRecord,
)

from cerebro.agents.models import ApprovalStatus, ToolInvocationStatus


class AgentToolingManager(AsyncManagerBase):
    """Inspect and manage tool invocations and approvals."""

    def __init__(self, db: AsyncSession, *, registry: CollectorRegistry | None = None) -> None:
        super().__init__(db)
        self._repo = ToolingRepository(db, registry=registry)

    async def list_invocations(
        self,
        *,
        session_id: Optional[UUID] = None,
        org_id: Optional[UUID] = None,
        status: ToolInvocationStatus | str | None = None,
        tool_name: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        cursor: Optional[datetime] = None,
        page_size: Optional[int] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ToolInvocationRecord]:
        status_enum: Optional[ToolInvocationStatus] = None
        if status:
            try:
                status_enum = self._require_enum(
                    status,
                    ToolInvocationStatus,
                    message=f"Invalid tool invocation status '{status}'",
                )
            except AgentInvalidStatusError:
                return []

        effective_limit = page_size if page_size is not None else limit
        invocations = await self._repo.list_invocations(
            session_id=session_id,
            org_id=org_id,
            status=status_enum,
            tool_name=tool_name,
            since=since,
            until=until,
            cursor=cursor,
            effective_limit=effective_limit,
            offset=offset,
        )
        return [self._invocation_to_record(invocation) for invocation in invocations]

    async def get_invocation(self, invocation_id: UUID) -> Optional[ToolInvocationRecord]:
        invocation = await self._repo.get_invocation(invocation_id)
        if not invocation:
            return None
        return self._invocation_to_record(invocation)

    async def create_invocation(
        self,
        *,
        session_id: UUID,
        tool_name: str,
        tool_version: str = "1.0",
        input_data: dict[str, Any],
        status: ToolInvocationStatus | str = ToolInvocationStatus.PENDING,
        started_at: Optional[datetime] = None,
        cel_policy_key: Optional[str] = None,
        cel_expression: Optional[str] = None,
        cel_context: Optional[dict[str, Any]] = None,
    ) -> ToolInvocationRecord:
        status_enum = self._require_enum(
            status,
            ToolInvocationStatus,
            message=f"Invalid tool invocation status '{status}'",
        )
        started_at_value = started_at or datetime.now(timezone.utc)
        async with self._transaction():
            invocation = await self._repo.create_invocation(
                session_id=session_id,
                tool_name=tool_name,
                tool_version=tool_version,
                input_data=input_data,
                status=status_enum,
                started_at=started_at_value,
                cel_policy_key=cel_policy_key,
                cel_expression=cel_expression,
                cel_context=cel_context,
            )
        await self._db.refresh(invocation)
        return self._invocation_to_record(invocation)

    async def list_approvals(
        self,
        *,
        org_id: UUID,
        status: ApprovalStatus | str | None = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        cursor: Optional[datetime] = None,
        page_size: Optional[int] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ToolApprovalRecord]:
        status_enum: Optional[ApprovalStatus] = None
        if status:
            try:
                status_enum = self._require_enum(
                    status,
                    ApprovalStatus,
                    message=f"Invalid approval status '{status}'",
                )
            except AgentInvalidStatusError:
                return []

        effective_limit = page_size if page_size is not None else limit
        approvals = await self._repo.list_approvals(
            org_id=org_id,
            status=status_enum,
            since=since,
            until=until,
            cursor=cursor,
            effective_limit=effective_limit,
            offset=offset,
        )
        return [self._approval_to_record(approval) for approval in approvals]

    async def update_approval_status(
        self,
        *,
        approval_id: UUID,
        status: ApprovalStatus | str,
        decided_by: str,
        decision_reason: Optional[str] = None,
    ) -> Optional[ToolApprovalRecord]:
        approval = await self._repo.get_approval(approval_id)
        if not approval:
            return None
        status_enum = self._require_enum(
            status,
            ApprovalStatus,
            message=f"Invalid approval status '{status}'",
        )

        invocation = approval.tool_invocation
        now = datetime.now(timezone.utc)

        async with self._transaction():
            approval.status = status_enum
            approval.decided_by = decided_by
            approval.decided_at = now
            approval.decision_reason = decision_reason

            if invocation:
                if status_enum == ApprovalStatus.APPROVED:
                    invocation.status = ToolInvocationStatus.SUCCESS
                    invocation.completed_at = now
                elif status_enum == ApprovalStatus.REJECTED:
                    invocation.status = ToolInvocationStatus.ERROR
                    invocation.error_message = decision_reason or "Rejected by reviewer"
                    invocation.completed_at = now

        await self._db.refresh(approval)
        if invocation:
            await self._db.refresh(invocation)
        return self._approval_to_record(approval)

    async def update_invocation_result(
        self,
        *,
        invocation_id: UUID,
        status: ToolInvocationStatus | str | None = None,
        output_data: Optional[dict[str, Any]] = None,
        error_message: Optional[str] = None,
        error_code: Optional[str] = None,
        cel_result: Optional[bool] = None,
        cel_context: Optional[dict[str, Any]] = None,
        completed_at: Optional[datetime] = None,
    ) -> ToolInvocationRecord:
        invocation = await self._repo.get_invocation(invocation_id)
        if not invocation:
            raise AgentNotFoundError(f"Tool invocation {invocation_id} not found")

        status_enum: Optional[ToolInvocationStatus] = None
        if status is not None:
            status_enum = self._require_enum(
                status,
                ToolInvocationStatus,
                message=f"Invalid tool invocation status '{status}'",
            )

        completed_value: Optional[datetime] = completed_at
        if completed_value is None and status_enum in {
            ToolInvocationStatus.SUCCESS,
            ToolInvocationStatus.ERROR,
            ToolInvocationStatus.DRY_RUN,
        }:
            completed_value = datetime.now(timezone.utc)

        async with self._transaction():
            await self._repo.update_invocation(
                invocation,
                status=status_enum,
                output_data=output_data,
                error_message=error_message,
                error_code=error_code,
                completed_at=completed_value,
                cel_result=cel_result,
                cel_context=cel_context,
            )

        await self._db.refresh(invocation)
        return self._invocation_to_record(invocation)

    async def list_policy_suggestions(
        self,
        *,
        org_id: UUID,
        tool_name: Optional[str] = None,
    ) -> list[AgentPolicySuggestionRecord]:
        stmt = select(AgentPolicySuggestion).where(AgentPolicySuggestion.org_id == org_id)
        if tool_name:
            stmt = stmt.where(AgentPolicySuggestion.tool_name == tool_name)
        stmt = stmt.order_by(AgentPolicySuggestion.last_seen.desc())
        suggestions = list(await self._db.scalars(stmt))
        return [self._policy_to_record(suggestion) for suggestion in suggestions]

    @staticmethod
    def _invocation_to_record(invocation: ToolInvocation) -> ToolInvocationRecord:
        input_payload = invocation.input_data if isinstance(invocation.input_data, dict) else {"value": invocation.input_data}
        output_payload = None
        if invocation.output_data is not None:
            output_payload = invocation.output_data if isinstance(invocation.output_data, dict) else {"value": invocation.output_data}
        return ToolInvocationRecord(
            invocation_id=invocation.id,
            session_id=invocation.session_id,
            tool_name=invocation.tool_name,
            tool_version=invocation.tool_version,
            status=invocation.status.value,
            started_at=invocation.started_at,
            completed_at=invocation.completed_at,
            input_data=input_payload,
            output_data=output_payload,
            error_message=invocation.error_message,
            cel_policy_key=invocation.cel_policy_key,
            cel_expression=invocation.cel_expression,
            cel_result=invocation.cel_result,
        )

    @staticmethod
    def _approval_to_record(approval: ToolApproval) -> ToolApprovalRecord:
        return ToolApprovalRecord(
            approval_id=approval.id,
            org_id=approval.org_id,
            tool_invocation_id=approval.tool_invocation_id,
            requested_by=approval.requested_by,
            requested_at=approval.requested_at,
            reason=approval.reason,
            status=approval.status.value,
            decided_by=approval.decided_by,
            decided_at=approval.decided_at,
            decision_reason=approval.decision_reason,
            expires_at=approval.expires_at,
            risk_assessment=approval.risk_assessment if isinstance(approval.risk_assessment, dict) else {},
        )

    @staticmethod
    def _policy_to_record(suggestion: AgentPolicySuggestion) -> AgentPolicySuggestionRecord:
        return AgentPolicySuggestionRecord(
            suggestion_id=suggestion.id,
            org_id=suggestion.org_id,
            tool_name=suggestion.tool_name,
            cel_expression=suggestion.cel_expression,
            support_count=suggestion.support_count,
            reject_count=suggestion.reject_count,
            details=suggestion.details if isinstance(suggestion.details, dict) else {},
            last_seen=suggestion.last_seen,
            created_at=suggestion.created_at,
        )
