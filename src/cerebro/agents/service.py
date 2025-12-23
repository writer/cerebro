"""
Cerebro Agent Service

High-level service layer for managing agent sessions, orchestrating conversations,
and providing clean interfaces for API endpoints and CLI commands.
"""

from datetime import datetime, timezone, timedelta
from typing import Any, AsyncIterator, Dict, List, Optional
from uuid import UUID, uuid4

import structlog
from sqlalchemy import text

from cerebro.agents.repositories import AgentSessionRepository, ToolApprovalRepository
from cerebro.agents.models import (
    AgentSession,
    AgentType,
    ReviewTaskStatus,
    ToolApproval,
    ToolInvocationStatus,
    ApprovalStatus,
)
from cerebro.agents.runtime_facade import AgentRuntimeFacade
from cerebro.agents.review_service import AgentReviewService
from cerebro.agents.analytics_service import (
    AgentAnalyticsService as RuntimeAnalyticsService,
)
from cerebro.agents.notification_service import NotificationService
from cerebro.rules.engine import RuleEngine, EvaluationContext, CompilationError

logger = structlog.get_logger(__name__)


class AgentSessionService:
    """Service for managing agent sessions and conversations."""

    def __init__(
        self,
        runtime: Optional[AgentRuntimeFacade] = None,
        repository: Optional[AgentSessionRepository] = None,
    ):
        self.runtime = runtime or AgentRuntimeFacade()
        self._rule_engine = RuleEngine()
        self._repository = repository or AgentSessionRepository()

    async def create_session(
        self,
        org_id: UUID,
        agent_type: str,
        created_by: str,
        context: Dict[str, Any],
        title: Optional[str] = None,
    ) -> AgentSession:
        """Create a new agent session."""

        # Validate agent type
        try:
            agent_type_enum = AgentType(agent_type)
        except ValueError:
            raise ValueError(f"Invalid agent type: {agent_type}")

        session = await self.runtime.create_session(
            org_id=org_id,
            agent_type=agent_type_enum,
            created_by=created_by,
            context=context,
            title=title,
        )

        logger.info(
            "Agent session created",
            session_id=session.id,
            agent_type=agent_type,
            org_id=org_id,
            created_by=created_by,
        )

        return session

    async def get_session(
        self,
        session_id: UUID,
        org_id: Optional[UUID] = None,
    ) -> Optional[AgentSession]:
        """Get an agent session by ID, optionally filtered by org."""

        return await self._repository.get_session(session_id=session_id, org_id=org_id)

    async def list_sessions(
        self,
        org_id: UUID,
        agent_type: Optional[str] = None,
        created_by: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[List[AgentSession], int]:
        """List agent sessions for an organization."""

        agent_type_enum: Optional[AgentType] = None
        if agent_type:
            try:
                agent_type_enum = AgentType(agent_type)
            except ValueError:
                return [], 0

        sessions, total_count = await self._repository.list_sessions(
            org_id=org_id,
            agent_type=agent_type_enum,
            created_by=created_by,
            limit=limit,
            offset=offset,
        )

        return list(sessions), total_count

    async def send_message(
        self,
        session_id: UUID,
        message: str,
        user_id: str,
        org_id: Optional[UUID] = None,
        stream: bool = False,
    ) -> AsyncIterator[Dict[str, Any]]:
        """Send a message to an agent session."""

        # Get session
        session = await self.get_session(session_id, org_id)
        if not session:
            yield {
                "type": "error",
                "content": {"message": "Session not found or access denied"},
                "metadata": {"session_id": str(session_id)},
            }
            return

        # Send message through runtime
        async for response in self.runtime.send_message(
            session=session,
            message=message,
            user_id=user_id,
            stream=stream,
        ):
            yield response

    async def get_session_messages(
        self,
        session_id: UUID,
        org_id: Optional[UUID] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Get messages from an agent session."""

        # Verify session access
        session = await self.get_session(session_id, org_id)
        if not session:
            return []

        return await self.runtime.get_session_messages(session, limit, offset)

    async def get_session_memory(
        self,
        session_id: UUID,
        org_id: Optional[UUID] = None,
        limit: int = 50,
        include_content: bool = False,
    ) -> Optional[List[Dict[str, Any]]]:
        """Retrieve recent memory entries associated with a session."""

        session = await self.get_session(session_id, org_id)
        if not session:
            return None

        entries = await self._repository.list_memory_entries(session_id, limit=limit)

        serialized: List[Dict[str, Any]] = []
        for entry in entries:
            scope_labels: List[str] = []
            for scope in entry.scopes or []:
                scope_type = scope.get("type")
                value = scope.get("value")
                if scope_type and scope_type != "session":
                    if value:
                        scope_labels.append(f"{scope_type}:{value}")
                    else:
                        scope_labels.append(scope_type)

            payload: Dict[str, Any] = {
                "id": str(entry.id),
                "role": entry.role.value if entry.role else None,
                "summary": entry.summary,
                "decay_score": entry.decay_score,
                "last_accessed_at": entry.last_accessed_at.isoformat(),
                "created_at": entry.created_at.isoformat(),
                "scopes": entry.scopes,
                "scope_labels": scope_labels,
                "metadata": entry.extra_metadata or {},
                "token_count": entry.token_count,
                "embedding_similarity": None,
                "lexical_similarity": None,
                "combined_similarity": None,
                "ann_selected": None,
            }

            if include_content:
                payload["content"] = entry.content

            serialized.append(payload)

        return serialized

    async def get_session_memory_stats(
        self,
        session_id: UUID,
        org_id: Optional[UUID] = None,
    ) -> Optional[Dict[str, Any]]:
        session = await self.get_session(session_id, org_id)
        if not session:
            return None

        entries = await self._repository.list_memory_entries_for_stats(session_id)

        total_entries = len(entries)
        if total_entries == 0:
            return {
                "total_entries": 0,
                "recent_entries": 0,
                "presented_entries": 0,
                "average_decay": 0.0,
                "token_total": 0,
                "role_distribution": {},
                "scope_distribution": {},
                "top_memories": [],
            }

        role_distribution: Dict[str, int] = {}
        scope_distribution: Dict[str, int] = {}
        token_total = 0
        decay_sum = 0.0
        recent_entries = 0
        presented_entries = 0
        recent_cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

        highlights: List[Dict[str, Any]] = []

        for entry in entries:
            created_at = entry.created_at
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)

            last_accessed = entry.last_accessed_at
            if last_accessed.tzinfo is None:
                last_accessed = last_accessed.replace(tzinfo=timezone.utc)

            role_key = (entry.role.value if entry.role else "unknown").lower()
            role_distribution[role_key] = role_distribution.get(role_key, 0) + 1

            for scope in entry.scopes or []:
                scope_type = (scope.get("type") or "unknown").lower()
                scope_distribution[scope_type] = (
                    scope_distribution.get(scope_type, 0) + 1
                )

            metadata = entry.extra_metadata or {}
            if int(metadata.get("presented_count", 0) or 0) > 0:
                presented_entries += 1

            if created_at >= recent_cutoff:
                recent_entries += 1

            token_total += entry.token_count or 0
            decay_sum += entry.decay_score

            scope_labels: List[str] = []
            for scope in entry.scopes or []:
                scope_type = scope.get("type")
                value = scope.get("value")
                if scope_type and scope_type != "session":
                    scope_labels.append(
                        f"{scope_type}:{value}" if value else scope_type
                    )

            highlights.append(
                {
                    "id": str(entry.id),
                    "summary": entry.summary,
                    "decay_score": entry.decay_score,
                    "last_accessed_at": last_accessed.isoformat(),
                    "role": entry.role.value if entry.role else None,
                    "scope_labels": scope_labels,
                }
            )

        highlights.sort(key=lambda item: item["decay_score"], reverse=True)

        average_decay = decay_sum / total_entries if total_entries else 0.0

        return {
            "total_entries": total_entries,
            "recent_entries": recent_entries,
            "presented_entries": presented_entries,
            "average_decay": round(average_decay, 3),
            "token_total": token_total,
            "role_distribution": role_distribution,
            "scope_distribution": scope_distribution,
            "top_memories": highlights[:5],
        }

    async def list_review_tasks(
        self,
        org_id: UUID,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        status_enum: Optional[ReviewTaskStatus] = None
        if status:
            try:
                status_enum = ReviewTaskStatus(status)
            except ValueError:
                status_enum = None

        tasks = await AgentReviewService.list_tasks(
            org_id=org_id,
            status=status_enum,
            limit=limit,
        )
        return [self._serialize_review_task(task) for task in tasks]

    async def list_review_tasks_page(
        self,
        org_id: UUID,
        *,
        status: Optional[str] = None,
        limit: int = 50,
        cursor: Optional[str] = None,
    ) -> Dict[str, Any]:
        status_enum: Optional[ReviewTaskStatus] = None
        if status:
            try:
                status_enum = ReviewTaskStatus(status)
            except ValueError:
                status_enum = None

        tasks, next_cursor = await AgentReviewService.list_tasks_page(
            org_id=org_id,
            status=status_enum,
            limit=limit,
            cursor=cursor,
        )
        return {
            "items": [self._serialize_review_task(task) for task in tasks],
            "next_cursor": next_cursor,
        }

    async def resolve_review_task(
        self,
        *,
        task_id: UUID,
        resolved_by: str,
        status: str,
        notes: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        try:
            status_enum = ReviewTaskStatus(status)
        except ValueError as exc:
            raise ValueError("Invalid review task status") from exc

        task = await AgentReviewService.resolve_task(
            task_id=task_id,
            resolved_by=resolved_by,
            status=status_enum,
            notes=notes,
        )
        if task is None:
            return None
        return self._serialize_review_task(task)

    async def bulk_update_review_tasks(
        self,
        *,
        org_id: UUID,
        task_ids: List[UUID],
        status: Optional[str] = None,
        resolved_by: Optional[str] = None,
        notes: Optional[str] = None,
        escalated_to: Optional[str] = None,
        due_at: Optional[datetime] = None,
        priority: Optional[str] = None,
        notification_channel: Optional[str] = None,
        ticket_system: Optional[str] = None,
        ticket_summary: Optional[str] = None,
        ticket_metadata: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        status_enum: Optional[ReviewTaskStatus] = None
        if status:
            try:
                status_enum = ReviewTaskStatus(status)
            except ValueError as exc:
                raise ValueError("Invalid review task status") from exc

        tasks = await AgentReviewService.bulk_update_tasks(
            org_id=org_id,
            task_ids=task_ids,
            status=status_enum,
            resolved_by=resolved_by,
            notes=notes,
            escalated_to=escalated_to,
            due_at=due_at,
            priority=priority,
            notification_channel=notification_channel,
            ticket_system=ticket_system,
            ticket_summary=ticket_summary,
            ticket_metadata=ticket_metadata,
        )
        return [self._serialize_review_task(task) for task in tasks]

    async def list_review_notifications(
        self,
        *,
        org_id: UUID,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        notifications = await NotificationService.list_notifications(
            org_id=org_id,
            status=status,
            limit=limit,
        )
        return [
            {
                "id": str(notification.id),
                "task_id": str(notification.task_id),
                "org_id": str(notification.org_id),
                "channel": notification.channel,
                "status": notification.status,
                "payload": notification.payload,
                "created_at": notification.created_at.isoformat(),
                "delivered_at": (
                    notification.delivered_at.isoformat()
                    if notification.delivered_at
                    else None
                ),
            }
            for notification in notifications
        ]

    async def get_session_analytics(
        self,
        *,
        session_id: UUID,
        org_id: Optional[UUID] = None,
        limit: int = 100,
        event_type: Optional[str] = None,
        before: Optional[datetime] = None,
        before_id: Optional[UUID] = None,
    ) -> List[Dict[str, Any]]:
        session = await self.get_session(session_id, org_id)
        if not session:
            return []
        return await RuntimeAnalyticsService.list_events(
            session_id=session_id,
            limit=limit,
            event_type=event_type,
            before=before,
            before_id=before_id,
        )

    async def get_session_analytics_summary(
        self,
        *,
        session_id: UUID,
        org_id: Optional[UUID] = None,
        event_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        session = await self.get_session(session_id, org_id)
        if not session:
            return []
        return await RuntimeAnalyticsService.summarize_events(
            session_id=session_id,
            event_type=event_type,
        )

    async def list_policy_suggestions(
        self,
        *,
        org_id: UUID,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        suggestions = await self._repository.list_policy_suggestions(
            org_id, limit=limit
        )

        ranked: List[Dict[str, Any]] = []
        for suggestion in suggestions:
            support = suggestion.support_count or 0
            reject = suggestion.reject_count or 0
            confidence = support / max(1, support + reject)
            ranked.append(
                {
                    "id": str(suggestion.id),
                    "tool_name": suggestion.tool_name,
                    "cel_expression": suggestion.cel_expression,
                    "support_count": support,
                    "reject_count": reject,
                    "confidence": round(confidence, 3),
                    "metadata": suggestion.details,
                    "last_seen": suggestion.last_seen.isoformat(),
                }
            )
        return ranked

    async def simulate_policy_expression(
        self,
        *,
        org_id: UUID,
        expression: str,
        tool_name: Optional[str] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        if not expression or not expression.strip():
            raise ValueError("CEL expression is required")

        try:
            # Ensure expression compiles before running bulk evaluation.
            self._rule_engine.compile_rule(expression)
        except CompilationError as exc:
            raise ValueError(f"CEL expression failed to compile: {exc}") from exc

        normalized_limit = max(1, min(limit, 200))

        rows = await self._repository.latest_tool_invocations(
            org_id,
            limit=normalized_limit,
            tool_name=tool_name,
        )

        evaluated = 0
        matched = 0
        mismatched = 0
        errors = 0
        examples: List[Dict[str, Any]] = []

        for invocation, session in rows:
            evaluated += 1
            cel_context = invocation.cel_context or {}
            eval_context = EvaluationContext(
                resource=cel_context,
                config=cel_context,
                principal={
                    "user_id": cel_context.get("user_id") or session.created_by,
                    "org_id": str(session.org_id),
                },
            )

            rule_result = self._rule_engine.evaluate_rule(
                rule_id=uuid4(),
                expression=expression,
                context=eval_context,
            )

            matched_flag = bool(rule_result.matched)
            if matched_flag:
                matched += 1
            else:
                mismatched += 1

            if rule_result.error:
                errors += 1

            if len(examples) < 10:
                examples.append(
                    {
                        "invocation_id": str(invocation.id),
                        "session_id": str(invocation.session_id),
                        "tool_name": invocation.tool_name,
                        "matched": matched_flag,
                        "status": invocation.status.value,
                        "started_at": (
                            invocation.started_at.isoformat()
                            if invocation.started_at
                            else None
                        ),
                        "completed_at": (
                            invocation.completed_at.isoformat()
                            if invocation.completed_at
                            else None
                        ),
                        "input_data": invocation.input_data,
                        "output_data": invocation.output_data,
                        "cel_context": cel_context,
                        "error": rule_result.error,
                        "latency_ms": rule_result.execution_time_ms,
                    }
                )

        return {
            "evaluated_count": evaluated,
            "matched_count": matched,
            "mismatched_count": mismatched,
            "error_count": errors,
            "examples": examples,
        }

    async def get_session_with_messages(
        self,
        session_id: UUID,
        org_id: Optional[UUID] = None,
        message_limit: int = 50,
    ) -> Optional[Dict[str, Any]]:
        """Get session with its recent messages."""

        session = await self._repository.get_session_with_relations(
            session_id=session_id,
            org_id=org_id,
        )

        if not session:
            return None

        # Get recent messages
        recent_messages = sorted(
            session.messages, key=lambda m: m.created_at, reverse=True
        )[:message_limit]

        return {
            "session": {
                "id": str(session.id),
                "org_id": str(session.org_id),
                "agent_type": session.agent_type.value,
                "title": session.title,
                "context": session.context,
                "created_at": session.created_at.isoformat(),
                "created_by": session.created_by,
                "status": (
                    session.status.value if hasattr(session, "status") else "active"
                ),
            },
            "messages": [
                {
                    "id": str(msg.id),
                    "role": msg.role.value,
                    "content": msg.content,
                    "created_at": msg.created_at.isoformat(),
                    "input_tokens": msg.input_tokens,
                    "output_tokens": msg.output_tokens,
                }
                for msg in recent_messages
            ],
            "tool_invocations": [
                {
                    "id": str(inv.id),
                    "tool_name": inv.tool_name,
                    "status": inv.status.value,
                    "started_at": inv.started_at.isoformat(),
                    "completed_at": (
                        inv.completed_at.isoformat() if inv.completed_at else None
                    ),
                    "error_message": inv.error_message,
                }
                for inv in session.tool_invocations
            ],
            "metrics": await self.runtime.get_session_metrics(session),
        }

    @staticmethod
    def _serialize_review_task(task) -> Dict[str, Any]:
        return {
            "id": str(task.id),
            "session_id": str(task.session_id),
            "org_id": str(task.org_id),
            "status": task.status.value,
            "title": task.title,
            "summary": task.summary,
            "payload": task.payload,
            "promotion_target": task.promotion_target,
            "priority": task.priority,
            "due_at": task.due_at.isoformat() if task.due_at else None,
            "escalated_to": task.escalated_to,
            "notification_channel": task.notification_channel,
            "ticket_reference": task.ticket_reference,
            "created_by": task.created_by,
            "created_at": task.created_at.isoformat(),
            "resolved_by": task.resolved_by,
            "resolved_at": task.resolved_at.isoformat() if task.resolved_at else None,
            "resolution_notes": task.resolution_notes,
        }

    async def delete_session(
        self,
        session_id: UUID,
        org_id: UUID,
        deleted_by: str,
    ) -> bool:
        """Delete an agent session (for development/testing only)."""
        deleted = await self._repository.delete_session(
            session_id=session_id, org_id=org_id
        )
        if deleted:
            logger.info(
                "Agent session deleted",
                session_id=session_id,
                org_id=org_id,
                deleted_by=deleted_by,
            )
        return deleted


class ToolApprovalService:
    """Service for managing tool approval workflows."""

    def __init__(self, repository: Optional[ToolApprovalRepository] = None) -> None:
        self._repository = repository or ToolApprovalRepository()

    async def list_pending_approvals(
        self,
        org_id: UUID,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[List[ToolApproval], int]:
        """List pending tool approvals for an organization."""

        approvals, total_count = await self._repository.list_pending(
            org_id,
            limit=limit,
            offset=offset,
        )
        return approvals, total_count

    async def get_approval(
        self,
        approval_id: UUID,
        org_id: UUID,
    ) -> Optional[ToolApproval]:
        """Get a specific tool approval."""

        return await self._repository.get(approval_id, org_id)

    async def approve_tool_invocation(
        self,
        approval_id: UUID,
        org_id: UUID,
        approved_by: str,
        decision_reason: Optional[str] = None,
    ) -> Optional[ToolApproval]:
        """Approve a tool invocation."""

        async with self._repository.approval_scope(approval_id, org_id) as (
            approval,
            db_session,
        ):
            if not approval or approval.status != ApprovalStatus.PENDING:
                return None

            if approval.expires_at and approval.expires_at < datetime.now(timezone.utc):
                approval.status = ApprovalStatus.EXPIRED
                return approval

            approval.status = ApprovalStatus.APPROVED
            approval.decided_by = approved_by
            approval.decided_at = datetime.now(timezone.utc)
            approval.decision_reason = decision_reason or "Approved by authorized user"

            # Update tool invocation status and re-execute if needed
            if approval.tool_invocation:
                from cerebro.agents.tools import tool_registry
                from cerebro.agents.tools.base import (
                    ToolExecutor,
                    AgentContext,
                    ToolPermissionLevel,
                )

                tool_invocation = approval.tool_invocation

                # Re-execute the tool with approval context
                tool = tool_registry.get(tool_invocation.tool_name)
                if tool:
                    # Build context with elevated permissions
                    execution_context = AgentContext(
                        session_id=tool_invocation.session_id,
                        org_id=org_id,
                        user_id=approved_by,
                        agent_type="approved_action",
                        permission_level=ToolPermissionLevel.WRITE_DESTRUCTIVE,  # Elevated for approved actions
                        cel_context={"approved": True, "approval_id": str(approval_id)},
                    )

                    # Execute the tool with original inputs but approval context
                    tool_executor = ToolExecutor()
                    try:
                        re_execution_result = await tool_executor.execute_tool(
                            tool=tool,
                            raw_inputs=tool_invocation.input_data,
                            context=execution_context,
                            dry_run=False,  # Execute for real since approved
                        )

                        # Update tool invocation with new results
                        tool_invocation.output_data = re_execution_result.model_dump()
                        tool_invocation.status = (
                            ToolInvocationStatus.SUCCESS
                            if re_execution_result.success
                            else ToolInvocationStatus.ERROR
                        )
                        tool_invocation.completed_at = datetime.now(timezone.utc)

                    except Exception as e:
                        logger.exception(
                            "Tool re-execution failed",
                            tool_name=tool_invocation.tool_name,
                            error=str(e),
                        )
                        tool_invocation.status = ToolInvocationStatus.ERROR
                        tool_invocation.error_message = f"Re-execution failed: {str(e)}"
                        tool_invocation.completed_at = datetime.now(timezone.utc)

            logger.info(
                "Tool invocation approved",
                approval_id=approval_id,
                tool_invocation_id=approval.tool_invocation_id,
                approved_by=approved_by,
            )

            return approval

    async def reject_tool_invocation(
        self,
        approval_id: UUID,
        org_id: UUID,
        rejected_by: str,
        decision_reason: str,
    ) -> Optional[ToolApproval]:
        """Reject a tool invocation."""

        async with self._repository.approval_scope(approval_id, org_id) as (
            approval,
            _,
        ):
            if not approval or approval.status != ApprovalStatus.PENDING:
                return None

            approval.status = ApprovalStatus.REJECTED
            approval.decided_by = rejected_by
            approval.decided_at = datetime.now(timezone.utc)
            approval.decision_reason = decision_reason

            logger.info(
                "Tool invocation rejected",
                approval_id=approval_id,
                tool_invocation_id=approval.tool_invocation_id,
                rejected_by=rejected_by,
                reason=decision_reason,
            )

            return approval


class AgentAnalyticsService:
    """Service for agent usage analytics and insights."""

    async def get_org_agent_usage(
        self,
        org_id: UUID,
        days: int = 30,
    ) -> Dict[str, Any]:
        """Get agent usage analytics for an organization."""

        from cerebro.core.database import async_session_factory

        async with async_session_factory() as db_session:
            from cerebro.analytics.sql_dialect import (
                get_dialect_name,
                minutes_between_expr,
            )

            cutoff = datetime.now(timezone.utc) - timedelta(days=max(days, 0))
            dialect = get_dialect_name(db_session)
            decision_minutes_expr = minutes_between_expr(
                start_expr="requested_at",
                end_expr="decided_at",
                dialect=dialect,
            )

            # Sessions by agent type with proper parameterization
            agent_type_stats = await db_session.execute(
                text(
                    """
                SELECT
                    agent_type,
                    COUNT(*) as session_count,
                    COUNT(DISTINCT created_by) as unique_users
                FROM agent_sessions
                WHERE org_id = :org_id
                    AND created_at >= :cutoff
                GROUP BY agent_type
                ORDER BY session_count DESC
                    """
                ),
                {"org_id": org_id, "cutoff": cutoff},
            )

            # Tool usage stats
            tool_stats = await db_session.execute(
                text(
                    """
                SELECT
                    ti.tool_name,
                    ti.status,
                    COUNT(*) as invocation_count
                FROM tool_invocations ti
                JOIN agent_sessions s ON ti.session_id = s.id
                WHERE s.org_id = :org_id
                    AND ti.started_at >= :cutoff
                GROUP BY ti.tool_name, ti.status
                ORDER BY invocation_count DESC
                    """
                ),
                {"org_id": org_id, "cutoff": cutoff},
            )

            # Token usage stats
            token_stats = await db_session.execute(
                text(
                    """
                SELECT
                    s.agent_type,
                    SUM(COALESCE(m.input_tokens, 0)) as total_input_tokens,
                    SUM(COALESCE(m.output_tokens, 0)) as total_output_tokens,
                    AVG(COALESCE(m.input_tokens, 0)) as avg_input_tokens,
                    AVG(COALESCE(m.output_tokens, 0)) as avg_output_tokens
                FROM agent_messages m
                JOIN agent_sessions s ON m.session_id = s.id
                WHERE s.org_id = :org_id
                    AND m.created_at >= :cutoff
                GROUP BY s.agent_type
                    """
                ),
                {"org_id": org_id, "cutoff": cutoff},
            )

            # Approval workflow stats
            approval_stats = await db_session.execute(
                text(
                    f"""
                SELECT
                    status,
                    COUNT(*) as count,
                    AVG({decision_minutes_expr}) as avg_decision_time_minutes
                FROM tool_approvals
                WHERE org_id = :org_id
                    AND requested_at >= :cutoff
                GROUP BY status
                    """
                ),
                {"org_id": org_id, "cutoff": cutoff},
            )

            return {
                "org_id": str(org_id),
                "analysis_period_days": days,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "agent_type_usage": [dict(row) for row in agent_type_stats.mappings()],
                "tool_usage": [dict(row) for row in tool_stats.mappings()],
                "token_usage": [dict(row) for row in token_stats.mappings()],
                "approval_workflow": [dict(row) for row in approval_stats.mappings()],
            }
