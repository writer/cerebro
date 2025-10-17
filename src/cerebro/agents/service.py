"""
Cerebro Agent Service

High-level service layer for managing agent sessions, orchestrating conversations,
and providing clean interfaces for API endpoints and CLI commands.
"""

from datetime import datetime, timezone, timedelta
from typing import Any, AsyncIterator, Dict, List, Optional
from uuid import UUID

import structlog
from sqlalchemy import select, text
from sqlalchemy.orm import selectinload

from cerebro.core.database import async_session_factory, get_db
from cerebro.agents.models import (
    AgentSession,
    AgentMessage,
    AgentMemoryEntry,
    AgentPolicySuggestion,
    AgentType,
    ReviewTaskStatus,
    ToolInvocation,
    ToolApproval,
    ApprovalStatus,
)
from cerebro.agents.runtime_facade import AgentRuntimeFacade
from cerebro.agents.review_service import AgentReviewService
from cerebro.agents.analytics_service import AgentAnalyticsService
from cerebro.agents.notification_service import NotificationService

logger = structlog.get_logger(__name__)


class AgentSessionService:
    """Service for managing agent sessions and conversations."""
    
    def __init__(self):
        self.runtime = AgentRuntimeFacade()
    
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
        
        from cerebro.core.database import async_session_factory
        async with async_session_factory() as db_session:
            query = select(AgentSession).where(AgentSession.id == session_id)
            
            if org_id:
                query = query.where(AgentSession.org_id == org_id)
            
            result = await db_session.execute(query)
            return result.scalar_one_or_none()
    
    async def list_sessions(
        self,
        org_id: UUID,
        agent_type: Optional[str] = None,
        created_by: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[List[AgentSession], int]:
        """List agent sessions for an organization."""
        
        from cerebro.core.database import async_session_factory
        async with async_session_factory() as db_session:
            # Build base query
            query = select(AgentSession).where(AgentSession.org_id == org_id)
            count_query = select(AgentSession.id).where(AgentSession.org_id == org_id)
            
            # Apply filters
            if agent_type:
                try:
                    agent_type_enum = AgentType(agent_type)
                    query = query.where(AgentSession.agent_type == agent_type_enum)
                    count_query = count_query.where(AgentSession.agent_type == agent_type_enum)
                except ValueError:
                    return [], 0
            
            if created_by:
                query = query.where(AgentSession.created_by == created_by)
                count_query = count_query.where(AgentSession.created_by == created_by)
            
            # Order by newest first
            query = query.order_by(AgentSession.created_at.desc())
            
            # Apply pagination
            query = query.limit(limit).offset(offset)
            
            # Execute queries
            sessions_result = await db_session.execute(query)
            sessions = sessions_result.scalars().all()
            
            count_result = await db_session.execute(count_query)
            total_count = len(count_result.scalars().all())
            
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

        from cerebro.core.database import async_session_factory

        async with async_session_factory() as db_session:
            stmt = (
                select(AgentMemoryEntry)
                .where(AgentMemoryEntry.session_id == session_id)
                .order_by(AgentMemoryEntry.created_at.desc())
                .limit(limit)
            )
            result = await db_session.execute(stmt)
            entries = result.scalars().all()

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

        from cerebro.core.database import async_session_factory

        async with async_session_factory() as db_session:
            stmt = select(AgentMemoryEntry).where(AgentMemoryEntry.session_id == session_id)
            result = await db_session.execute(stmt)
            entries = list(result.scalars())

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
                scope_distribution[scope_type] = scope_distribution.get(scope_type, 0) + 1

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
                    scope_labels.append(f"{scope_type}:{value}" if value else scope_type)

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
                "delivered_at": notification.delivered_at.isoformat() if notification.delivered_at else None,
            }
            for notification in notifications
        ]

    async def get_session_analytics(
        self,
        *,
        session_id: UUID,
        org_id: Optional[UUID] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        session = await self.get_session(session_id, org_id)
        if not session:
            return []
        return await AgentAnalyticsService.list_events(session_id=session_id, limit=limit)

    async def list_policy_suggestions(
        self,
        *,
        org_id: UUID,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        async with async_session_factory() as db_session:
            stmt = (
                select(AgentPolicySuggestion)
                .where(AgentPolicySuggestion.org_id == org_id)
                .order_by(AgentPolicySuggestion.support_count.desc())
                .limit(limit)
            )
            result = await db_session.execute(stmt)
            suggestions = result.scalars().all()

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

    async def get_session_with_messages(
        self,
        session_id: UUID,
        org_id: Optional[UUID] = None,
        message_limit: int = 50,
    ) -> Optional[Dict[str, Any]]:
        """Get session with its recent messages."""
        
        from cerebro.core.database import async_session_factory
        async with async_session_factory() as db_session:
            # Get session with related data
            query = (
                select(AgentSession)
                .options(selectinload(AgentSession.messages))
                .options(selectinload(AgentSession.tool_invocations))
                .where(AgentSession.id == session_id)
            )
            
            if org_id:
                query = query.where(AgentSession.org_id == org_id)
            
            result = await db_session.execute(query)
            session = result.scalar_one_or_none()
            
            if not session:
                return None
            
            # Get recent messages
            recent_messages = sorted(
                session.messages,
                key=lambda m: m.created_at,
                reverse=True
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
                        "completed_at": inv.completed_at.isoformat() if inv.completed_at else None,
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
        
        from cerebro.core.database import async_session_factory
        async with async_session_factory() as db_session:
            # Verify session exists and belongs to org
            session = await db_session.get(AgentSession, session_id)
            if not session or session.org_id != org_id:
                return False
            
            # In production, we would mark as deleted rather than actually delete
            # to maintain audit trail. For now, we'll actually delete.
            await db_session.delete(session)
            await db_session.commit()
            
            logger.info(
                "Agent session deleted",
                session_id=session_id,
                org_id=org_id,
                deleted_by=deleted_by,
            )
            
            return True


class ToolApprovalService:
    """Service for managing tool approval workflows."""
    
    async def list_pending_approvals(
        self,
        org_id: UUID,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[List[ToolApproval], int]:
        """List pending tool approvals for an organization."""
        
        from cerebro.core.database import async_session_factory
        async with async_session_factory() as db_session:
            # Get pending approvals
            query = (
                select(ToolApproval)
                .options(selectinload(ToolApproval.tool_invocation))
                .where(ToolApproval.org_id == org_id)
                .where(ToolApproval.status == ApprovalStatus.PENDING)
                .order_by(ToolApproval.requested_at.desc())
                .limit(limit)
                .offset(offset)
            )
            
            result = await db_session.execute(query)
            approvals = result.scalars().all()
            
            # Get total count
            count_query = (
                select(ToolApproval.id)
                .where(ToolApproval.org_id == org_id)
                .where(ToolApproval.status == ApprovalStatus.PENDING)
            )
            count_result = await db_session.execute(count_query)
            total_count = len(count_result.scalars().all())
            
            return list(approvals), total_count
    
    async def get_approval(
        self,
        approval_id: UUID,
        org_id: UUID,
    ) -> Optional[ToolApproval]:
        """Get a specific tool approval."""
        
        from cerebro.core.database import async_session_factory
        async with async_session_factory() as db_session:
            query = (
                select(ToolApproval)
                .options(selectinload(ToolApproval.tool_invocation))
                .where(ToolApproval.id == approval_id)
                .where(ToolApproval.org_id == org_id)
            )
            
            result = await db_session.execute(query)
            return result.scalar_one_or_none()
    
    async def approve_tool_invocation(
        self,
        approval_id: UUID,
        org_id: UUID,
        approved_by: str,
        decision_reason: Optional[str] = None,
    ) -> Optional[ToolApproval]:
        """Approve a tool invocation."""
        
        from cerebro.core.database import async_session_factory
        async with async_session_factory() as db_session:
            # Get approval
            approval = await self.get_approval(approval_id, org_id)
            if not approval or approval.status != ApprovalStatus.PENDING:
                return None
            
            # Check if not expired
            if approval.expires_at and approval.expires_at < datetime.now(timezone.utc):
                approval.status = ApprovalStatus.EXPIRED
                await db_session.commit()
                return approval
            
            # Update approval
            approval.status = ApprovalStatus.APPROVED
            approval.decided_by = approved_by
            approval.decided_at = datetime.now(timezone.utc)
            approval.decision_reason = decision_reason or "Approved by authorized user"
            
            # Update tool invocation status and re-execute if needed
            if approval.tool_invocation:
                from cerebro.agents.tools import tool_registry
                from cerebro.agents.tools.base import ToolExecutor, AgentContext, ToolPermissionLevel
                
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
                        cel_context={"approved": True, "approval_id": str(approval_id)}
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
                            ToolInvocationStatus.SUCCESS if re_execution_result.success
                            else ToolInvocationStatus.ERROR
                        )
                        tool_invocation.completed_at = datetime.now(timezone.utc)
                        
                    except Exception as e:
                        logger.exception("Tool re-execution failed", tool_name=tool_invocation.tool_name, error=str(e))
                        tool_invocation.status = ToolInvocationStatus.ERROR
                        tool_invocation.error_message = f"Re-execution failed: {str(e)}"
                        tool_invocation.completed_at = datetime.now(timezone.utc)
            
            await db_session.commit()
            
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
        
        from cerebro.core.database import async_session_factory
        async with async_session_factory() as db_session:
            # Get approval
            approval = await self.get_approval(approval_id, org_id)
            if not approval or approval.status != ApprovalStatus.PENDING:
                return None
            
            # Update approval
            approval.status = ApprovalStatus.REJECTED
            approval.decided_by = rejected_by
            approval.decided_at = datetime.now(timezone.utc)
            approval.decision_reason = decision_reason
            
            await db_session.commit()
            
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
            # Sessions by agent type with proper parameterization
            agent_type_stats = await db_session.execute(
                text("""
                SELECT 
                    agent_type,
                    COUNT(*) as session_count,
                    COUNT(DISTINCT created_by) as unique_users
                FROM agent_sessions 
                WHERE org_id = :org_id
                    AND created_at >= NOW() - (:days || ' days')::interval
                GROUP BY agent_type
                ORDER BY session_count DESC
                """),
                {"org_id": org_id, "days": days}
            )
            
            # Tool usage stats
            tool_stats = await db_session.execute(
                text("""
                SELECT 
                    ti.tool_name,
                    ti.status,
                    COUNT(*) as invocation_count
                FROM tool_invocations ti
                JOIN agent_sessions s ON ti.session_id = s.id
                WHERE s.org_id = :org_id
                    AND ti.started_at >= NOW() - (:days || ' days')::interval
                GROUP BY ti.tool_name, ti.status
                ORDER BY invocation_count DESC
                """),
                {"org_id": org_id, "days": days}
            )
            
            # Token usage stats  
            token_stats = await db_session.execute(
                text("""
                SELECT 
                    s.agent_type,
                    SUM(COALESCE(m.input_tokens, 0)) as total_input_tokens,
                    SUM(COALESCE(m.output_tokens, 0)) as total_output_tokens,
                    AVG(COALESCE(m.input_tokens, 0)) as avg_input_tokens,
                    AVG(COALESCE(m.output_tokens, 0)) as avg_output_tokens
                FROM agent_messages m
                JOIN agent_sessions s ON m.session_id = s.id
                WHERE s.org_id = :org_id
                    AND m.created_at >= NOW() - (:days || ' days')::interval
                GROUP BY s.agent_type
                """),
                {"org_id": org_id, "days": days}
            )
            
            # Approval workflow stats
            approval_stats = await db_session.execute(
                text("""
                SELECT 
                    status,
                    COUNT(*) as count,
                    AVG(EXTRACT(EPOCH FROM (decided_at - requested_at))/60) as avg_decision_time_minutes
                FROM tool_approvals
                WHERE org_id = :org_id
                    AND requested_at >= NOW() - (:days || ' days')::interval
                GROUP BY status
                """),
                {"org_id": org_id, "days": days}
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
