"""
Agent API Endpoints

Provides REST API for Claude agent sessions with streaming support.
Enables users to create agent sessions, send messages, and receive real-time
responses with tool execution capabilities.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse
import structlog
import json

from cerebro.api.auth import User, get_current_user
from cerebro.agents.service import AgentSessionService
from cerebro.agents.models import AgentType

logger = structlog.get_logger(__name__)
router = APIRouter()

# Pydantic Models

class CreateSessionRequest(BaseModel):
    """Request to create a new agent session."""
    agent_type: str = Field(
        ...,
        description="Type of agent to create",
        examples=["security_analyst", "incident_responder"]
    )
    title: Optional[str] = Field(
        None,
        description="Optional title for the session",
        max_length=255
    )
    context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Context for the session (finding IDs, provider scope, etc.)"
    )


class SessionResponse(BaseModel):
    """Response containing session information."""
    session_id: UUID
    org_id: UUID
    agent_type: str
    title: Optional[str]
    created_at: datetime
    created_by: str
    status: str
    context: Dict[str, Any]

    class Config:
        from_attributes = True


class SendMessageRequest(BaseModel):
    """Request to send a message to an agent session."""
    message: str = Field(
        ...,
        description="Message to send to the agent",
        min_length=1,
        max_length=10000
    )
    stream: bool = Field(
        default=True,
        description="Whether to stream the response using SSE"
    )


class MessageResponse(BaseModel):
    """Response containing a single message."""
    message_id: UUID
    role: str
    content: str
    timestamp: datetime
    metadata: Optional[Dict[str, Any]] = None


class SessionListResponse(BaseModel):
    """Response containing list of sessions."""
    sessions: List[SessionResponse]
    total: int
    limit: int
    offset: int


class SessionWithMessagesResponse(BaseModel):
    """Response containing session with message history."""
    session: SessionResponse
    messages: List[MessageResponse]
    message_count: int
    tool_invocations: List["ToolInvocationResponse"] = Field(default_factory=list)
    metrics: Dict[str, Any] = Field(default_factory=dict)


class ToolInvocationResponse(BaseModel):
    id: UUID
    tool_name: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime]
    error_message: Optional[str]


SessionWithMessagesResponse.model_rebuild()


class MemoryEntryResponse(BaseModel):
    """Response containing a single memory entry."""

    id: UUID
    role: Optional[str]
    summary: Optional[str]
    decay_score: float
    last_accessed_at: datetime
    created_at: datetime
    scopes: List[Dict[str, Any]]
    scope_labels: List[str]
    metadata: Dict[str, Any]
    token_count: int
    content: Optional[str] = None
    embedding_similarity: Optional[float] = None
    lexical_similarity: Optional[float] = None
    combined_similarity: Optional[float] = None
    ann_selected: Optional[bool] = None


class MemoryHighlightResponse(BaseModel):
    id: UUID
    summary: Optional[str]
    role: Optional[str]
    decay_score: float
    last_accessed_at: datetime
    scope_labels: List[str]


class MemoryStatsResponse(BaseModel):
    total_entries: int
    recent_entries: int
    presented_entries: int
    average_decay: float
    token_total: int
    role_distribution: Dict[str, int]
    scope_distribution: Dict[str, int]
    top_memories: List[MemoryHighlightResponse]


class ReviewTaskResponse(BaseModel):
    """Response model for review queue items."""

    id: UUID
    session_id: UUID
    org_id: UUID
    status: str
    title: str
    summary: Optional[str]
    payload: Dict[str, Any]
    promotion_target: Optional[str]
    priority: Optional[str]
    due_at: Optional[datetime]
    escalated_to: Optional[str]
    notification_channel: Optional[str]
    ticket_reference: Optional[str]
    created_by: str
    created_at: datetime
    resolved_by: Optional[str]
    resolved_at: Optional[datetime]
    resolution_notes: Optional[str]


class ResolveReviewTaskRequest(BaseModel):
    status: str = Field(..., description="New status for the review task")
    notes: Optional[str] = Field(None, description="Optional resolution notes")


class BulkReviewUpdateRequest(BaseModel):
    task_ids: List[UUID]
    status: Optional[str] = Field(None, description="Status to apply to selected tasks")
    notes: Optional[str] = None
    escalated_to: Optional[str] = Field(None, description="Escalation target identifier")
    due_at: Optional[datetime] = Field(None, description="Optional due date for review completion")
    priority: Optional[str] = Field(None, description="Priority label")
    notification_channel: Optional[str] = Field(None, description="Channel for notifications (e.g. slack:#alerts)")
    ticket_system: Optional[str] = Field(None, description="External ticket system identifier")
    ticket_summary: Optional[str] = Field(None, description="Summary used when creating an external ticket")
    ticket_metadata: Optional[Dict[str, Any]] = Field(None, description="Additional ticket metadata")


class ReviewNotificationResponse(BaseModel):
    id: UUID
    task_id: UUID
    org_id: UUID
    channel: str
    status: str
    payload: Dict[str, Any]
    created_at: datetime
    delivered_at: Optional[datetime]


class RuntimeEventResponse(BaseModel):
    id: UUID
    event_type: str
    payload: Dict[str, Any]
    created_at: datetime


class PolicySuggestionResponse(BaseModel):
    id: UUID
    tool_name: str
    cel_expression: str
    support_count: int
    reject_count: int
    confidence: float
    metadata: Dict[str, Any]
    last_seen: datetime


class PolicySimulationExample(BaseModel):
    invocation_id: UUID
    session_id: UUID
    tool_name: str
    matched: bool
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    input_data: Dict[str, Any]
    output_data: Optional[Dict[str, Any]]
    cel_context: Dict[str, Any]
    error: Optional[str]
    latency_ms: Optional[float]


class PolicySimulationResponse(BaseModel):
    evaluated_count: int
    matched_count: int
    mismatched_count: int
    error_count: int
    examples: List[PolicySimulationExample]


class PolicySimulationRequest(BaseModel):
    expression: str = Field(..., min_length=3, description="CEL expression to evaluate")
    tool_name: Optional[str] = Field(None, description="Filter to a specific tool name")
    limit: int = Field(50, ge=1, le=200, description="Number of recent invocations to evaluate")


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _review_task_to_response(data: Dict[str, Any]) -> ReviewTaskResponse:
    return ReviewTaskResponse(
        id=UUID(data["id"]),
        session_id=UUID(data["session_id"]),
        org_id=UUID(data["org_id"]),
        status=data["status"],
        title=data["title"],
        summary=data.get("summary"),
        payload=data.get("payload", {}),
        promotion_target=data.get("promotion_target"),
        priority=data.get("priority"),
        due_at=_parse_datetime(data.get("due_at")),
        escalated_to=data.get("escalated_to"),
        notification_channel=data.get("notification_channel"),
        ticket_reference=data.get("ticket_reference"),
        created_by=data.get("created_by", ""),
        created_at=_parse_datetime(data.get("created_at")) or datetime.now(),
        resolved_by=data.get("resolved_by"),
        resolved_at=_parse_datetime(data.get("resolved_at")),
        resolution_notes=data.get("resolution_notes"),
    )


def _notification_to_response(data: Dict[str, Any]) -> ReviewNotificationResponse:
    return ReviewNotificationResponse(
        id=UUID(data["id"]),
        task_id=UUID(data["task_id"]),
        org_id=UUID(data["org_id"]),
        channel=data["channel"],
        status=data["status"],
        payload=data.get("payload", {}),
        created_at=_parse_datetime(data.get("created_at")) or datetime.now(),
        delivered_at=_parse_datetime(data.get("delivered_at")),
    )


def _runtime_event_to_response(data: Dict[str, Any]) -> RuntimeEventResponse:
    return RuntimeEventResponse(
        id=UUID(data["id"]),
        event_type=data["event_type"],
        payload=data.get("payload", {}),
        created_at=_parse_datetime(data.get("created_at")) or datetime.now(),
    )


def _policy_suggestion_to_response(data: Dict[str, Any]) -> PolicySuggestionResponse:
    return PolicySuggestionResponse(
        id=UUID(data["id"]),
        tool_name=data["tool_name"],
        cel_expression=data["cel_expression"],
        support_count=data.get("support_count", 0),
        reject_count=data.get("reject_count", 0),
        confidence=float(data.get("confidence", 0.0)),
        metadata=data.get("metadata", {}),
        last_seen=_parse_datetime(data.get("last_seen")) or datetime.now(),
    )


# API Endpoints

@router.post("/sessions", response_model=SessionResponse, status_code=201)
async def create_agent_session(
    request: CreateSessionRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Create a new agent session.

    The agent session maintains conversation context and enables multi-turn
    interactions with tool execution capabilities.
    """
    service = AgentSessionService()

    try:
        session = await service.create_session(
            org_id=current_user.org_id,
            agent_type=request.agent_type,
            created_by=current_user.user_id,
            context=request.context,
            title=request.title,
        )

        return SessionResponse(
            session_id=session.id,
            org_id=session.org_id,
            agent_type=session.agent_type.value,
            title=session.title,
            created_at=session.created_at,
            created_by=session.created_by,
            status=session.status.value,
            context=session.context,
        )

    except ValueError as e:
        logger.warning("Invalid agent session request", error=str(e), user=current_user.user_id)
        raise HTTPException(status_code=400, detail=str(e))

    except Exception as e:
        logger.exception("Failed to create agent session", error=str(e), user=current_user.user_id)
        raise HTTPException(status_code=500, detail="Failed to create agent session")


@router.get("/sessions", response_model=SessionListResponse)
async def list_agent_sessions(
    agent_type: Optional[str] = Query(None, description="Filter by agent type"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of sessions to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    current_user: User = Depends(get_current_user),
):
    """
    List agent sessions for the current user's organization.

    Supports filtering by agent type and pagination.
    """
    service = AgentSessionService()

    try:
        sessions, total = await service.list_sessions(
            org_id=current_user.org_id,
            agent_type=agent_type,
            created_by=None,  # Show all sessions in org for now
            limit=limit,
            offset=offset,
        )

        return SessionListResponse(
            sessions=[
                SessionResponse(
                    session_id=s.id,
                    org_id=s.org_id,
                    agent_type=s.agent_type.value,
                    title=s.title,
                    created_at=s.created_at,
                    created_by=s.created_by,
                    status=s.status.value,
                    context=s.context,
                )
                for s in sessions
            ],
            total=total,
            limit=limit,
            offset=offset,
        )

    except Exception as e:
        logger.exception("Failed to list agent sessions", error=str(e), user=current_user.user_id)
        raise HTTPException(status_code=500, detail="Failed to list agent sessions")


@router.get("/sessions/{session_id}", response_model=SessionWithMessagesResponse)
async def get_agent_session(
    session_id: UUID,
    message_limit: int = Query(50, ge=1, le=200, description="Maximum number of messages to return"),
    current_user: User = Depends(get_current_user),
):
    """
    Get an agent session with its message history.

    Returns full session details including recent messages and tool invocations.
    """
    service = AgentSessionService()

    try:
        session_data = await service.get_session_with_messages(
            session_id=session_id,
            org_id=current_user.org_id,
            message_limit=message_limit,
        )

        if not session_data:
            raise HTTPException(status_code=404, detail="Session not found or access denied")

        session_dict = session_data["session"]
        messages = session_data["messages"]

        tool_invocations = session_data.get("tool_invocations", [])
        metrics = session_data.get("metrics", {})

        return SessionWithMessagesResponse(
            session=SessionResponse(
                session_id=UUID(session_dict["id"]),
                org_id=UUID(session_dict["org_id"]),
                agent_type=session_dict["agent_type"],
                title=session_dict.get("title"),
                created_at=datetime.fromisoformat(session_dict["created_at"]),
                created_by=session_dict["created_by"],
                status=session_dict.get("status", "active"),
                context=session_dict.get("context", {}),
            ),
            messages=[
                MessageResponse(
                    message_id=UUID(m["id"]),
                    role=m["role"],
                    content=m["content"],
                    timestamp=datetime.fromisoformat(m["created_at"]),
                    metadata=m.get("metadata"),
                )
                for m in messages
            ],
            message_count=len(messages),
            tool_invocations=[
                ToolInvocationResponse(
                    id=UUID(inv["id"]),
                    tool_name=inv["tool_name"],
                    status=inv["status"],
                    started_at=datetime.fromisoformat(inv["started_at"]),
                    completed_at=datetime.fromisoformat(inv["completed_at"])
                    if inv.get("completed_at")
                    else None,
                    error_message=inv.get("error_message"),
                )
                for inv in tool_invocations
            ],
            metrics=metrics or {},
        )

    except HTTPException:
        raise

    except Exception as e:
        logger.exception("Failed to get agent session", session_id=session_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get agent session")


@router.post("/sessions/{session_id}/messages")
async def send_message_to_agent(
    session_id: UUID,
    request: SendMessageRequest,
    req: Request,
    current_user: User = Depends(get_current_user),
):
    """
    Send a message to an agent session.

    Supports streaming responses via Server-Sent Events (SSE) for real-time
    updates as the agent processes the message and executes tools.

    When stream=true, returns SSE stream with events:
    - message_start: Agent begins responding
    - content_delta: Incremental text content
    - tool_use: Agent is calling a tool
    - tool_result: Tool execution result
    - message_complete: Agent finished responding
    - error: An error occurred
    """
    service = AgentSessionService()

    if not request.stream:
        # Non-streaming response - collect all events
        response_content = []
        tool_calls = []
        error = None

        try:
            async for event in service.send_message(
                session_id=session_id,
                message=request.message,
                user_id=current_user.user_id,
                org_id=current_user.org_id,
                stream=False,
            ):
                if event.get("type") == "error":
                    error = event.get("content", {}).get("message", "Unknown error")
                    break
                elif event.get("type") == "content":
                    response_content.append(event.get("content", ""))
                elif event.get("type") == "tool_use":
                    tool_calls.append(event)

        except Exception as e:
            logger.exception("Error sending message", session_id=session_id, error=str(e))
            raise HTTPException(status_code=500, detail="Failed to send message")

        if error:
            raise HTTPException(status_code=400, detail=error)

        return {
            "session_id": str(session_id),
            "response": "".join(response_content),
            "tool_calls": tool_calls,
        }

    else:
        # Streaming response using SSE
        async def event_generator():
            """Generate SSE events from agent responses."""
            try:
                async for event in service.send_message(
                    session_id=session_id,
                    message=request.message,
                    user_id=current_user.user_id,
                    org_id=current_user.org_id,
                    stream=True,
                ):
                    # Convert event to SSE format
                    event_type = event.get("type", "unknown")
                    event_data = {
                        "type": event_type,
                        "content": event.get("content"),
                        "metadata": event.get("metadata", {}),
                    }

                    yield {
                        "event": event_type,
                        "data": json.dumps(event_data),
                    }

                    # Check if client disconnected
                    if await req.is_disconnected():
                        logger.info("Client disconnected", session_id=session_id)
                        break

                # Send completion event
                yield {
                    "event": "complete",
                    "data": json.dumps({"type": "complete"}),
                }

            except Exception as e:
                logger.exception("Error in SSE stream", session_id=session_id, error=str(e))
                yield {
                    "event": "error",
                    "data": json.dumps({
                        "type": "error",
                        "content": {"message": "Stream error occurred"},
                    }),
                }

        return EventSourceResponse(event_generator())


@router.get("/sessions/{session_id}/messages", response_model=List[MessageResponse])
async def get_session_messages(
    session_id: UUID,
    limit: int = Query(100, ge=1, le=500, description="Maximum number of messages to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    current_user: User = Depends(get_current_user),
):
    """
    Get message history for an agent session.

    Returns messages in chronological order with pagination support.
    """
    service = AgentSessionService()

    try:
        messages = await service.get_session_messages(
            session_id=session_id,
            org_id=current_user.org_id,
            limit=limit,
            offset=offset,
        )

        return [
            MessageResponse(
                message_id=m["id"],
                role=m["role"],
                content=m["content"],
                timestamp=m["timestamp"],
                metadata=m.get("metadata"),
            )
            for m in messages
        ]

    except Exception as e:
        logger.exception("Failed to get session messages", session_id=session_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get session messages")


@router.get("/sessions/{session_id}/memory", response_model=List[MemoryEntryResponse])
async def get_session_memory_entries(
    session_id: UUID,
    limit: int = Query(50, ge=1, le=200, description="Maximum memory entries to return"),
    include_content: bool = Query(False, description="Include full memory content in response"),
    current_user: User = Depends(get_current_user),
):
    """List memory entries associated with an agent session."""

    service = AgentSessionService()

    try:
        entries = await service.get_session_memory(
            session_id=session_id,
            org_id=current_user.org_id,
            limit=limit,
            include_content=include_content,
        )

        if entries is None:
            raise HTTPException(status_code=404, detail="Session not found or access denied")

        return [
            MemoryEntryResponse(
                id=UUID(entry["id"]),
                role=entry["role"],
                summary=entry.get("summary"),
                decay_score=entry["decay_score"],
                last_accessed_at=datetime.fromisoformat(entry["last_accessed_at"]),
                created_at=datetime.fromisoformat(entry["created_at"]),
                scopes=entry.get("scopes", []),
                scope_labels=entry.get("scope_labels", []),
                metadata=entry.get("metadata", {}),
                token_count=entry.get("token_count", 0),
                content=entry.get("content"),
                embedding_similarity=entry.get("embedding_similarity"),
                lexical_similarity=entry.get("lexical_similarity"),
                combined_similarity=entry.get("combined_similarity"),
                ann_selected=entry.get("ann_selected"),
            )
            for entry in entries
        ]

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to get session memory", session_id=session_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get session memory entries")


@router.get("/sessions/{session_id}/memory/stats", response_model=MemoryStatsResponse)
async def get_session_memory_stats(
    session_id: UUID,
    current_user: User = Depends(get_current_user),
):
    service = AgentSessionService()
    stats = await service.get_session_memory_stats(
        session_id=session_id,
        org_id=current_user.org_id,
    )
    if stats is None:
        raise HTTPException(status_code=404, detail="Session not found or access denied")
    return MemoryStatsResponse(**stats)


@router.get("/review-tasks", response_model=List[ReviewTaskResponse])
async def list_review_tasks(
    status: Optional[str] = Query(None, description="Filter by review status"),
    limit: int = Query(50, ge=1, le=200, description="Maximum number of tasks to return"),
    current_user: User = Depends(get_current_user),
):
    """Return review tasks awaiting human decisions."""

    service = AgentSessionService()
    tasks = await service.list_review_tasks(
        org_id=current_user.org_id,
        status=status,
        limit=limit,
    )
    return [_review_task_to_response(task) for task in tasks]


@router.post("/review-tasks/{task_id}/resolve", response_model=ReviewTaskResponse)
async def resolve_review_task(
    task_id: UUID,
    request: ResolveReviewTaskRequest,
    current_user: User = Depends(get_current_user),
):
    """Resolve a review task by approving, rejecting, or promoting it."""

    service = AgentSessionService()
    task = await service.resolve_review_task(
        task_id=task_id,
        resolved_by=current_user.user_id,
        status=request.status,
        notes=request.notes,
    )
    if task is None:
        raise HTTPException(status_code=404, detail="Review task not found")

    return _review_task_to_response(task)


@router.post("/review-tasks/bulk-update", response_model=List[ReviewTaskResponse])
async def bulk_update_review_tasks(
    request: BulkReviewUpdateRequest,
    current_user: User = Depends(get_current_user),
):
    """Apply bulk status updates, escalations, or ticket actions to review tasks."""

    service = AgentSessionService()
    tasks = await service.bulk_update_review_tasks(
        org_id=current_user.org_id,
        task_ids=request.task_ids,
        status=request.status,
        resolved_by=current_user.user_id,
        notes=request.notes,
        escalated_to=request.escalated_to,
        due_at=request.due_at,
        priority=request.priority,
        notification_channel=request.notification_channel,
        ticket_system=request.ticket_system,
        ticket_summary=request.ticket_summary,
        ticket_metadata=request.ticket_metadata,
    )
    return [_review_task_to_response(task) for task in tasks]


@router.post("/review-tasks/{task_id}/assign", response_model=ReviewTaskResponse)
async def assign_review_task(
    task_id: UUID,
    assigned_to: str = Field(..., description="Username or email to assign to"),
    current_user: User = Depends(get_current_user),
):
    """Assign a review task to a user."""
    from cerebro.agents.review_service import AgentReviewService
    
    task = await AgentReviewService.assign_task(
        task_id=task_id,
        assigned_to=assigned_to,
        assigned_by=current_user.username,
    )
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return _review_task_to_response(task)


@router.post("/review-tasks/{task_id}/comments", response_model=Dict[str, Any])
async def add_task_comment(
    task_id: UUID,
    content: str = Field(..., min_length=1, max_length=5000, description="Comment content"),
    metadata: Optional[Dict[str, Any]] = None,
    current_user: User = Depends(get_current_user),
):
    """Add a comment to a review task."""
    from cerebro.agents.review_service import AgentReviewService
    
    comment = await AgentReviewService.add_comment(
        task_id=task_id,
        author=current_user.username,
        content=content,
        metadata=metadata,
    )
    if not comment:
        raise HTTPException(status_code=404, detail="Task not found")
    
    return {
        "id": str(comment.id),
        "task_id": str(comment.task_id),
        "author": comment.author,
        "content": comment.content,
        "created_at": comment.created_at.isoformat(),
        "updated_at": comment.updated_at.isoformat() if comment.updated_at else None,
        "metadata": comment.metadata,
    }


@router.get("/review-tasks/{task_id}/comments", response_model=List[Dict[str, Any]])
async def get_task_comments(
    task_id: UUID,
    limit: int = Query(100, ge=1, le=500, description="Maximum comments to return"),
    current_user: User = Depends(get_current_user),
):
    """Get all comments for a review task."""
    from cerebro.agents.review_service import AgentReviewService
    
    comments = await AgentReviewService.get_comments(
        task_id=task_id,
        limit=limit,
    )
    
    return [
        {
            "id": str(comment.id),
            "task_id": str(comment.task_id),
            "author": comment.author,
            "content": comment.content,
            "created_at": comment.created_at.isoformat(),
            "updated_at": comment.updated_at.isoformat() if comment.updated_at else None,
            "metadata": comment.metadata,
        }
        for comment in comments
    ]


@router.get("/review-tasks/{task_id}/history", response_model=List[Dict[str, Any]])
async def get_task_history(
    task_id: UUID,
    limit: int = Query(100, ge=1, le=500, description="Maximum history records to return"),
    current_user: User = Depends(get_current_user),
):
    """Get change history for a review task."""
    from cerebro.agents.review_service import AgentReviewService
    
    history = await AgentReviewService.get_history(
        task_id=task_id,
        limit=limit,
    )
    
    return [
        {
            "id": str(record.id),
            "task_id": str(record.task_id),
            "changed_by": record.changed_by,
            "change_type": record.change_type,
            "field_name": record.field_name,
            "old_value": record.old_value,
            "new_value": record.new_value,
            "created_at": record.created_at.isoformat(),
            "metadata": record.metadata,
        }
        for record in history
    ]


@router.get("/review-tasks/sla/summary", response_model=Dict[str, Any])
async def get_sla_summary(
    current_user: User = Depends(get_current_user),
):
    """Get SLA compliance summary for all pending tasks."""
    from cerebro.agents.sla_service import SLAService
    
    summary = await SLAService.get_sla_summary(org_id=current_user.org_id)
    return summary


@router.get("/review-tasks/sla/breached", response_model=List[Dict[str, Any]])
async def get_breached_tasks(
    current_user: User = Depends(get_current_user),
):
    """Get all tasks that have breached their SLA."""
    from cerebro.agents.sla_service import SLAService
    
    breached = await SLAService.get_breached_tasks(org_id=current_user.org_id)
    return [status.to_dict() for status in breached]


@router.get("/review-tasks/sla/at-risk", response_model=List[Dict[str, Any]])
async def get_at_risk_tasks(
    current_user: User = Depends(get_current_user),
):
    """Get all tasks at risk of breaching SLA."""
    from cerebro.agents.sla_service import SLAService
    
    at_risk = await SLAService.get_at_risk_tasks(org_id=current_user.org_id)
    return [status.to_dict() for status in at_risk]


@router.get("/review-tasks/notifications", response_model=List[ReviewNotificationResponse])
async def list_review_notifications(
    status: Optional[str] = Query(None, description="Filter notifications by status"),
    limit: int = Query(100, ge=1, le=500, description="Maximum notification records to return"),
    current_user: User = Depends(get_current_user),
):
    service = AgentSessionService()
    notifications = await service.list_review_notifications(
        org_id=current_user.org_id,
        status=status,
        limit=limit,
    )
    return [_notification_to_response(notification) for notification in notifications]


@router.get("/sessions/{session_id}/analytics", response_model=List[RuntimeEventResponse])
async def get_session_analytics(
    session_id: UUID,
    limit: int = Query(100, ge=1, le=500, description="Maximum analytics events to return"),
    current_user: User = Depends(get_current_user),
):
    service = AgentSessionService()
    events = await service.get_session_analytics(
        session_id=session_id,
        org_id=current_user.org_id,
        limit=limit,
    )
    return [_runtime_event_to_response(event) for event in events]


@router.get("/policy-suggestions", response_model=List[PolicySuggestionResponse])
async def list_policy_suggestions(
    limit: int = Query(50, ge=1, le=200, description="Maximum policy suggestions to return"),
    current_user: User = Depends(get_current_user),
):
    service = AgentSessionService()
    suggestions = await service.list_policy_suggestions(
        org_id=current_user.org_id,
        limit=limit,
    )
    return [_policy_suggestion_to_response(item) for item in suggestions]


@router.post("/policy-suggestions/simulate", response_model=PolicySimulationResponse)
async def simulate_policy_expression(
    request: PolicySimulationRequest,
    current_user: User = Depends(get_current_user),
):
    service = AgentSessionService()
    try:
        result = await service.simulate_policy_expression(
            org_id=current_user.org_id,
            expression=request.expression,
            tool_name=request.tool_name,
            limit=request.limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return PolicySimulationResponse(**result)


# Health check for agent system
@router.get("/health")
async def agent_health():
    """
    Health check for agent system.

    Verifies that the agent runtime and SDK integration are operational.
    """
    try:
        service = AgentSessionService()
        # Basic check that service initializes
        return {
            "status": "healthy",
            "runtime": "operational",
            "sdk_integration": "active",
        }
    except Exception as e:
        logger.exception("Agent health check failed", error=str(e))
        raise HTTPException(status_code=503, detail="Agent system unavailable")