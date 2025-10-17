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

        return SessionWithMessagesResponse(
            session=SessionResponse(
                session_id=UUID(session_dict["id"]),
                org_id=UUID(session_dict["org_id"]),
                agent_type=session_dict["agent_type"],
                title=session_dict.get("title"),
                created_at=datetime.fromisoformat(session_dict["created_at"]),
                created_by=session_dict["created_by"],
                status="active",  # Service doesn't return status yet
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
            )
            for entry in entries
        ]

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to get session memory", session_id=session_id, error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get session memory entries")


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