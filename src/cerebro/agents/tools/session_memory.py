"""
Session Memory Tools

Enables agents to remember context across sessions and retrieve conversation history.
"""

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import structlog
from pydantic import BaseModel, Field
from sqlalchemy import select, and_, or_
from sqlalchemy.orm import selectinload

from cerebro.agents.tools.base import (
    StructuredTool,
    ToolResult,
    AgentContext,
    ToolPermissionLevel,
)
from cerebro.agents.models import AgentSessionContext, AgentSession
from cerebro.core.database import async_session_factory

logger = structlog.get_logger(__name__)


# ==================== Input/Output Schemas ====================


class RememberContextInput(BaseModel):
    """Input for remember_context tool."""

    context_key: str = Field(
        description="Unique key for this context (e.g. 'prod_aws_account_id', 'ceo_name')",
        min_length=1,
        max_length=255,
    )
    context_value: Dict[str, Any] = Field(
        description="Value to remember (can be any JSON structure)",
    )
    context_type: str = Field(
        description="Type of context: user_preference, learned_fact, correction, environment",
        pattern="^(user_preference|learned_fact|correction|environment)$",
    )
    learned_from: str = Field(
        description="How was this learned: user_conversation, tool_execution, external_source",
        pattern="^(user_conversation|tool_execution|external_source)$",
    )
    confidence: Optional[float] = Field(
        default=1.0,
        description="Confidence score 0-1 for learned facts",
        ge=0.0,
        le=1.0,
    )
    expires_in_days: Optional[int] = Field(
        default=None,
        description="Optional: expire this context after N days",
        gt=0,
    )


class RememberContextOutput(BaseModel):
    """Output for remember_context tool."""

    success: bool
    context_id: Optional[str]
    message: str
    previous_value: Optional[Dict[str, Any]] = None  # If key already existed


class GetSessionHistoryInput(BaseModel):
    """Input for get_session_history tool."""

    lookback_sessions: int = Field(
        default=5,
        description="Number of recent sessions to retrieve",
        ge=1,
        le=20,
    )
    include_messages: bool = Field(
        default=True,
        description="Include message content from sessions",
    )
    context_keys: Optional[List[str]] = Field(
        default=None,
        description="Optional: filter to specific context keys",
    )


class SessionInfo(BaseModel):
    """Information about a session."""

    session_id: str
    agent_type: str
    title: Optional[str]
    created_at: str
    message_count: int
    recent_messages: List[Dict[str, Any]] = []
    learned_context: List[Dict[str, Any]] = []


class GetSessionHistoryOutput(BaseModel):
    """Output for get_session_history tool."""

    success: bool
    org_name: str
    sessions_retrieved: int
    sessions: List[SessionInfo]
    total_context_entries: int
    common_context_keys: List[str]


# ==================== Tools ====================


class RememberContextTool(StructuredTool):
    """
    Store context that should persist across agent sessions.

    Examples:
    - User preferences: "Summarize findings for our CEO" → remember audience
    - Environment facts: "AWS account 123456789012 is production" → remember mapping
    - Corrections: "Don't use technical jargon" → remember communication style
    - Custom mappings: "Project Apollo uses eu-west-1" → remember project info
    """

    tool_name = "remember_context"
    tool_description = """Store information that should be remembered across agent sessions.
Use this to save user preferences, environment facts, corrections, or any context that
will be useful in future conversations. This enables continuity and personalization."""

    tool_version = "1.0.0"
    input_model = RememberContextInput
    output_model = RememberContextOutput
    required_permission = (
        ToolPermissionLevel.WRITE_SAFE
    )  # Can write context but not destructive

    async def _run(
        self,
        context: AgentContext,
        context_key: str,
        context_value: Dict[str, Any],
        context_type: str,
        learned_from: str,
        confidence: float = 1.0,
        expires_in_days: Optional[int] = None,
    ) -> ToolResult:
        """Store context for cross-session memory."""

        try:
            async with async_session_factory() as db_session:
                # Check if context already exists for this org + key
                existing_query = (
                    select(AgentSessionContext)
                    .where(
                        and_(
                            AgentSessionContext.org_id == context.org_id,
                            AgentSessionContext.context_key == context_key,
                        )
                    )
                    .order_by(AgentSessionContext.created_at.desc())
                )

                result = await db_session.execute(existing_query)
                existing = result.scalar_one_or_none()

                previous_value = None
                if existing:
                    previous_value = existing.context_value
                    logger.info(
                        "Updating existing context",
                        org_id=context.org_id,
                        context_key=context_key,
                        previous_value=previous_value,
                    )

                # Calculate expiration
                expires_at = None
                if expires_in_days:
                    expires_at = datetime.now(timezone.utc) + timedelta(
                        days=expires_in_days
                    )

                # Create new context entry
                new_context = AgentSessionContext(
                    session_id=context.session_id,
                    org_id=context.org_id,
                    context_key=context_key,
                    context_value=context_value,
                    context_type=context_type,
                    learned_from=learned_from,
                    confidence=confidence,
                    expires_at=expires_at,
                    created_by=context.user_id,
                    metadata={
                        "agent_type": context.agent_type,
                        "replaced_existing": (existing is not None),
                    },
                )

                db_session.add(new_context)
                await db_session.commit()
                await db_session.refresh(new_context)

                output = RememberContextOutput(
                    success=True,
                    context_id=str(new_context.id),
                    message=f"Remembered: {context_key} (type: {context_type})",
                    previous_value=previous_value,
                )

                logger.info(
                    "Context stored successfully",
                    org_id=context.org_id,
                    context_id=new_context.id,
                    context_key=context_key,
                    context_type=context_type,
                )

                return ToolResult(
                    success=True,
                    data=output.model_dump(),
                    metadata={
                        "context_id": str(new_context.id),
                        "updated_existing": (previous_value is not None),
                    },
                )

        except Exception as e:
            logger.exception(
                "Failed to store context",
                error=str(e),
                context_key=context_key,
            )

            output = RememberContextOutput(
                success=False,
                context_id=None,
                message=f"Failed to remember context: {str(e)}",
            )

            return ToolResult(
                success=False,
                data=output.model_dump(),
                metadata={"error": str(e)},
            )


class GetSessionHistoryTool(StructuredTool):
    """
    Retrieve conversation history and learned context from recent sessions.

    Enables continuity by loading:
    - Previous conversation topics and questions
    - Learned facts and user preferences
    - Environmental context from past sessions
    """

    tool_name = "get_session_history"
    tool_description = """Retrieve conversation history and learned context from recent sessions.
Use this to understand what was discussed previously, what facts were learned,
and what preferences the user expressed. Essential for continuity across sessions."""

    tool_version = "1.0.0"
    input_model = GetSessionHistoryInput
    output_model = GetSessionHistoryOutput
    required_permission = ToolPermissionLevel.READ_ONLY

    async def _run(
        self,
        context: AgentContext,
        lookback_sessions: int = 5,
        include_messages: bool = True,
        context_keys: Optional[List[str]] = None,
    ) -> ToolResult:
        """Retrieve session history and learned context."""

        try:
            async with async_session_factory() as db_session:
                # Get organization for name
                from cerebro.core.models import Organization

                org = await db_session.get(Organization, context.org_id)
                org_name = org.name if org else "Unknown Organization"

                # Get recent sessions for this org
                sessions_query = (
                    select(AgentSession)
                    .where(AgentSession.org_id == context.org_id)
                    .order_by(AgentSession.created_at.desc())
                    .limit(lookback_sessions)
                )

                if include_messages:
                    sessions_query = sessions_query.options(
                        selectinload(AgentSession.messages)
                    )

                sessions_result = await db_session.execute(sessions_query)
                sessions = sessions_result.scalars().all()

                # Get learned context for these sessions
                session_ids = [s.id for s in sessions]

                context_query = select(AgentSessionContext).where(
                    and_(
                        AgentSessionContext.org_id == context.org_id,
                        AgentSessionContext.session_id.in_(session_ids),
                        # Only non-expired context
                        or_(
                            AgentSessionContext.expires_at.is_(None),
                            AgentSessionContext.expires_at > datetime.now(timezone.utc),
                        ),
                    )
                )

                # Filter by specific keys if requested
                if context_keys:
                    context_query = context_query.where(
                        AgentSessionContext.context_key.in_(context_keys)
                    )

                context_query = context_query.order_by(
                    AgentSessionContext.created_at.desc()
                )

                context_result = await db_session.execute(context_query)
                context_entries = context_result.scalars().all()

                # Build session info
                session_infos = []
                for session in sessions:
                    # Get learned context for this session
                    session_context = [
                        {
                            "key": c.context_key,
                            "value": c.context_value,
                            "type": c.context_type,
                            "confidence": c.confidence,
                            "learned_from": c.learned_from,
                        }
                        for c in context_entries
                        if c.session_id == session.id
                    ]

                    # Get recent messages
                    recent_messages = []
                    if include_messages and session.messages:
                        for msg in sorted(session.messages, key=lambda m: m.created_at)[
                            -5:
                        ]:
                            recent_messages.append(
                                {
                                    "role": msg.role.value,
                                    "content": msg.content,
                                    "created_at": msg.created_at.isoformat(),
                                }
                            )

                    session_infos.append(
                        SessionInfo(
                            session_id=str(session.id),
                            agent_type=session.agent_type.value,
                            title=session.title,
                            created_at=session.created_at.isoformat(),
                            message_count=(
                                len(session.messages) if include_messages else 0
                            ),
                            recent_messages=recent_messages,
                            learned_context=session_context,
                        )
                    )

                # Find common context keys
                context_key_counts = {}
                for entry in context_entries:
                    context_key_counts[entry.context_key] = (
                        context_key_counts.get(entry.context_key, 0) + 1
                    )

                common_keys = sorted(
                    context_key_counts.keys(),
                    key=lambda k: context_key_counts[k],
                    reverse=True,
                )[:10]

                output = GetSessionHistoryOutput(
                    success=True,
                    org_name=org_name,
                    sessions_retrieved=len(sessions),
                    sessions=session_infos,
                    total_context_entries=len(context_entries),
                    common_context_keys=common_keys,
                )

                logger.info(
                    "Session history retrieved",
                    org_id=context.org_id,
                    sessions_count=len(sessions),
                    context_entries=len(context_entries),
                )

                return ToolResult(
                    success=True,
                    data=output.model_dump(),
                    metadata={
                        "sessions_retrieved": len(sessions),
                        "context_entries": len(context_entries),
                    },
                )

        except Exception as e:
            logger.exception(
                "Failed to retrieve session history",
                error=str(e),
                org_id=context.org_id,
            )

            output = GetSessionHistoryOutput(
                success=False,
                org_name="",
                sessions_retrieved=0,
                sessions=[],
                total_context_entries=0,
                common_context_keys=[],
            )

            return ToolResult(
                success=False,
                data=output.model_dump(),
                metadata={"error": str(e)},
            )
