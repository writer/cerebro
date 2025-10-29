"""Agent session and messaging helpers for the Cerebro SDK."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.agents.models import AgentSession, AgentMessage, AgentType, MessageRole


@dataclass(slots=True)
class AgentSessionRecord:
    session_id: UUID
    org_id: UUID
    agent_type: str
    created_at: datetime
    created_by: str
    title: Optional[str]
    is_active: bool
    context: dict[str, Any]


@dataclass(slots=True)
class AgentMessageRecord:
    message_id: UUID
    session_id: UUID
    role: str
    content: dict[str, Any]
    created_at: datetime


class AgentManager:
    """Manage agent sessions and messages via the SDK."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def create_session(
        self,
        *,
        org_id: UUID,
        agent_type: str,
        created_by: str,
        context: Optional[dict[str, Any]] = None,
        title: Optional[str] = None,
    ) -> AgentSessionRecord:
        session = AgentSession(
            org_id=org_id,
            agent_type=self._parse_agent_type(agent_type),
            created_by=created_by,
            title=title,
            context=dict(context or {}),
        )
        self._db.add(session)
        await self._db.commit()
        await self._db.refresh(session)
        return self._session_to_record(session)

    async def get_session(self, session_id: UUID, *, org_id: Optional[UUID] = None) -> Optional[AgentSessionRecord]:
        session = await self._db.get(AgentSession, session_id)
        if not session:
            return None
        if org_id and session.org_id != org_id:
            return None
        return self._session_to_record(session)

    async def list_sessions(
        self,
        *,
        org_id: UUID,
        agent_type: Optional[str] = None,
        created_by: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AgentSessionRecord], int]:
        stmt = select(AgentSession).where(AgentSession.org_id == org_id)
        count_stmt: Select

        count_stmt = select(func.count(AgentSession.id)).where(AgentSession.org_id == org_id)

        if agent_type:
            try:
                agent_type_enum = self._parse_agent_type(agent_type)
            except ValueError:
                return [], 0
            stmt = stmt.where(AgentSession.agent_type == agent_type_enum)
            count_stmt = count_stmt.where(AgentSession.agent_type == agent_type_enum)

        if created_by:
            stmt = stmt.where(AgentSession.created_by == created_by)
            count_stmt = count_stmt.where(AgentSession.created_by == created_by)

        stmt = stmt.order_by(AgentSession.created_at.desc()).offset(offset).limit(limit)

        result = await self._db.scalars(stmt)
        sessions = list(result)
        total = await self._db.scalar(count_stmt)
        total_count = int(total or 0)
        return [self._session_to_record(session) for session in sessions], total_count

    async def close_session(self, session_id: UUID) -> bool:
        session = await self._db.get(AgentSession, session_id)
        if not session:
            return False
        session.is_active = False
        await self._db.commit()
        return True

    async def add_message(
        self,
        *,
        session_id: UUID,
        role: str,
        content: dict[str, Any],
    ) -> AgentMessageRecord:
        session = await self._db.get(AgentSession, session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")

        message = AgentMessage(
            session_id=session_id,
            role=self._parse_message_role(role),
            content=content,
        )
        self._db.add(message)
        await self._db.commit()
        await self._db.refresh(message)
        return self._message_to_record(message)

    async def list_messages(
        self,
        *,
        session_id: UUID,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AgentMessageRecord]:
        stmt = (
            select(AgentMessage)
            .where(AgentMessage.session_id == session_id)
            .order_by(AgentMessage.created_at.asc())
            .offset(offset)
            .limit(limit)
        )
        rows = await self._db.scalars(stmt)
        return [self._message_to_record(row) for row in rows]

    async def delete_message(self, message_id: UUID) -> bool:
        message = await self._db.get(AgentMessage, message_id)
        if not message:
            return False
        await self._db.delete(message)
        await self._db.commit()
        return True

    @staticmethod
    def _parse_agent_type(agent_type: str) -> AgentType:
        try:
            return AgentType(agent_type)
        except ValueError as exc:
            raise ValueError(f"Invalid agent type '{agent_type}'") from exc

    @staticmethod
    def _parse_message_role(role: str) -> MessageRole:
        try:
            return MessageRole(role)
        except ValueError as exc:
            raise ValueError(f"Invalid message role '{role}'") from exc

    @staticmethod
    def _session_to_record(session: AgentSession) -> AgentSessionRecord:
        return AgentSessionRecord(
            session_id=session.id,
            org_id=session.org_id,
            agent_type=session.agent_type.value,
            created_at=session.created_at,
            created_by=session.created_by,
            title=session.title,
            is_active=session.is_active,
            context=dict(session.context or {}),
        )

    @staticmethod
    def _message_to_record(message: AgentMessage) -> AgentMessageRecord:
        return AgentMessageRecord(
            message_id=message.id,
            session_id=message.session_id,
            role=message.role.value,
            content=dict(message.content or {}),
            created_at=message.created_at,
        )
