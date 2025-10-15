"""SQLAlchemy-backed conversation memory for Cerebro agent sessions."""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from agents.items import TResponseInputItem
from agents.memory import Session
from sqlalchemy import delete, select

from cerebro.agents.models import AgentConversationItem, AgentSession, Base
from cerebro.core.database import async_session_factory, engine


class OpenAIAgentConversationSession(Session):
    """Session implementation that stores OpenAI agent history in the Cerebro database."""

    _tables_ready: bool = False
    _table_lock: asyncio.Lock = asyncio.Lock()

    def __init__(self, session: AgentSession):
        self.session_id = str(session.id)
        self._session_uuid = session.id

    @classmethod
    async def _ensure_table(cls) -> None:
        if cls._tables_ready:
            return
        async with cls._table_lock:
            if cls._tables_ready:
                return
            async with engine.begin() as connection:
                await connection.run_sync(
                    Base.metadata.create_all,
                    tables=[AgentConversationItem.__table__],
                )
            cls._tables_ready = True

    async def get_items(self, limit: int | None = None) -> List[TResponseInputItem]:
        await self._ensure_table()
        async with async_session_factory() as db_session:
            stmt = (
                select(AgentConversationItem.item)
                .where(AgentConversationItem.session_id == self._session_uuid)
                .order_by(AgentConversationItem.created_at.asc())
            )
            if limit is not None:
                stmt = (
                    select(AgentConversationItem.item)
                    .where(AgentConversationItem.session_id == self._session_uuid)
                    .order_by(AgentConversationItem.created_at.desc())
                    .limit(limit)
                )

            result = await db_session.execute(stmt)
            rows: List[Dict[str, Any]] = [row[0] for row in result.all()]

            if limit is not None:
                rows.reverse()

            return [self._to_input_item(row) for row in rows]

    async def add_items(self, items: List[TResponseInputItem]) -> None:
        if not items:
            return

        await self._ensure_table()
        normalized = [self._normalize_item(item) for item in items]
        async with async_session_factory() as db_session:
            async with db_session.begin():
                db_session.add_all(
                    [
                        AgentConversationItem(
                            session_id=self._session_uuid,
                            item=payload,
                        )
                        for payload in normalized
                    ]
                )

    async def pop_item(self) -> TResponseInputItem | None:
        await self._ensure_table()
        async with async_session_factory() as db_session:
            async with db_session.begin():
                stmt = (
                    select(AgentConversationItem)
                    .where(AgentConversationItem.session_id == self._session_uuid)
                    .order_by(AgentConversationItem.created_at.desc())
                    .limit(1)
                )
                result = await db_session.execute(stmt)
                row = result.scalar_one_or_none()
                if row is None:
                    return None

                await db_session.delete(row)
                return self._to_input_item(row.item)

    async def clear_session(self) -> None:
        await self._ensure_table()
        async with async_session_factory() as db_session:
            async with db_session.begin():
                await db_session.execute(
                    delete(AgentConversationItem).where(
                        AgentConversationItem.session_id == self._session_uuid
                    )
                )

    @staticmethod
    def _normalize_item(item: TResponseInputItem) -> Dict[str, Any]:
        if hasattr(item, "model_dump"):
            return item.model_dump(exclude_unset=True)  # type: ignore[return-value]
        if isinstance(item, dict):
            return dict(item)
        return {"value": item}

    @staticmethod
    def _to_input_item(payload: Dict[str, Any]) -> TResponseInputItem:
        if "value" in payload and len(payload) == 1:
            return payload["value"]  # type: ignore[return-value]
        return payload  # type: ignore[return-value]
