"""Embedding-backed memory store for Cerebro agents."""

from __future__ import annotations

import asyncio
import logging
import math
from collections import deque
from typing import Dict, Iterable, List, Optional

from sqlalchemy import select

from cerebro.agents.models import AgentMemoryEntry, AgentSession, MemoryScope, MessageRole
from cerebro.core.config import settings
from cerebro.core.database import async_session_factory

logger = logging.getLogger(__name__)

try:  # pragma: no cover - optional dependency
    from openai import AsyncOpenAI
except ImportError:  # pragma: no cover
    AsyncOpenAI = None  # type: ignore

try:  # pragma: no cover - sklearn may not be present in minimal envs
    from sklearn.feature_extraction.text import HashingVectorizer
except ImportError:  # pragma: no cover
    HashingVectorizer = None  # type: ignore


class AgentMemoryStore:
    """Provides storage and retrieval of long-term agent memory snippets."""

    _instance: "AgentMemoryStore" | None = None
    _instance_lock = asyncio.Lock()

    def __init__(self) -> None:
        self._openai_client = None
        if (
            settings.enable_agent_memory_embeddings
            and settings.openai_api_key
            and AsyncOpenAI is not None
        ):  # pragma: no branch
            try:
                self._openai_client = AsyncOpenAI(api_key=settings.openai_api_key)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Failed to initialize OpenAI client for memory embeddings", error=str(exc))
                self._openai_client = None

        if HashingVectorizer is not None:
            self._hashing_vectorizer = HashingVectorizer(
                n_features=256,
                alternate_sign=False,
                norm="l2",
            )
        else:  # pragma: no cover - fallback when sklearn missing
            self._hashing_vectorizer = None

    @classmethod
    async def shared(cls) -> "AgentMemoryStore":
        if cls._instance is None:
            async with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    async def add_message(
        self,
        *,
        session: AgentSession,
        role: MessageRole,
        content: str,
        metadata: Optional[Dict[str, object]] = None,
    ) -> None:
        if not content or not content.strip():
            return

        embedding = await self._generate_embedding(content)
        embedding_norm = None
        if embedding is not None:
            embedding_norm = math.sqrt(sum(value * value for value in embedding)) or None

        scopes = self._build_scopes(session)
        scope_priority = min(scope["priority"] for scope in scopes) if scopes else 0

        summary = content.strip()
        if len(summary) > 400:
            summary = summary[:397] + "..."

        async with async_session_factory() as db_session:
            async with db_session.begin():
                existing = await db_session.execute(
                    select(AgentMemoryEntry)
                    .where(AgentMemoryEntry.session_id == session.id)
                    .order_by(AgentMemoryEntry.created_at.desc())
                    .limit(1)
                )
                last_entry = existing.scalar_one_or_none()
                if last_entry and last_entry.content == content:
                    return

                entry = AgentMemoryEntry(
                    org_id=session.org_id,
                    session_id=session.id,
                    agent_type=session.agent_type.value,
                    role=role,
                    scopes=[scope["data"] for scope in scopes],
                    scope_priority=scope_priority,
                    content=content,
                    summary=summary,
                    embedding=embedding,
                    embedding_norm=embedding_norm,
                    extra_metadata=metadata or {},
                )
                db_session.add(entry)

    async def retrieve_relevant(
        self,
        *,
        session: AgentSession,
        query: str,
        limit: int = 5,
    ) -> List[str]:
        if not query or not query.strip():
            return []

        query_embedding = await self._generate_embedding(query)
        if not query_embedding:
            return []

        query_norm = math.sqrt(sum(value * value for value in query_embedding)) or 1.0

        session_scopes = {scope["type"]: scope for scope in self._build_scopes(session)}

        async with async_session_factory() as db_session:
            stmt = (
                select(AgentMemoryEntry)
                .where(AgentMemoryEntry.org_id == session.org_id)
                .order_by(AgentMemoryEntry.created_at.desc())
                .limit(200)
            )
            result = await db_session.execute(stmt)
            candidates = result.scalars().all()

        scored: deque[tuple[float, AgentMemoryEntry]] = deque()
        for entry in candidates:
            if not entry.embedding:
                continue

            similarity = self._cosine_similarity(
                query_embedding,
                query_norm,
                entry.embedding,
                entry.embedding_norm or 1.0,
            )

            if similarity <= 0:
                continue

            if not self._scopes_intersect(session_scopes, entry.scopes):
                similarity *= 0.75

            scored.append((similarity, entry))

        top = sorted(scored, key=lambda item: item[0], reverse=True)[:limit]
        snippets = [self._format_snippet(score, entry) for score, entry in top]
        return snippets

    async def _generate_embedding(self, text: str) -> Optional[List[float]]:
        if not settings.enable_agent_memory_embeddings:
            return None

        text = text.strip()
        if not text:
            return None

        if self._openai_client is not None:
            try:
                response = await self._openai_client.embeddings.create(
                    model=settings.openai_embedding_model,
                    input=text,
                )
                return response.data[0].embedding
            except Exception as exc:
                logger.debug(
                    "Falling back to local embeddings after OpenAI error",
                    error=str(exc),
                )

        if self._hashing_vectorizer is None:
            return None

        vector = self._hashing_vectorizer.transform([text]).toarray()[0]
        return vector.astype(float).tolist()

    @staticmethod
    def _scopes_intersect(
        session_scopes: Dict[str, Dict[str, object]], scopes: Iterable[Dict[str, object]]
    ) -> bool:
        for scope in scopes:
            scope_type = scope.get("type")
            scope_value = scope.get("value")
            session_scope = session_scopes.get(scope_type)
            if session_scope and session_scope["data"].get("value") == scope_value:
                return True
        return False

    @staticmethod
    def _cosine_similarity(
        query: List[float],
        query_norm: float,
        stored: List[float],
        stored_norm: float,
    ) -> float:
        if query_norm == 0 or stored_norm == 0:
            return 0.0
        length = min(len(query), len(stored))
        dot = sum(query[i] * stored[i] for i in range(length))
        return dot / (query_norm * stored_norm)

    @staticmethod
    def _format_snippet(score: float, entry: AgentMemoryEntry) -> str:
        scope_labels = []
        for scope in entry.scopes or []:
            scope_type = scope.get("type")
            value = scope.get("value")
            if scope_type == MemoryScope.SESSION.value:
                continue
            if value:
                scope_labels.append(f"{scope_type}:{value}")
            else:
                scope_labels.append(scope_type)

        label = " | ".join(scope_labels)
        summary = entry.summary or entry.content
        return f"[{label}] {summary} (relevance={score:.2f})" if label else f"{summary} (relevance={score:.2f})"

    @staticmethod
    def _build_scopes(session: AgentSession) -> List[Dict[str, object]]:
        scopes: List[Dict[str, object]] = []
        scopes.append(
            {
                "priority": 0,
                "data": {"type": MemoryScope.ORGANIZATION.value, "value": str(session.org_id)},
            }
        )

        context = session.context or {}
        incident_id = context.get("incident_id")
        if incident_id:
            scopes.append(
                {
                    "priority": 1,
                    "data": {"type": MemoryScope.INCIDENT.value, "value": incident_id},
                }
            )

        finding_ids = context.get("finding_ids", []) or []
        for fid in finding_ids:
            scopes.append(
                {
                    "priority": 1,
                    "data": {"type": MemoryScope.FINDING.value, "value": fid},
                }
            )

        scopes.append(
            {
                "priority": 2,
                "data": {"type": MemoryScope.SESSION.value, "value": str(session.id)},
            }
        )

        return scopes
