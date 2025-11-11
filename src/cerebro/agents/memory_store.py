"""Embedding-backed memory store for Cerebro agents."""

from __future__ import annotations

import asyncio
import logging
import math
import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from uuid import UUID

from sqlalchemy import delete, func, or_, select, update

from cerebro.agents.metrics import record_memory_event
from cerebro.agents.models import (
    AgentMemoryDecayOverride,
    AgentMemoryEntry,
    AgentSession,
    MemoryScope,
    MessageRole,
)
from cerebro.agents.memory_utils import (
    cosine_similarity,
    estimate_token_count,
    hash_text,
    summarize_text,
)
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

try:  # pragma: no cover - optional ANN engine
    from annoy import AnnoyIndex
except ImportError:  # pragma: no cover
    AnnoyIndex = None  # type: ignore


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

        self._half_life_hours = max(1, settings.agent_memory_half_life_hours)
        self._decay_boost = max(0.0, settings.agent_memory_decay_boost)
        self._decay_cap = max(1.0, settings.agent_memory_decay_cap)
        self._summary_max_chars = max(40, settings.agent_memory_summary_max_chars)
        self._max_snippets = max(1, settings.agent_memory_max_snippets)
        self._max_entries_per_org = max(1, settings.agent_memory_max_entries_per_org)
        self._max_entries_per_session = max(1, settings.agent_memory_max_entries_per_session)
        self._prune_batch_size = max(1, settings.agent_memory_prune_batch_size)
        self._prune_min_decay = max(0.0, settings.agent_memory_prune_min_decay)
        self._prune_probability = min(max(settings.agent_memory_prune_probability, 0.0), 1.0)
        self._prune_max_age = timedelta(hours=max(1, settings.agent_memory_prune_max_age_hours))
        self._duplicate_window = timedelta(hours=max(1, settings.agent_memory_duplicate_window_hours))
        self._mmr_lambda = min(max(settings.agent_memory_mmr_lambda, 0.0), 1.0)
        self._hybrid_alpha = min(max(settings.agent_memory_hybrid_alpha, 0.0), 1.0)
        self._session_boost = max(1.0, settings.agent_memory_session_scope_boost)
        self._incident_boost = max(1.0, settings.agent_memory_incident_scope_boost)
        self._finding_boost = max(1.0, settings.agent_memory_finding_scope_boost)
        self._role_weights = {
            role.lower(): float(weight)
            for role, weight in (settings.agent_memory_role_weights or {}).items()
        }
        self._scope_miss_penalty = 0.6
        self._decay_profiles = {
            key: max(1, int(value)) for key, value in (settings.agent_memory_decay_profiles or {}).items()
        }
        self._decay_override_cache: Dict[UUID, Tuple[datetime, Dict[Tuple[str, Optional[str]], int]]] = {}
        self._override_cache_ttl = timedelta(minutes=15)
        self._annoy_enabled = bool(
            AnnoyIndex is not None and settings.agent_memory_enable_annoy
        )

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

        message_text = content.strip()
        if not message_text:
            return

        embedding = await self._generate_embedding(message_text)
        embedding_norm = None
        if embedding is not None:
            embedding_norm = math.sqrt(sum(value * value for value in embedding)) or None

        scopes = self._build_scopes(session)
        scope_priority = min(scope["priority"] for scope in scopes) if scopes else 0
        summary = summarize_text(message_text, self._summary_max_chars)
        now = datetime.now(timezone.utc)
        content_hash = hash_text(message_text)
        token_count = estimate_token_count(message_text)
        metadata_payload: Dict[str, object] = dict(metadata or {})

        async with async_session_factory() as db_session:
            async with db_session.begin():
                duplicate_stmt = (
                    select(AgentMemoryEntry)
                    .where(
                        AgentMemoryEntry.org_id == session.org_id,
                        AgentMemoryEntry.content_hash == content_hash,
                    )
                    .order_by(AgentMemoryEntry.created_at.desc())
                    .limit(1)
                )
                duplicate_entry = (await db_session.execute(duplicate_stmt)).scalar_one_or_none()
                if duplicate_entry and self._is_duplicate_recent(duplicate_entry, now):
                    metadata_update = dict(duplicate_entry.extra_metadata or {})
                    existing_count = metadata_update.get("occurrence_count", 1)
                    try:
                        occurrence_count = int(existing_count) + 1
                    except (TypeError, ValueError):
                        occurrence_count = 2
                    metadata_update["occurrence_count"] = occurrence_count
                    metadata_update["last_duplicate_at"] = now.isoformat()
                    if metadata_payload:
                        metadata_update.setdefault("latest_metadata", metadata_payload)

                    update_values: Dict[str, object] = {
                        "updated_at": now,
                        "last_accessed_at": now,
                        "decay_score": min((duplicate_entry.decay_score or 1.0) + self._decay_boost, self._decay_cap),
                        "extra_metadata": metadata_update,
                        "token_count": token_count,
                    }

                    if duplicate_entry.summary is None and summary:
                        update_values["summary"] = summary
                    if duplicate_entry.embedding is None and embedding is not None:
                        update_values["embedding"] = embedding
                        update_values["embedding_norm"] = embedding_norm
                    if not duplicate_entry.content_hash:
                        update_values["content_hash"] = content_hash

                    await db_session.execute(
                        update(AgentMemoryEntry)
                        .where(AgentMemoryEntry.id == duplicate_entry.id)
                        .values(**update_values)
                    )
                    record_memory_event("duplicate_merge")
                    return

                existing = await db_session.execute(
                    select(AgentMemoryEntry)
                    .where(AgentMemoryEntry.session_id == session.id)
                    .order_by(AgentMemoryEntry.created_at.desc())
                    .limit(1)
                )
                last_entry = existing.scalar_one_or_none()
                if last_entry and last_entry.content == message_text:
                    return

                existing_count = metadata_payload.get("occurrence_count", 0)
                try:
                    occurrence_value = int(existing_count)
                except (TypeError, ValueError):
                    occurrence_value = 0
                metadata_payload["occurrence_count"] = occurrence_value + 1
                metadata_payload.setdefault("first_ingested_at", now.isoformat())

                entry = AgentMemoryEntry(
                    org_id=session.org_id,
                    session_id=session.id,
                    agent_type=session.agent_type.value,
                    role=role,
                    scopes=[scope["data"] for scope in scopes],
                    scope_priority=scope_priority,
                    content=message_text,
                    summary=summary,
                    content_hash=content_hash,
                    token_count=token_count,
                    embedding=embedding,
                    embedding_norm=embedding_norm,
                    extra_metadata=metadata_payload,
                    decay_score=1.0,
                    last_accessed_at=now,
                )
                db_session.add(entry)

        record_memory_event("ingest")
        await self._maybe_prune(session, now)

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
        query_norm: Optional[float] = None
        if query_embedding:
            query_norm = math.sqrt(sum(value * value for value in query_embedding)) or 1.0

        lexical_query_vector: Optional[List[float]] = None
        lexical_query_norm: Optional[float] = None
        vectorizer = self._hashing_vectorizer
        if vectorizer is not None:
            lexical_array = vectorizer.transform([query]).toarray()[0]
            lexical_query_vector = [float(value) for value in lexical_array]
            lexical_query_norm = math.sqrt(
                sum(value * value for value in lexical_query_vector)
            ) or 1.0

        if query_embedding is None and lexical_query_vector is None:
            return []

        session_scope_map = self._session_scope_map(session)
        limit = min(limit, self._max_snippets)
        overrides = await self._load_decay_overrides(session.org_id)

        async with async_session_factory() as db_session:
            stmt = (
                select(AgentMemoryEntry)
                .where(AgentMemoryEntry.org_id == session.org_id)
                .order_by(AgentMemoryEntry.created_at.desc())
                .limit(200)
            )
            result = await db_session.execute(stmt)
            candidates = result.scalars().all()

        if not candidates:
            return []

        now = datetime.now(timezone.utc)
        embedding_candidates: List[Tuple[int, AgentMemoryEntry, List[float], float]] = []
        for idx, entry in enumerate(candidates):
            if entry.embedding:
                embedding_candidates.append(
                    (idx, entry, entry.embedding, entry.embedding_norm or 1.0)
                )

        preferred_indices: Optional[set[int]] = None
        if self._annoy_enabled and query_embedding and embedding_candidates:
            dimension = len(query_embedding)
            try:
                annoy_index = AnnoyIndex(dimension, "angular")  # type: ignore[arg-type]
                index_map: Dict[int, int] = {}
                for ann_idx, (candidate_idx, _, embedding, _) in enumerate(embedding_candidates):
                    annoy_index.add_item(ann_idx, embedding)
                    index_map[ann_idx] = candidate_idx
                tree_count = min(10, max(1, len(embedding_candidates) // 3))
                annoy_index.build(tree_count)
                approx = annoy_index.get_nns_by_vector(
                    query_embedding,
                    min(len(embedding_candidates), max(limit * 5, 10)),
                )
                preferred_indices = {index_map[item] for item in approx}
            except Exception:
                preferred_indices = None

        scored: List[Tuple[float, AgentMemoryEntry, Optional[List[float]], float, float, float, bool]] = []
        for idx, entry in enumerate(candidates):
            embedding = entry.embedding
            embedding_norm = entry.embedding_norm or 1.0
            if preferred_indices is not None and embedding and idx not in preferred_indices:
                continue

            similarity = 0.0
            if query_embedding is not None:
                if not embedding:
                    refreshed = await self._refresh_embedding(entry)
                    if refreshed:
                        embedding, embedding_norm = refreshed
                if embedding:
                    similarity = cosine_similarity(
                        query_embedding,
                        query_norm or 1.0,
                        embedding,
                        embedding_norm,
                    )

            lexical_score = 0.0
            if lexical_query_vector is not None and vectorizer is not None:
                entry_array = vectorizer.transform([entry.content]).toarray()[0]
                entry_vector = [float(value) for value in entry_array]
                entry_norm = math.sqrt(sum(value * value for value in entry_vector)) or 1.0
                if entry_norm > 0 and lexical_query_norm:
                    lexical_score = cosine_similarity(
                        lexical_query_vector,
                        lexical_query_norm,
                        entry_vector,
                        entry_norm,
                    )

            combined_similarity = 0.0
            if similarity > 0:
                combined_similarity += self._hybrid_alpha * similarity
            if lexical_score > 0:
                weight = 1.0 if query_embedding is None else (1 - self._hybrid_alpha)
                combined_similarity += weight * lexical_score

            if combined_similarity <= 0:
                continue

            scope_multiplier = self._scope_multiplier(session_scope_map, entry.scopes)
            role_multiplier = self._role_weight(entry.role)
            combined_similarity_raw = combined_similarity
            adjusted = combined_similarity_raw * scope_multiplier * role_multiplier
            half_life_hours = self._determine_half_life(overrides, entry)
            recency = self._compute_decay_multiplier(entry, now, half_life_hours)
            final_score = adjusted * recency
            if final_score <= 0:
                continue

            ann_selected = preferred_indices is not None and idx in preferred_indices
            scored.append(
                (
                    final_score,
                    entry,
                    embedding,
                    embedding_norm,
                    similarity,
                    lexical_score,
                    ann_selected,
                    combined_similarity_raw,
                )
            )

        if not scored:
            return []

        top = self._select_diverse_candidates(scored, limit)
        await self._update_access_metadata([entry for _, entry, *_ in top])
        record_memory_event("recall", len(top))

        results: List[Dict[str, Any]] = []
        for (
            score,
            entry,
            _,
            _,
            embedding_similarity,
            lexical_similarity,
            ann_selected,
            combined_similarity_raw,
        ) in top:
            snippet_text, summary_text, scope_labels = self._format_snippet(score, entry)
            results.append(
                {
                    "id": str(entry.id),
                    "role": entry.role.value if entry.role else None,
                    "snippet": snippet_text,
                    "summary": summary_text,
                    "score": score,
                    "decay_score": entry.decay_score,
                    "scopes": entry.scopes,
                    "scope_labels": scope_labels,
                    "last_accessed_at": self._normalize_timestamp(
                        entry.last_accessed_at, now
                    ).isoformat(),
                    "created_at": self._normalize_timestamp(entry.created_at, now).isoformat(),
                    "metadata": entry.extra_metadata or {},
                    "token_count": entry.token_count,
                    "embedding_similarity": embedding_similarity if embedding_similarity > 0 else None,
                    "lexical_similarity": lexical_similarity if lexical_similarity > 0 else None,
                    "combined_similarity": combined_similarity_raw if combined_similarity_raw > 0 else None,
                    "ann_selected": ann_selected,
                }
            )

        return results

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

    def _session_scope_map(self, session: AgentSession) -> Dict[str, set[str]]:
        scope_map: Dict[str, set[str]] = {}
        for scope in self._build_scopes(session):
            data = scope.get("data") if isinstance(scope, dict) else None
            if not data:
                continue
            scope_type = data.get("type")
            if not scope_type:
                continue
            value = data.get("value")
            scope_map.setdefault(scope_type, set()).add(str(value) if value is not None else "__null__")
        return scope_map

    def _scope_multiplier(
        self,
        session_scope_map: Dict[str, set[str]],
        entry_scopes: Iterable[Dict[str, object]] | None,
    ) -> float:
        if not entry_scopes:
            return self._scope_miss_penalty

        multiplier = 1.0
        matched = False
        session_matched = False
        for scope in entry_scopes:
            scope_type = scope.get("type") if isinstance(scope, dict) else None
            if not scope_type:
                continue
            value = scope.get("value")
            value_key = str(value) if value is not None else "__null__"
            value_matches = value_key in session_scope_map.get(scope_type, set())

            if scope_type == MemoryScope.SESSION.value and value_matches:
                multiplier *= self._session_boost
                matched = True
                session_matched = True
            elif scope_type == MemoryScope.INCIDENT.value and value_matches:
                multiplier *= self._incident_boost
                matched = True
            elif scope_type == MemoryScope.FINDING.value and value_matches:
                multiplier *= self._finding_boost
                matched = True
            elif value_matches:
                multiplier *= 1.05
                matched = True

        if not matched:
            multiplier *= self._scope_miss_penalty
        elif not session_matched:
            multiplier *= self._scope_miss_penalty

        return multiplier

    def _role_weight(self, role: Optional[MessageRole]) -> float:
        if role is None:
            return 1.0
        return self._role_weights.get(role.value.lower(), 1.0)

    def _select_diverse_candidates(
        self,
        candidates: List[Tuple[float, AgentMemoryEntry, Optional[List[float]], float, float, float, bool, float]],
        limit: int,
    ) -> List[Tuple[float, AgentMemoryEntry, Optional[List[float]], float, float, float, bool, float]]:
        if not candidates:
            return []

        ordered = sorted(candidates, key=lambda item: item[0], reverse=True)
        selected: List[Tuple[float, AgentMemoryEntry, Optional[List[float]], float, float, float, bool, float]] = []

        while ordered and len(selected) < limit:
            best_index = 0
            best_score = float("-inf")
            for index, candidate in enumerate(ordered):
                base_score, _, embedding, norm, *_ = candidate
                if not selected or embedding is None:
                    mmr_score = base_score
                else:
                    max_similarity = 0.0
                    for chosen in selected:
                        chosen_embedding = chosen[2]
                        if not chosen_embedding or embedding is None:
                            continue
                        similarity = cosine_similarity(
                            embedding,
                            norm or 1.0,
                            chosen_embedding,
                            chosen[3] or 1.0,
                        )
                        max_similarity = max(max_similarity, similarity)
                    mmr_score = (
                        self._mmr_lambda * base_score
                        - (1 - self._mmr_lambda) * max_similarity
                    )

                if mmr_score > best_score:
                    best_index = index
                    best_score = mmr_score

            selected.append(ordered.pop(best_index))

        return selected

    async def _load_decay_overrides(
        self,
        org_id: UUID,
    ) -> Dict[Tuple[str, Optional[str]], int]:
        cached = self._decay_override_cache.get(org_id)
        now = datetime.now(timezone.utc)
        if cached and (now - cached[0]) < self._override_cache_ttl:
            return cached[1]

        overrides: Dict[Tuple[str, Optional[str]], int] = {}
        async with async_session_factory() as db_session:
            stmt = select(AgentMemoryDecayOverride).where(
                AgentMemoryDecayOverride.org_id == org_id
            )
            result = await db_session.execute(stmt)
            for record in result.scalars().all():
                key = (record.scope_type, record.scope_value)
                overrides[key] = max(1, int(record.half_life_hours or self._half_life_hours))

        self._decay_override_cache[org_id] = (now, overrides)
        return overrides

    def _determine_half_life(
        self,
        overrides: Dict[Tuple[str, Optional[str]], int],
        entry: AgentMemoryEntry,
    ) -> float:
        half_life = self._half_life_hours
        scopes = entry.scopes or []
        for scope in scopes:
            scope_type = scope.get("type") if isinstance(scope, dict) else None
            if not scope_type:
                continue
            value = scope.get("value") if isinstance(scope, dict) else None
            specific_key = (scope_type, str(value) if value is not None else None)
            generic_key = (scope_type, None)
            if specific_key in overrides:
                return max(1, overrides[specific_key])
            if generic_key in overrides:
                half_life = max(1, overrides[generic_key])
            elif scope_type in self._decay_profiles:
                half_life = min(half_life, max(1, self._decay_profiles[scope_type]))
        return half_life

    def _compute_decay_multiplier(
        self,
        entry: AgentMemoryEntry,
        now: datetime,
        half_life_hours: float,
    ) -> float:
        base_decay = entry.decay_score or 1.0
        last_seen = self._normalize_timestamp(entry.last_accessed_at or entry.created_at, now)
        current_time = self._normalize_timestamp(now, now)
        age_seconds = max((current_time - last_seen).total_seconds(), 0.0)
        age_hours = age_seconds / 3600.0
        exponential = math.exp(-age_hours / max(1.0, half_life_hours))
        return max(0.01, exponential * base_decay)

    async def _update_access_metadata(self, entries: Iterable[AgentMemoryEntry]) -> None:
        entries = list(entries)
        if not entries:
            return

        now = datetime.now(timezone.utc)
        async with async_session_factory() as db_session:
            async with db_session.begin():
                for entry in entries:
                    new_score = min((entry.decay_score or 1.0) + self._decay_boost, self._decay_cap)
                    metadata_update = dict(entry.extra_metadata or {})
                    previous_presented = metadata_update.get("presented_count", 0)
                    try:
                        presented_count = int(previous_presented) + 1
                    except (TypeError, ValueError):
                        presented_count = 1
                    metadata_update["presented_count"] = presented_count
                    metadata_update["last_presented_at"] = now.isoformat()
                    await db_session.execute(
                        update(AgentMemoryEntry)
                        .where(AgentMemoryEntry.id == entry.id)
                        .values(
                            last_accessed_at=now,
                            decay_score=new_score,
                            updated_at=now,
                            extra_metadata=metadata_update,
                        )
                    )

        record_memory_event("presented", len(entries))

    async def _refresh_embedding(
        self, entry: AgentMemoryEntry
    ) -> Optional[Tuple[List[float], float]]:
        refreshed = await self._generate_embedding(entry.content)
        if not refreshed:
            return None

        norm = math.sqrt(sum(value * value for value in refreshed)) or 1.0
        timestamp = datetime.now(timezone.utc)

        async with async_session_factory() as db_session:
            async with db_session.begin():
                await db_session.execute(
                    update(AgentMemoryEntry)
                    .where(AgentMemoryEntry.id == entry.id)
                    .values(
                        embedding=refreshed,
                        embedding_norm=norm,
                        updated_at=timestamp,
                    )
                )

        entry.embedding = refreshed
        entry.embedding_norm = norm
        return refreshed, norm

    def _is_duplicate_recent(self, entry: AgentMemoryEntry, now: datetime) -> bool:
        created_at = self._normalize_timestamp(entry.created_at, now)
        return created_at >= now - self._duplicate_window

    async def _maybe_prune(self, session: AgentSession, now: datetime) -> None:
        if not self._should_prune():
            return

        await self._prune_org_memory(session.org_id, now)
        if session.id:
            await self._prune_session_memory(session.id, now)

    async def _prune_org_memory(self, org_id: UUID, now: datetime) -> None:
        async with async_session_factory() as db_session:
            total_entries = await db_session.scalar(
                select(func.count(AgentMemoryEntry.id)).where(AgentMemoryEntry.org_id == org_id)
            )
            if not total_entries or total_entries <= self._max_entries_per_org:
                return

            to_remove = total_entries - self._max_entries_per_org
            cutoff_time = now - self._prune_max_age
            base_condition = or_(
                AgentMemoryEntry.decay_score <= self._prune_min_decay,
                AgentMemoryEntry.last_accessed_at <= cutoff_time,
            )

            prune_ids = await self._collect_prunable_ids(
                db_session,
                [AgentMemoryEntry.org_id == org_id, base_condition],
                to_remove,
            )

            if not prune_ids:
                prune_ids = await self._collect_prunable_ids(
                    db_session,
                    [AgentMemoryEntry.org_id == org_id],
                    to_remove,
                )

            if prune_ids:
                await db_session.execute(
                    delete(AgentMemoryEntry).where(AgentMemoryEntry.id.in_(prune_ids))
                )
                await db_session.commit()
                record_memory_event("pruned", len(prune_ids))

    async def _prune_session_memory(self, session_id: UUID, now: datetime) -> None:
        async with async_session_factory() as db_session:
            total_entries = await db_session.scalar(
                select(func.count(AgentMemoryEntry.id)).where(AgentMemoryEntry.session_id == session_id)
            )
            if not total_entries or total_entries <= self._max_entries_per_session:
                return

            to_remove = total_entries - self._max_entries_per_session
            cutoff_time = now - self._prune_max_age
            base_condition = or_(
                AgentMemoryEntry.decay_score <= self._prune_min_decay,
                AgentMemoryEntry.last_accessed_at <= cutoff_time,
            )

            prune_ids = await self._collect_prunable_ids(
                db_session,
                [AgentMemoryEntry.session_id == session_id, base_condition],
                to_remove,
            )

            if not prune_ids:
                prune_ids = await self._collect_prunable_ids(
                    db_session,
                    [AgentMemoryEntry.session_id == session_id],
                    to_remove,
                )

            if prune_ids:
                await db_session.execute(
                    delete(AgentMemoryEntry).where(AgentMemoryEntry.id.in_(prune_ids))
                )
                await db_session.commit()
                record_memory_event("pruned", len(prune_ids))

    async def _collect_prunable_ids(self, db_session, filters, limit: int) -> List[UUID]:
        limit = min(self._prune_batch_size, max(0, limit))
        if limit <= 0:
            return []

        if isinstance(filters, (list, tuple, set)):
            where_clauses = list(filters)
        else:
            where_clauses = [filters]

        if not where_clauses:
            return []

        stmt = (
            select(AgentMemoryEntry.id)
            .where(*where_clauses)
            .order_by(
                AgentMemoryEntry.decay_score.asc(),
                AgentMemoryEntry.last_accessed_at.asc(),
                AgentMemoryEntry.created_at.asc(),
            )
            .limit(limit)
        )
        result = await db_session.execute(stmt)
        return [row[0] for row in result.all()]

    def _should_prune(self) -> bool:
        if self._prune_probability <= 0:
            return False
        if self._prune_probability >= 1:
            return True
        return random.random() <= self._prune_probability

    @staticmethod
    def _normalize_timestamp(value: Optional[datetime], fallback: datetime) -> datetime:
        if value is None:
            return fallback
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def _format_snippet(self, score: float, entry: AgentMemoryEntry) -> tuple[str, str, List[str]]:
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
        if len(summary) > self._summary_max_chars:
            summary = summary[: self._summary_max_chars - 3].rstrip() + "..."

        metadata = f"score={score:.2f}"
        if entry.last_accessed_at:
            last_seen = self._normalize_timestamp(entry.last_accessed_at, datetime.now(timezone.utc))
            metadata += f", last={last_seen.strftime('%Y-%m-%d')}"

        body = f"{summary} ({metadata})"
        snippet = f"[{label}] {body}" if label else body
        return snippet, summary, scope_labels

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
