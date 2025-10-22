"""Utilities for aggregating telemetry into labeled corpora."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.agents.models import AgentReviewTask, AgentRuntimeEvent
from cerebro.core.models import FrontendObservationEvent


@dataclass(slots=True)
class DatasetRecord:
    """Normalized observation used for supervised fine-tuning."""

    org_id: UUID
    session_id: Optional[UUID]
    timestamp: datetime
    source: str
    event_type: str
    payload: Dict[str, object]
    labels: Dict[str, object]

    def as_dict(self) -> Dict[str, object]:
        return {
            "org_id": str(self.org_id),
            "session_id": str(self.session_id) if self.session_id else None,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "event_type": self.event_type,
            "payload": self.payload,
            "labels": self.labels,
        }


class DatasetBuilder:
    """Aggregate telemetry streams into a unified labeled corpus."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def build(self, org_id: Optional[UUID] = None) -> List[DatasetRecord]:
        records: List[DatasetRecord] = []
        records.extend(await self._collect_runtime_events(org_id))
        records.extend(await self._collect_frontend_events(org_id))
        records.extend(await self._collect_review_events(org_id))
        records.sort(key=lambda record: record.timestamp)
        return records

    async def export_jsonl(self, path: Path, org_id: Optional[UUID] = None) -> None:
        records = await self.build(org_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record.as_dict(), ensure_ascii=False))
                handle.write("\n")

    async def _collect_runtime_events(self, org_id: Optional[UUID]) -> List[DatasetRecord]:
        stmt = select(AgentRuntimeEvent)
        if org_id:
            stmt = stmt.where(AgentRuntimeEvent.org_id == org_id)
        stmt = stmt.order_by(AgentRuntimeEvent.created_at.asc())

        result = await self._session.execute(stmt)
        events: Iterable[AgentRuntimeEvent] = result.scalars().all()

        records: List[DatasetRecord] = []
        for event in events:
            payload = dict(event.payload or {})
            labels = {}
            if "outcome" in payload:
                labels["outcome"] = payload["outcome"]
            records.append(
                DatasetRecord(
                    org_id=event.org_id,
                    session_id=event.session_id,
                    timestamp=event.created_at,
                    source="runtime",
                    event_type=event.event_type,
                    payload=payload,
                    labels=labels,
                )
            )
        return records

    async def _collect_frontend_events(self, org_id: Optional[UUID]) -> List[DatasetRecord]:
        stmt = select(FrontendObservationEvent)
        if org_id:
            stmt = stmt.where(FrontendObservationEvent.org_id == org_id)
        stmt = stmt.order_by(FrontendObservationEvent.occurred_at.asc())

        result = await self._session.execute(stmt)
        events: Iterable[FrontendObservationEvent] = result.scalars().all()

        records: List[DatasetRecord] = []
        for event in events:
            payload = {
                "component": event.component,
                "context": dict(event.context_data or {}),
                "metadata": dict(event.event_metadata or {}),
            }
            labels = {
                "interaction": event.event_type,
            }
            records.append(
                DatasetRecord(
                    org_id=event.org_id,
                    session_id=event.agent_session_id,
                    timestamp=event.occurred_at,
                    source="frontend",
                    event_type=event.event_type,
                    payload=payload,
                    labels=labels,
                )
            )
        return records

    async def _collect_review_events(self, org_id: Optional[UUID]) -> List[DatasetRecord]:
        stmt = select(AgentReviewTask)
        if org_id:
            stmt = stmt.where(AgentReviewTask.org_id == org_id)
        stmt = stmt.order_by(AgentReviewTask.created_at.asc())

        result = await self._session.execute(stmt)
        tasks: Iterable[AgentReviewTask] = result.scalars().all()

        records: List[DatasetRecord] = []
        for task in tasks:
            payload = {
                "title": task.title,
                "summary": task.summary,
                "payload": dict(task.payload or {}),
                "priority": task.priority,
            }
            labels = {
                "status": task.status.value if hasattr(task.status, "value") else str(task.status),
                "resolved_at": task.resolved_at.isoformat() if task.resolved_at else None,
                "resolution_notes": task.resolution_notes,
            }
            records.append(
                DatasetRecord(
                    org_id=task.org_id,
                    session_id=task.session_id,
                    timestamp=task.created_at,
                    source="review",
                    event_type="agent_review_task",
                    payload=payload,
                    labels=labels,
                )
            )
        return records
