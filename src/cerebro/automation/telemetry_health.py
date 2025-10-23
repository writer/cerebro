"""Utilities for assessing frontend telemetry signal quality."""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.database import async_session_factory
from cerebro.core.models import FrontendObservationEvent


@dataclasses.dataclass(slots=True)
class TelemetryHealthSnapshot:
    generated_at: datetime
    window_start: Optional[datetime]
    window_end: datetime
    total_events: int
    unique_orgs: int
    unique_users: int
    unique_sessions: int
    events_by_type: Dict[str, int]
    events_by_component: Dict[str, int]
    missing_component: int
    missing_metadata: int
    empty_context: int
    average_events_per_session: float
    recent_events: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        payload = dataclasses.asdict(self)
        payload["generated_at"] = self.generated_at.isoformat()
        if self.window_start:
            payload["window_start"] = self.window_start.isoformat()
        payload["window_end"] = self.window_end.isoformat()
        return payload

    def missing_metadata_ratio(self) -> float:
        return (self.missing_metadata / self.total_events) if self.total_events else 0.0

    def missing_component_ratio(self) -> float:
        return (self.missing_component / self.total_events) if self.total_events else 0.0


async def fetch_telemetry_health(
    window_days: int = 7,
    *,
    db_session: Optional[AsyncSession] = None,
) -> TelemetryHealthSnapshot:
    now = datetime.now(timezone.utc)
    window_start: Optional[datetime] = None
    filters: List[Any] = []

    if window_days > 0:
        window_start = now - timedelta(days=window_days)
        filters.append(FrontendObservationEvent.occurred_at >= window_start)

    async def _query(session: AsyncSession) -> TelemetryHealthSnapshot:
        base_query = select(func.count()).select_from(FrontendObservationEvent)
        if filters:
            base_query = base_query.where(*filters)
        total_events = (await session.execute(base_query)).scalar_one()

        events_by_type_rows = await session.execute(
            select(
                FrontendObservationEvent.event_type,
                func.count(),
            )
            .where(*filters)
            .group_by(FrontendObservationEvent.event_type)
            .order_by(func.count().desc())
        )
        events_by_type = {
            event_type or "(unknown)": count
            for event_type, count in events_by_type_rows
        }

        events_by_component_rows = await session.execute(
            select(
                FrontendObservationEvent.component,
                func.count(),
            )
            .where(*filters)
            .group_by(FrontendObservationEvent.component)
            .order_by(func.count().desc())
        )
        events_by_component = {
            component or "(none)": count
            for component, count in events_by_component_rows
        }

        unique_orgs = (
            await session.execute(
                select(func.count(func.distinct(FrontendObservationEvent.org_id))).where(
                    *filters
                )
            )
        ).scalar_one()

        unique_users = (
            await session.execute(
                select(func.count(func.distinct(FrontendObservationEvent.user_id))).where(
                    *filters
                )
            )
        ).scalar_one()

        unique_sessions = (
            await session.execute(
                select(
                    func.count(
                        func.distinct(FrontendObservationEvent.agent_session_id)
                    )
                ).where(*filters)
            )
        ).scalar_one()

        missing_component = (
            await session.execute(
                select(func.count())
                .select_from(FrontendObservationEvent)
                .where(FrontendObservationEvent.component.is_(None), *filters)
            )
        ).scalar_one()

        missing_metadata_condition = or_(
            FrontendObservationEvent.event_metadata.is_(None),
            cast(FrontendObservationEvent.event_metadata, String) == "{}",
        )
        missing_metadata = (
            await session.execute(
                select(func.count())
                .select_from(FrontendObservationEvent)
                .where(missing_metadata_condition, *filters)
            )
        ).scalar_one()

        empty_context = (
            await session.execute(
                select(func.count())
                .select_from(FrontendObservationEvent)
                .where(FrontendObservationEvent.context_data == {}, *filters)
            )
        ).scalar_one()

        events_per_session = (
            total_events / unique_sessions
            if unique_sessions
            else 0.0
        )

        recent_stmt = (
            select(FrontendObservationEvent)
            .where(*filters)
            .order_by(FrontendObservationEvent.occurred_at.desc())
            .limit(20)
        )
        recent_rows = (await session.execute(recent_stmt)).scalars().all()
        recent_events: List[Dict[str, Any]] = [
            {
                "event_id": str(row.event_id),
                "occurred_at": row.occurred_at.isoformat() if row.occurred_at else None,
                "event_type": row.event_type,
                "component": row.component,
                "org_id": str(row.org_id) if row.org_id else None,
                "user_id": str(row.user_id) if row.user_id else None,
                "agent_session_id": str(row.agent_session_id)
                if row.agent_session_id
                else None,
                "metadata_keys": sorted((row.event_metadata or {}).keys()),
            }
            for row in recent_rows
        ]

        return TelemetryHealthSnapshot(
            generated_at=now,
            window_start=window_start,
            window_end=now,
            total_events=total_events,
            unique_orgs=unique_orgs,
            unique_users=unique_users,
            unique_sessions=unique_sessions,
            events_by_type=events_by_type,
            events_by_component=events_by_component,
            missing_component=missing_component,
            missing_metadata=missing_metadata,
            empty_context=empty_context,
            average_events_per_session=round(events_per_session, 2),
            recent_events=recent_events,
        )

    if db_session is not None:
        return await _query(db_session)

    async with async_session_factory() as session:
        return await _query(session)


def evaluate_health_thresholds(
    snapshot: TelemetryHealthSnapshot,
    *,
    max_missing_metadata_ratio: float,
    max_missing_component_ratio: float,
    min_total_events: int = 1,
) -> List[str]:
    issues: List[str] = []

    if snapshot.total_events < min_total_events:
        issues.append(
            f"total_events below minimum ({snapshot.total_events} < {min_total_events})"
        )

    if snapshot.missing_metadata_ratio() > max_missing_metadata_ratio:
        ratio = snapshot.missing_metadata_ratio()
        issues.append(
            f"missing_metadata_ratio {ratio:.4f} exceeds limit {max_missing_metadata_ratio:.4f}"
        )

    if snapshot.missing_component_ratio() > max_missing_component_ratio:
        ratio = snapshot.missing_component_ratio()
        issues.append(
            f"missing_component_ratio {ratio:.4f} exceeds limit {max_missing_component_ratio:.4f}"
        )

    return issues
