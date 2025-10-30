"""Analytics helpers for the Cerebro SDK."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.analytics.runtime_health import summarize_runtime_health


@dataclass(slots=True)
class RuntimeEventAggregate:
    """Aggregated event counts for a runtime channel."""

    count: int
    last_seen: Optional[datetime]


@dataclass(slots=True)
class RuntimeMetadataSnapshot:
    """Latest metadata payload emitted by a runtime backend."""

    payload: dict[str, Any]
    captured_at: datetime


@dataclass(slots=True)
class RuntimeHealthRecord:
    """Summarized runtime health diagnostics for a backend."""

    runtime: str
    window_start: datetime
    window_end: datetime
    events: dict[str, RuntimeEventAggregate]
    warnings: dict[str, RuntimeEventAggregate]
    latest_metadata: Optional[RuntimeMetadataSnapshot]


class RuntimeHealthClient:
    """Query runtime health analytics derived from agent telemetry."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def summarize(self, *, hours: int = 24) -> list[RuntimeHealthRecord]:
        """Return runtime health rollups for the requested window."""

        raw_records = await summarize_runtime_health(self._db, hours=hours)

        summary: list[RuntimeHealthRecord] = []
        for payload in raw_records:
            events = {
                name: RuntimeEventAggregate(
                    count=int(details.get("count", 0) or 0),
                    last_seen=details.get("last_seen"),
                )
                for name, details in (payload.get("events") or {}).items()
            }
            warnings = {
                name: RuntimeEventAggregate(
                    count=int(details.get("count", 0) or 0),
                    last_seen=details.get("last_seen"),
                )
                for name, details in (payload.get("warnings") or {}).items()
            }

            metadata = None
            metadata_payload = payload.get("latest_metadata")
            if metadata_payload and metadata_payload.get("captured_at") is not None:
                metadata = RuntimeMetadataSnapshot(
                    payload=dict(metadata_payload.get("payload") or {}),
                    captured_at=metadata_payload["captured_at"],
                )

            window_start = payload.get("window_start")
            window_end = payload.get("window_end")
            if not isinstance(window_start, datetime) or not isinstance(window_end, datetime):
                continue

            summary.append(
                RuntimeHealthRecord(
                    runtime=payload.get("runtime") or "unknown",
                    window_start=window_start,
                    window_end=window_end,
                    events=events,
                    warnings=warnings,
                    latest_metadata=metadata,
                )
            )

        return summary


__all__ = [
    "RuntimeHealthClient",
    "RuntimeHealthRecord",
    "RuntimeEventAggregate",
    "RuntimeMetadataSnapshot",
]
