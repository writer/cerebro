"""Runtime health analytics helpers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.agents.models import AgentRuntimeEvent


async def summarize_runtime_health(
    db: AsyncSession,
    *,
    hours: int = 24,
) -> List[Dict[str, Any]]:
    """Summarize runtime metadata, warning, and error events.

    Args:
        db: Async database session.
        hours: Lookback window for analytics.

    Returns:
        List of summaries keyed by runtime backend.
    """

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=max(hours, 1))

    bind = db.get_bind()  # AsyncEngine
    dialect_name = getattr(bind, "dialect", None)
    dialect_name = getattr(dialect_name, "name", None)

    if dialect_name == "postgresql":
        runtime_expr = func.jsonb_extract_path_text(AgentRuntimeEvent.payload, "runtime")
    else:
        runtime_expr = func.json_extract(AgentRuntimeEvent.payload, "$.runtime")

    base_stmt = (
        select(
            runtime_expr.label("runtime"),
            AgentRuntimeEvent.event_type.label("event_type"),
            func.count().label("event_count"),
            func.max(AgentRuntimeEvent.created_at).label("last_seen"),
        )
        .where(
            AgentRuntimeEvent.created_at >= cutoff,
            AgentRuntimeEvent.event_type.in_(
                ("runtime_metadata", "runtime_warning", "runtime_error")
            ),
        )
        .group_by(runtime_expr, AgentRuntimeEvent.event_type)
    )

    base_rows = await db.execute(base_stmt)

    summary: Dict[str, Dict[str, Any]] = {}
    for runtime, event_type, count, last_seen in base_rows:
        bucket = summary.setdefault(
            runtime or "unknown",
            {
                "runtime": runtime or "unknown",
                "window_start": cutoff,
                "window_end": now,
                "events": {},
                "warnings": {},
                "latest_metadata": None,
            },
        )
        bucket["events"][event_type] = {
            "count": int(count or 0),
            "last_seen": last_seen,
        }

    if dialect_name == "postgresql":
        reason_expr = func.jsonb_extract_path_text(AgentRuntimeEvent.payload, "reason")
    else:
        reason_expr = func.json_extract(AgentRuntimeEvent.payload, "$.reason")

    warning_stmt = (
        select(
            runtime_expr.label("runtime"),
            reason_expr.label("reason"),
            func.count().label("event_count"),
            func.max(AgentRuntimeEvent.created_at).label("last_seen"),
        )
        .where(
            AgentRuntimeEvent.created_at >= cutoff,
            AgentRuntimeEvent.event_type == "runtime_warning",
        )
        .group_by(runtime_expr, reason_expr)
    )

    warning_rows = await db.execute(warning_stmt)
    for runtime, reason, count, last_seen in warning_rows:
        bucket = summary.setdefault(
            runtime or "unknown",
            {
                "runtime": runtime or "unknown",
                "window_start": cutoff,
                "window_end": now,
                "events": {},
                "warnings": {},
                "latest_metadata": None,
            },
        )
        bucket["warnings"][reason or "unspecified"] = {
            "count": int(count or 0),
            "last_seen": last_seen,
        }

    metadata_subquery = (
        select(
            runtime_expr.label("runtime"),
            AgentRuntimeEvent.payload.label("payload"),
            AgentRuntimeEvent.created_at.label("created_at"),
            func.row_number()
            .over(
                partition_by=runtime_expr,
                order_by=AgentRuntimeEvent.created_at.desc(),
            )
            .label("rn"),
        )
        .where(
            AgentRuntimeEvent.created_at >= cutoff,
            AgentRuntimeEvent.event_type == "runtime_metadata",
        )
        .subquery()
    )

    latest_stmt = (
        select(
            metadata_subquery.c.runtime,
            metadata_subquery.c.payload,
            metadata_subquery.c.created_at,
        )
        .where(metadata_subquery.c.rn == 1)
    )

    latest_rows = await db.execute(latest_stmt)
    for runtime, payload, created_at in latest_rows:
        bucket = summary.setdefault(
            runtime or "unknown",
            {
                "runtime": runtime or "unknown",
                "window_start": cutoff,
                "window_end": now,
                "events": {},
                "warnings": {},
                "latest_metadata": None,
            },
        )
        bucket["latest_metadata"] = {
            "payload": payload,
            "captured_at": created_at,
        }

    return [
        {
            **bucket,
            "events": {
                key: {
                    "count": value.get("count", 0),
                    "last_seen": value.get("last_seen"),
                }
                for key, value in bucket["events"].items()
            },
            "warnings": {
                key: {
                    "count": value.get("count", 0),
                    "last_seen": value.get("last_seen"),
                }
                for key, value in bucket["warnings"].items()
            },
            "latest_metadata": (
                {
                    "payload": bucket["latest_metadata"]["payload"],
                    "captured_at": bucket["latest_metadata"]["captured_at"],
                }
                if bucket["latest_metadata"]
                else None
            ),
        }
        for bucket in sorted(summary.values(), key=lambda item: item["runtime"])
    ]
