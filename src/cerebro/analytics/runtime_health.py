"""Runtime health analytics helpers."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from sqlalchemy import text

from cerebro.analytics.sql_dialect import get_dialect_name, json_text_extract_expr


async def summarize_runtime_health(
    db: Any,
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

    dialect = get_dialect_name(db)
    runtime_expr = json_text_extract_expr(
        column_expr="payload", key="runtime", dialect=dialect
    )

    base_stmt = text(
        f"""
        SELECT
            {runtime_expr} AS runtime,
            event_type,
            COUNT(*) AS event_count,
            MAX(created_at) AS last_seen
        FROM agent_runtime_events
        WHERE created_at >= :cutoff
            AND event_type IN ('runtime_metadata', 'runtime_warning', 'runtime_error')
        GROUP BY 1, 2
        """
    )

    base_rows = await db.execute(base_stmt, {"cutoff": cutoff})

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

    reason_expr = json_text_extract_expr(
        column_expr="payload", key="reason", dialect=dialect
    )

    warning_stmt = text(
        f"""
        SELECT
            {runtime_expr} AS runtime,
            {reason_expr} AS reason,
            COUNT(*) AS event_count,
            MAX(created_at) AS last_seen
        FROM agent_runtime_events
        WHERE created_at >= :cutoff
            AND event_type = 'runtime_warning'
        GROUP BY 1, 2
        """
    )

    warning_rows = await db.execute(warning_stmt, {"cutoff": cutoff})
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

    latest_stmt = text(
        f"""
        SELECT runtime, payload, created_at
        FROM (
            SELECT
                {runtime_expr} AS runtime,
                payload,
                created_at,
                ROW_NUMBER() OVER (
                    PARTITION BY {runtime_expr}
                    ORDER BY created_at DESC
                ) AS rn
            FROM agent_runtime_events
            WHERE created_at >= :cutoff
                AND event_type = 'runtime_metadata'
        ) AS latest
        WHERE rn = 1
        """
    )

    latest_rows = await db.execute(latest_stmt, {"cutoff": cutoff})
    for runtime, payload, created_at in latest_rows:
        payload_value = payload
        if isinstance(payload_value, str):
            try:
                payload_value = json.loads(payload_value)
            except json.JSONDecodeError:
                pass
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
            "payload": payload_value,
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
