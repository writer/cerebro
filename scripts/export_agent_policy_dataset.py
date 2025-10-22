"""Export agent interaction trajectories from telemetry for policy training.

The exporter materialises JSONL trajectories constructed from
``frontend_observation_events`` so that RLHF / self-play pipelines can
bootstrap from production telemetry.

Each output line contains metadata for a single ``agent_session_id`` along with
the ordered sequence of observation events recorded during that session.

Example usage::

    uv run python scripts/export_agent_policy_dataset.py \
        --window-days 30 --output datasets/trajectories.jsonl
"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy import select

from cerebro.core.database import async_session_factory
from cerebro.core.models import FrontendObservationEvent


def _parse_args() -> argparse.Namespace:
    """Parse CLI arguments for the exporter."""
    parser = argparse.ArgumentParser(
        description="Export agent session trajectories from telemetry events"
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Destination JSONL file",
    )
    parser.add_argument(
        "--window-days",
        type=int,
        default=30,
        help="Number of days to include (0 = all history)",
    )
    parser.add_argument(
        "--min-events",
        type=int,
        default=3,
        help="Minimum events per session to retain",
    )
    parser.add_argument(
        "--max-sessions",
        type=int,
        default=0,
        help="Optional cap on the number of sessions to export (0 = unlimited)",
    )
    return parser.parse_args()


def _serialise_event(event: FrontendObservationEvent) -> Dict[str, Any]:
    """Convert ORM event row to a serialisable dictionary."""
    return {
        "event_id": str(event.event_id),
        "occurred_at": event.occurred_at.isoformat() if event.occurred_at else None,
        "event_type": event.event_type,
        "component": event.component,
        "context": event.context_data,
        "metadata": event.event_metadata,
    }


async def export_dataset(
    output_path: Path,
    window_days: int,
    min_events: int,
    max_sessions: int,
) -> Dict[str, Any]:
    """Stream telemetry events and persist them as JSONL trajectories."""
    now = datetime.now(timezone.utc)
    filters = []
    if window_days > 0:
        filters.append(FrontendObservationEvent.occurred_at >= now - timedelta(days=window_days))

    stmt = (
        select(FrontendObservationEvent)
        .where(*filters)
        .order_by(
            FrontendObservationEvent.agent_session_id,
            FrontendObservationEvent.occurred_at,
            FrontendObservationEvent.event_id,
        )
    )

    exported_sessions = 0
    total_events = 0
    output_path.parent.mkdir(parents=True, exist_ok=True)

    async with async_session_factory() as session, output_path.open(
        "w", encoding="utf-8"
    ) as handle:
        stream = await session.stream(stmt)

        current_session_id: Optional[str] = None
        current_payload: Optional[Dict[str, Any]] = None

        async for event in stream.scalars():
            if event.agent_session_id is None:
                # Skip telemetry that was not attached to an agent session.
                continue

            session_key = str(event.agent_session_id)
            if session_key != current_session_id:
                if (
                    current_payload
                    and current_payload["event_count"] >= min_events
                    and (max_sessions == 0 or exported_sessions < max_sessions)
                ):
                    handle.write(json.dumps(current_payload) + "\n")
                    exported_sessions += 1

                    if max_sessions and exported_sessions >= max_sessions:
                        break

                current_session_id = session_key
                current_payload = {
                    "session_id": session_key,
                    "org_id": str(event.org_id) if event.org_id else None,
                    "user_id": str(event.user_id) if event.user_id else None,
                    "event_count": 0,
                    "events": [],
                }

            if current_payload is None:
                continue

            current_payload["events"].append(_serialise_event(event))
            current_payload["event_count"] += 1
            total_events += 1

        # Flush final session
        if (
            current_payload
            and current_payload["event_count"] >= min_events
            and (max_sessions == 0 or exported_sessions < max_sessions)
        ):
            handle.write(json.dumps(current_payload) + "\n")
            exported_sessions += 1

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window_days": window_days,
        "sessions_exported": exported_sessions,
        "min_events": min_events,
        "total_events_processed": total_events,
        "output_path": str(output_path),
    }
    return summary


async def _run(args: argparse.Namespace) -> int:
    """CLI execution helper for the exporter."""
    summary = await export_dataset(
        args.output,
        args.window_days,
        args.min_events,
        args.max_sessions,
    )

    print("Telemetry agent trajectory export complete")
    for key, value in summary.items():
        print(f" - {key}: {value}")
    return 0


def main() -> int:
    """Entrypoint used by ``python scripts/export_agent_policy_dataset.py``."""
    args = _parse_args()
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
