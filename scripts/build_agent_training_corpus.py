"""Construct a sanitized training corpus from frontend telemetry.

The exporter classifies ``frontend_observation_events`` into coarse-grained
labels suitable for RLHF / self-play bootstrapping and writes a JSONL corpus.

Example usage::

    uv run python scripts/build_agent_training_corpus.py \
        --window-days 30 --output datasets/training_corpus.jsonl
"""

from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from sqlalchemy import select

from cerebro.core.database import async_session_factory
from cerebro.core.models import FrontendObservationEvent


LABEL_MAP = {
    "agent.message": "dialogue_event",
    "agent.tool_invocation": "tool_interaction",
    "finding.review": "finding_triage",
    "timeline.view": "timeline_activity",
    "timeline.annotation": "timeline_annotation",
    "query.run": "query_execution",
    "query.saved": "query_management",
    "rule.execution": "policy_evaluation",
    "dashboard.view": "dashboard_navigation",
    "incident.update": "incident_management",
}

SAFE_CONTEXT_KEYS = {
    "finding_id",
    "severity",
    "resource_type",
    "provider",
    "query_id",
    "rule_id",
    "timeline_id",
    "view",
    "filters",
}


@dataclass
class TrainingEvent:
    session_id: str
    event_id: str
    occurred_at: Optional[str]
    label: str
    event_type: Optional[str]
    component: Optional[str]
    org_id: Optional[str]
    user_id: Optional[str]
    context: Dict[str, Any]
    metadata: Dict[str, Any]

    def to_json(self) -> str:
        return json.dumps(self.__dict__, ensure_ascii=False)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a sanitized agent training corpus from telemetry"
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
        "--min-label-count",
        type=int,
        default=10,
        help="Discard labels with fewer than this many events",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=0,
        help="Optional cap on total events (0 = unlimited)",
    )
    return parser.parse_args()


async def _fetch_events(window_days: int) -> Iterable[FrontendObservationEvent]:
    now = datetime.now(timezone.utc)
    filters = []
    if window_days > 0:
        filters.append(FrontendObservationEvent.occurred_at >= now - timedelta(days=window_days))

    stmt = (
        select(FrontendObservationEvent)
        .where(*filters)
        .order_by(FrontendObservationEvent.occurred_at)
    )

    async with async_session_factory() as session:
        stream = await session.stream(stmt)
        async for row in stream.scalars():
            yield row


def _derive_label(event_type: Optional[str], component: Optional[str]) -> str:
    if event_type:
        if event_type in LABEL_MAP:
            return LABEL_MAP[event_type]
        if event_type.startswith("query."):
            return "query_interaction"
        if event_type.startswith("finding."):
            return "finding_activity"
        if event_type.startswith("incident."):
            return "incident_activity"
    if component and "timeline" in component:
        return "timeline_activity"
    return "telemetry_event"


def _sanitize_payload(payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not payload:
        return {}
    sanitized: Dict[str, Any] = {}
    for key, value in payload.items():
        if key in SAFE_CONTEXT_KEYS:
            sanitized[key] = value
    return sanitized


async def build_corpus(
    output_path: Path,
    window_days: int,
    min_label_count: int,
    max_events: int,
) -> Dict[str, Any]:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    label_counts: Dict[str, int] = {}
    total_processed = 0
    retained = 0

    with output_path.open("w", encoding="utf-8") as handle:
        async for event in _fetch_events(window_days):
            if max_events and total_processed >= max_events:
                break

            total_processed += 1
            label = _derive_label(event.event_type, event.component)
            label_counts[label] = label_counts.get(label, 0) + 1

            telemetry_event = TrainingEvent(
                session_id=str(event.agent_session_id) if event.agent_session_id else "unknown",
                event_id=str(event.event_id),
                occurred_at=event.occurred_at.isoformat() if event.occurred_at else None,
                label=label,
                event_type=event.event_type,
                component=event.component,
                org_id=str(event.org_id) if event.org_id else None,
                user_id=str(event.user_id) if event.user_id else None,
                context=_sanitize_payload(event.context_data),
                metadata=_sanitize_payload(event.event_metadata),
            )
            handle.write(telemetry_event.to_json() + "\n")
            retained += 1

    # Filter label counts based on threshold
    filtered_counts = {
        label: count for label, count in label_counts.items() if count >= min_label_count
    }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window_days": window_days,
        "output_path": str(output_path),
        "total_processed": total_processed,
        "retained_events": retained,
        "min_label_count": min_label_count,
        "label_counts": filtered_counts,
    }


async def _run(args: argparse.Namespace) -> int:
    summary = await build_corpus(
        args.output,
        args.window_days,
        args.min_label_count,
        args.max_events,
    )

    print("Training corpus generation complete")
    for key, value in summary.items():
        print(f" - {key}: {value}")
    return 0


def main() -> int:
    args = _parse_args()
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
