"""Create a daily agent session seeded with hot findings and optional Slack output."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Optional
from uuid import UUID

import httpx

from cerebro.automation.daily_summary import build_slack_payload, generate_daily_summary
from cerebro.core.database import async_session_factory


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Seed an agent session with the latest high-priority findings and post a summary",
    )
    parser.add_argument("org_id", help="Organization UUID to scope the session")
    parser.add_argument(
        "--created-by",
        default="automation",
        help="Identifier recorded as the session creator",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=5,
        help="Maximum number of findings to include",
    )
    parser.add_argument(
        "--window-hours",
        type=int,
        default=24,
        help="Lookback window for findings in hours",
    )
    parser.add_argument(
        "--title",
        help="Optional title override for the agent session",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional JSON file to persist the summary payload",
    )
    parser.add_argument(
        "--slack-webhook",
        help="Slack webhook URL to post the summary",
    )
    parser.add_argument(
        "--session-base-url",
        help="Optional base URL to link directly to the created session",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip Slack delivery and only print the summary",
    )
    return parser.parse_args()


def _derive_session_url(base_url: Optional[str], session_id: UUID) -> Optional[str]:
    if not base_url:
        return None
    return base_url.rstrip("/") + f"/{session_id}"


async def _send_slack_message(webhook: str, payload: dict[str, object]) -> None:
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(webhook, json=payload)
        response.raise_for_status()


async def _run(args: argparse.Namespace) -> int:
    org_id = UUID(args.org_id)

    async with async_session_factory() as db_session:
        summary = await generate_daily_summary(
            db_session,
            org_id=org_id,
            created_by=args.created_by,
            limit=args.limit,
            window_hours=args.window_hours,
            title=args.title,
        )

    print("Daily Agent Summary")
    print("===================")
    print(json.dumps(summary.to_dict(), indent=2))

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(summary.to_dict(), indent=2), encoding="utf-8"
        )
        print(f"Summary written to {args.output}")

    if args.slack_webhook and not args.dry_run:
        session_url = _derive_session_url(args.session_base_url, summary.session_id)
        payload = build_slack_payload(summary, session_url=session_url)
        await _send_slack_message(args.slack_webhook, payload)
        print("Slack notification delivered")
    elif args.slack_webhook and args.dry_run:
        print("Dry run enabled; Slack payload not sent")

    return 0


def main() -> int:
    args = _parse_args()
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
