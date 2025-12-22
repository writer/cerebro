"""CLI entrypoint for telemetry alerting automation."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from typing import Sequence

from cerebro.automation.alerting import RuleSeverity, run_telemetry_alerts


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run telemetry alert evaluation")
    parser.add_argument(
        "--window-days", type=int, default=1, help="Lookback window in days"
    )
    parser.add_argument(
        "--slack-webhook",
        action="append",
        default=[],
        help="Slack webhook URL for alert delivery (can be used multiple times)",
    )
    parser.add_argument(
        "--email-recipient",
        action="append",
        default=[],
        help="Email recipient for alert delivery (can be used multiple times)",
    )
    parser.add_argument("--redis-url", help="Redis URL for cooldown tracking")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Evaluate alerts without sending notifications",
    )
    parser.add_argument(
        "--print-snapshot", action="store_true", help="Print telemetry snapshot JSON"
    )
    parser.add_argument(
        "--fail-on-alerts",
        action="store_true",
        help="Exit with non-zero status if any alerts are triggered",
    )
    parser.add_argument(
        "--fail-on-severity",
        choices=[severity.value for severity in RuleSeverity],
        help="Exit with non-zero status if alerts at or above the specified severity are triggered",
    )
    return parser.parse_args(argv)


async def _run_async(args: argparse.Namespace) -> int:
    alerts, snapshot = await run_telemetry_alerts(
        window_days=args.window_days,
        slack_webhooks=args.slack_webhook,
        email_recipients=args.email_recipient,
        redis_url=args.redis_url,
        dry_run=args.dry_run,
    )

    if args.print_snapshot:
        print(json.dumps(snapshot.to_dict(), indent=2))

    if alerts:
        print(f"Triggered {len(alerts)} telemetry alerts")
        for alert in alerts:
            print(
                f" - [{alert.severity.value.upper()}] {alert.rule.rule_id}: {alert.message}"
            )
    else:
        print("No telemetry alerts triggered")

    should_fail = False

    if alerts and args.fail_on_alerts:
        should_fail = True

    if alerts and args.fail_on_severity:
        threshold = RuleSeverity(args.fail_on_severity)
        severity_order = {
            RuleSeverity.INFO: 0,
            RuleSeverity.WARNING: 1,
            RuleSeverity.CRITICAL: 2,
        }
        threshold_rank = severity_order[threshold]
        if any(severity_order[alert.severity] >= threshold_rank for alert in alerts):
            should_fail = True

    return 1 if should_fail else 0


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO)
    args = _parse_args(argv)
    return asyncio.run(_run_async(args))


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
