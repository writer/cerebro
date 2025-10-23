"""Run security posture health checks for operator workflows."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from cerebro.automation.security_checks import (
    find_stale_admins,
    has_cel_canary,
    tools_missing_attestation,
)
from cerebro.core.database import async_session_factory


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Cerebro security health checks")
    parser.add_argument(
        "--max-admin-age-days",
        type=int,
        default=90,
        help="Maximum allowed age for admin credentials since last login",
    )
    parser.add_argument(
        "--canary-rule-name",
        default="cel.canary.policy",
        help="Rule name to treat as CEL canary",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional JSON file for check results",
    )
    parser.add_argument(
        "--fail-on-issues",
        action="store_true",
        help="Return non-zero exit code when issues are detected",
    )
    return parser.parse_args()


async def _run(args: argparse.Namespace) -> int:
    async with async_session_factory() as db:
        stale_admins = await find_stale_admins(db, max_age_days=args.max_admin_age_days)
        canary_present = await has_cel_canary(db, rule_name=args.canary_rule_name)

    attestation_gaps = tools_missing_attestation()

    report = {
        "stale_admins": [admin.__dict__ for admin in stale_admins],
        "cel_canary_present": canary_present,
        "tools_missing_attestation": attestation_gaps,
    }

    print("Security Health Report")
    print("======================")
    print(json.dumps(report, indent=2, sort_keys=True, default=str))

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True, default=str), encoding="utf-8")
        print(f"Report written to {args.output}")

    issues_detected = bool(stale_admins or not canary_present or attestation_gaps)

    if args.fail_on_issues and issues_detected:
        return 1

    return 0


def main() -> int:
    args = _parse_args()
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
