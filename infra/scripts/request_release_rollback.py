#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import UTC, datetime
import os
from pathlib import Path
import sys
import time
from typing import Any

from release_promotion import (
    find_successful_deployment,
    gh_json,
    parse_stable_tag,
    read_stack_digest,
    read_stack_tag,
    resolve_image_digest,
    run,
)


ROLLBACK_LABEL = "approved-cerebro-rollback"
PAUSE_LABEL = "cerebro-promotion-paused"
PAUSE_ISSUE_TITLE = "Cerebro automatic promotion paused"


def _published_release(source_repository: str, tag: str) -> dict[str, Any]:
    release = gh_json(["api", f"repos/{source_repository}/releases/tags/{tag}"])
    if (
        not isinstance(release, dict)
        or release.get("tag_name") != tag
        or release.get("draft")
        or release.get("prerelease")
    ):
        raise RuntimeError(f"{tag} is not a published stable release")
    return release


def _find_open_pr(repository: str, branch: str) -> str:
    pulls = gh_json(
        [
            "pr",
            "list",
            "--repo",
            repository,
            "--state",
            "open",
            "--head",
            branch,
            "--json",
            "url",
        ]
    )
    if isinstance(pulls, list) and pulls and isinstance(pulls[0], dict):
        return str(pulls[0].get("url") or "")
    return ""


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _ensure_promotion_pause(
    repository: str, *, image_tag: str, environment: str, reason: str
) -> str:
    run(
        [
            "gh",
            "label",
            "create",
            PAUSE_LABEL,
            "--repo",
            repository,
            "--color",
            "B60205",
            "--description",
            "Automatic stable release promotion is paused",
            "--force",
        ]
    )
    issues = gh_json(
        [
            "issue",
            "list",
            "--repo",
            repository,
            "--state",
            "open",
            "--label",
            PAUSE_LABEL,
            "--json",
            "number,title,createdAt",
        ]
    )
    body = "\n".join(
        [
            f"Automatic stable release promotion is paused for the `{environment}` rollback to `{image_tag}`.",
            "",
            f"Reason: {reason}",
            "",
            "Complete and verify the rollback, then run the approved resume workflow. Until then, the reconciler will not restore the latest stable release.",
        ]
    )
    pause_issue = next(
        (
            issue
            for issue in issues or []
            if isinstance(issue, dict)
            and issue.get("title") == PAUSE_ISSUE_TITLE
            and isinstance(issue.get("number"), int)
        ),
        None,
    )
    if pause_issue is None:
        run(
            [
                "gh",
                "issue",
                "create",
                "--repo",
                repository,
                "--title",
                PAUSE_ISSUE_TITLE,
                "--label",
                PAUSE_LABEL,
                "--body",
                body,
            ]
        )
        created = gh_json(
            [
                "issue",
                "list",
                "--repo",
                repository,
                "--state",
                "open",
                "--label",
                PAUSE_LABEL,
                "--json",
                "number,title,createdAt",
            ]
        )
        pause_issue = next(
            (
                issue
                for issue in created or []
                if isinstance(issue, dict) and issue.get("title") == PAUSE_ISSUE_TITLE
            ),
            None,
        )
    else:
        run(
            [
                "gh",
                "issue",
                "edit",
                str(pause_issue["number"]),
                "--repo",
                repository,
                "--body",
                body,
            ]
        )
    created_at = str((pause_issue or {}).get("createdAt") or "")
    if not created_at:
        raise RuntimeError(
            "Could not resolve the automatic promotion pause creation time"
        )
    return created_at


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Request a reviewed Cerebro image rollback."
    )
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--source-repository", default="writer/cerebro")
    parser.add_argument("--environment", required=True, choices=("sec-dev", "go-prod"))
    parser.add_argument("--image-tag", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument("--wait-seconds", type=int, default=600)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if not args.repository:
        raise RuntimeError("GITHUB_REPOSITORY or --repository is required")
    target_version = parse_stable_tag(args.image_tag)
    current_tag = read_stack_tag(args.stack_file)
    if target_version >= parse_stable_tag(current_tag):
        raise RuntimeError(
            f"Rollback target {args.image_tag} must be older than current {args.environment} tag {current_tag}"
        )
    _published_release(args.source_repository, args.image_tag)
    digest = resolve_image_digest(args.image_tag)

    pause_created_at = _ensure_promotion_pause(
        args.repository,
        image_tag=args.image_tag,
        environment=args.environment,
        reason=args.reason,
    )

    if args.environment == "go-prod":
        sec_dev_stack = args.stack_file.with_name("Pulumi.sec-dev.yaml")
        if (
            read_stack_tag(sec_dev_stack) != args.image_tag
            or read_stack_digest(sec_dev_stack) != digest
        ):
            raise RuntimeError(
                f"Rollback {args.image_tag} must be the current sec-dev release lock before go-prod can be requested"
            )
        receipt = find_successful_deployment(
            args.repository,
            environment="sec-dev",
            image_tag=args.image_tag,
            image_digest=digest,
        )
        if receipt is None:
            raise RuntimeError(
                f"Rollback {args.image_tag} must complete a successful sec-dev deployment before go-prod can be requested"
            )
        if not receipt.created_at or _parse_datetime(
            receipt.created_at
        ) < _parse_datetime(pause_created_at):
            raise RuntimeError(
                f"Rollback {args.image_tag} requires a sec-dev deployment completed after automatic promotion was paused"
            )

    branch = f"automation/cerebro-image-{args.environment}-{args.image_tag}"
    pr_url = _find_open_pr(args.repository, branch)
    if not pr_url:
        run(
            [
                "gh",
                "workflow",
                "run",
                "propose-image-tag.yml",
                "--repo",
                args.repository,
                "--ref",
                "main",
                "-f",
                f"environment={args.environment}",
                "-f",
                f"image_tag={args.image_tag}",
            ]
        )
        deadline = time.monotonic() + args.wait_seconds
        while time.monotonic() < deadline:
            pr_url = _find_open_pr(args.repository, branch)
            if pr_url:
                break
            time.sleep(5)
    if not pr_url:
        raise RuntimeError(
            f"Timed out waiting for the {args.environment} rollback PR for {args.image_tag}"
        )

    if args.environment == "go-prod":
        run(
            [
                "gh",
                "label",
                "create",
                ROLLBACK_LABEL,
                "--repo",
                args.repository,
                "--color",
                "B60205",
                "--description",
                "Approved production image rollback",
                "--force",
            ]
        )
        run(
            [
                "gh",
                "pr",
                "edit",
                pr_url,
                "--repo",
                args.repository,
                "--add-label",
                ROLLBACK_LABEL,
            ]
        )
    run(
        [
            "gh",
            "pr",
            "comment",
            pr_url,
            "--repo",
            args.repository,
            "--body",
            f"Rollback requested through the approved workflow. Reason: {args.reason}",
        ]
    )
    print(f"Rollback PR ready for review: {pr_url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
