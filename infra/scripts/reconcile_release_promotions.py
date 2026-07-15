#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import sys
from typing import Any

from release_promotion import (
    DeploymentReceipt,
    find_successful_deployment,
    gh_json,
    parse_stable_tag,
    read_stack_digest,
    read_stack_tag,
    resolve_image_digest,
    run,
)


PAUSE_LABEL = "cerebro-promotion-paused"


@dataclass(frozen=True)
class PromotionPlan:
    state: str
    dispatch_environment: str | None
    complete: bool
    detail: str


def build_plan(
    *,
    latest_tag: str,
    sec_dev_tag: str,
    go_prod_tag: str,
    sec_dev_receipt: DeploymentReceipt | None,
    go_prod_receipt: DeploymentReceipt | None,
    latest_digest: str | None = None,
    sec_dev_digest: str | None = None,
    go_prod_digest: str | None = None,
) -> PromotionPlan:
    latest = parse_stable_tag(latest_tag)
    sec_dev = parse_stable_tag(sec_dev_tag)
    go_prod = parse_stable_tag(go_prod_tag)

    if sec_dev > latest:
        return PromotionPlan(
            "blocked",
            None,
            False,
            f"sec-dev {sec_dev_tag} is newer than latest stable {latest_tag}; automatic downgrade refused",
        )
    if go_prod > latest:
        return PromotionPlan(
            "blocked",
            None,
            False,
            f"go-prod {go_prod_tag} is newer than latest stable {latest_tag}; automatic downgrade refused",
        )
    if sec_dev < latest or (
        sec_dev == latest
        and latest_digest is not None
        and sec_dev_digest != latest_digest
    ):
        return PromotionPlan(
            "sec-dev-promotion-required",
            "sec-dev",
            False,
            f"sec-dev release lock does not match {latest_tag}@{latest_digest or 'unknown'}",
        )
    if sec_dev_receipt is None:
        return PromotionPlan(
            "sec-dev-deployment-required",
            None,
            False,
            f"sec-dev config uses {latest_tag}, but no successful deployment receipt matches its digest",
        )
    if go_prod < latest or (
        go_prod == latest
        and latest_digest is not None
        and go_prod_digest != latest_digest
    ):
        return PromotionPlan(
            "go-prod-promotion-required",
            "go-prod",
            False,
            f"go-prod release lock does not match deployed sec-dev {latest_tag}@{latest_digest or 'unknown'}",
        )
    if go_prod_receipt is None:
        return PromotionPlan(
            "go-prod-deployment-required",
            None,
            False,
            f"go-prod config uses {latest_tag}, but no successful deployment receipt matches its digest",
        )
    return PromotionPlan(
        "complete",
        None,
        True,
        f"{latest_tag} is deployed successfully to sec-dev and go-prod",
    )


def _latest_release(source_repository: str) -> dict[str, Any]:
    pages = gh_json(
        [
            "api",
            "--paginate",
            "--slurp",
            f"repos/{source_repository}/releases?per_page=100",
        ]
    )
    releases: list[dict[str, Any]] = []
    if isinstance(pages, list):
        for page in pages:
            if isinstance(page, list):
                releases.extend(item for item in page if isinstance(item, dict))
            elif isinstance(page, dict):
                releases.append(page)
    stable: list[dict[str, Any]] = []
    for release in releases:
        tag = str(release.get("tag_name") or "")
        try:
            parse_stable_tag(tag)
        except ValueError:
            continue
        if not release.get("draft") and not release.get("prerelease"):
            stable.append(release)
    if not stable:
        raise RuntimeError(
            f"Could not resolve a published stable release from {source_repository}"
        )
    return max(stable, key=lambda release: parse_stable_tag(str(release["tag_name"])))


def _promotion_pause(repository: str) -> dict[str, Any] | None:
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
            "number,title,url",
        ]
    )
    if not isinstance(issues, list):
        return None
    return next((issue for issue in issues if isinstance(issue, dict)), None)


def _promotion_branch(environment: str, tag: str) -> str:
    return f"automation/cerebro-image-{environment}-{tag}"


def _promotion_is_active(repository: str, environment: str, tag: str) -> bool:
    branch = _promotion_branch(environment, tag)
    open_prs = gh_json(
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
            "number",
        ]
    )
    if isinstance(open_prs, list) and open_prs:
        return True

    runs = gh_json(
        [
            "run",
            "list",
            "--repo",
            repository,
            "--workflow",
            "propose-image-tag.yml",
            "--limit",
            "50",
            "--json",
            "displayTitle,status",
        ]
    )
    expected = f"Cerebro image {environment} {tag} "
    return isinstance(runs, list) and any(
        isinstance(item, dict)
        and item.get("status")
        in {"queued", "in_progress", "waiting", "pending", "requested"}
        and str(item.get("displayTitle") or "").startswith(expected)
        for item in runs
    )


def _dispatch_promotion(
    repository: str,
    *,
    source_repository: str,
    release: dict[str, Any],
    image_digest: str,
    environment: str,
) -> None:
    tag = str(release["tag_name"])
    request_id = (
        f"reconcile-{environment}-{tag}-{os.environ.get('GITHUB_RUN_ID', 'local')}"
    )
    payload = {
        "event_type": "cerebro-release-reconcile",
        "client_payload": {
            "image_tag": tag,
            "image_digest": image_digest,
            "release_url": str(release.get("html_url") or ""),
            "source_repository": source_repository,
            "source_ref": f"refs/tags/{tag}",
            "request_id": request_id,
            "target_environment": environment,
            "apply_mode": "trusted_sec_dev_release"
            if environment == "sec-dev"
            else "pull_request",
        },
    }
    gh_json(
        ["api", "--method", "POST", f"repos/{repository}/dispatches"],
        input_payload=payload,
    )
    print(f"Dispatched {environment} promotion for {tag}@{image_digest}")


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _open_stall_issue(repository: str, title: str) -> int | None:
    issues = gh_json(
        [
            "issue",
            "list",
            "--repo",
            repository,
            "--state",
            "open",
            "--search",
            f"{title} in:title",
            "--json",
            "number,title",
        ]
    )
    if not isinstance(issues, list):
        return None
    for issue in issues:
        if (
            isinstance(issue, dict)
            and issue.get("title") == title
            and isinstance(issue.get("number"), int)
        ):
            return int(issue["number"])
    return None


def _manage_stall_issue(
    repository: str,
    *,
    tag: str,
    plan: PromotionPlan,
    release_age_minutes: int,
    stale_after_minutes: int,
    sec_dev_tag: str,
    go_prod_tag: str,
) -> bool:
    title = f"Cerebro release promotion stalled: {tag}"
    issue_number = _open_stall_issue(repository, title)
    if plan.complete:
        if issue_number is not None:
            run(
                [
                    "gh",
                    "issue",
                    "close",
                    str(issue_number),
                    "--repo",
                    repository,
                    "--comment",
                    f"{tag} now has successful sec-dev and go-prod deployment receipts.",
                ]
            )
        return False

    if release_age_minutes < stale_after_minutes:
        return False

    body = "\n".join(
        [
            f"Release `{tag}` has not completed promotion after {release_age_minutes} minutes.",
            "",
            f"- State: `{plan.state}`",
            f"- sec-dev config: `{sec_dev_tag}`",
            f"- go-prod config: `{go_prod_tag}`",
            f"- Required action: {plan.detail}",
            "",
            "The reconciliation workflow will continue checking this release. Resolve the recorded state; do not merge the production image change without the required deployment status.",
        ]
    )
    if issue_number is None:
        run(
            [
                "gh",
                "issue",
                "create",
                "--repo",
                repository,
                "--title",
                title,
                "--body",
                body,
            ]
        )
    else:
        run(
            [
                "gh",
                "issue",
                "edit",
                str(issue_number),
                "--repo",
                repository,
                "--body",
                body,
            ]
        )
    return True


def _write_summary(
    *,
    tag: str,
    digest: str,
    plan: PromotionPlan,
    sec_dev_tag: str,
    go_prod_tag: str,
    release_age_minutes: int,
) -> None:
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary:
        return
    with Path(summary).open("a", encoding="utf-8") as handle:
        handle.write("## Cerebro release promotion\n\n")
        handle.write(f"- Release: `{tag}`\n")
        handle.write(f"- Digest: `{digest}`\n")
        handle.write(f"- State: `{plan.state}`\n")
        handle.write(f"- sec-dev: `{sec_dev_tag}`\n")
        handle.write(f"- go-prod: `{go_prod_tag}`\n")
        handle.write(f"- Release age: `{release_age_minutes} minutes`\n")
        handle.write(f"- Action: {plan.detail}\n")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reconcile the latest stable Cerebro release across deployment environments."
    )
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--source-repository", default="writer/cerebro")
    parser.add_argument(
        "--sec-dev-stack", type=Path, default=Path("aws/Pulumi.sec-dev.yaml")
    )
    parser.add_argument(
        "--go-prod-stack", type=Path, default=Path("aws/Pulumi.go-prod.yaml")
    )
    parser.add_argument("--stale-after-minutes", type=int, default=120)
    parser.add_argument("--manage-issue", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if not args.repository:
        raise RuntimeError("GITHUB_REPOSITORY or --repository is required")

    pause = _promotion_pause(args.repository)
    if pause is not None:
        print(
            json.dumps(
                {
                    "state": "paused",
                    "detail": "Automatic release promotion is paused for an approved rollback",
                    "pause_issue": pause.get("url"),
                }
            )
        )
        return 0

    release = _latest_release(args.source_repository)
    latest_tag = str(release["tag_name"])
    image_digest = resolve_image_digest(latest_tag)
    sec_dev_tag = read_stack_tag(args.sec_dev_stack)
    go_prod_tag = read_stack_tag(args.go_prod_stack)
    sec_dev_digest = read_stack_digest(args.sec_dev_stack)
    go_prod_digest = read_stack_digest(args.go_prod_stack)

    sec_dev_receipt = None
    if sec_dev_tag == latest_tag and sec_dev_digest == image_digest:
        sec_dev_receipt = find_successful_deployment(
            args.repository,
            environment="sec-dev",
            image_tag=latest_tag,
            image_digest=image_digest,
        )
    go_prod_receipt = None
    if go_prod_tag == latest_tag and go_prod_digest == image_digest:
        go_prod_receipt = find_successful_deployment(
            args.repository,
            environment="go-prod",
            image_tag=latest_tag,
            image_digest=image_digest,
        )

    plan = build_plan(
        latest_tag=latest_tag,
        sec_dev_tag=sec_dev_tag,
        go_prod_tag=go_prod_tag,
        sec_dev_receipt=sec_dev_receipt,
        go_prod_receipt=go_prod_receipt,
        latest_digest=image_digest,
        sec_dev_digest=sec_dev_digest,
        go_prod_digest=go_prod_digest,
    )
    if plan.dispatch_environment and not _promotion_is_active(
        args.repository, plan.dispatch_environment, latest_tag
    ):
        _dispatch_promotion(
            args.repository,
            source_repository=args.source_repository,
            release=release,
            image_digest=image_digest,
            environment=plan.dispatch_environment,
        )
    elif plan.dispatch_environment:
        print(
            f"{plan.dispatch_environment} promotion for {latest_tag} is already active"
        )

    published_at = str(release.get("published_at") or release.get("created_at") or "")
    release_age_minutes = 0
    if published_at:
        release_age_minutes = max(
            0,
            int(
                (datetime.now(UTC) - _parse_datetime(published_at)).total_seconds()
                // 60
            ),
        )
    stalled = False
    if args.manage_issue:
        stalled = _manage_stall_issue(
            args.repository,
            tag=latest_tag,
            plan=plan,
            release_age_minutes=release_age_minutes,
            stale_after_minutes=args.stale_after_minutes,
            sec_dev_tag=sec_dev_tag,
            go_prod_tag=go_prod_tag,
        )
    _write_summary(
        tag=latest_tag,
        digest=image_digest,
        plan=plan,
        sec_dev_tag=sec_dev_tag,
        go_prod_tag=go_prod_tag,
        release_age_minutes=release_age_minutes,
    )
    print(
        json.dumps(
            {"state": plan.state, "detail": plan.detail, "complete": plan.complete}
        )
    )
    return 1 if stalled or plan.state == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
