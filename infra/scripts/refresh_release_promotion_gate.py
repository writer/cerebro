#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
import re
import sys
from typing import Any

from release_promotion import (
    DeploymentReceipt,
    IMAGE_DIGEST_KEY,
    IMAGE_TAG_KEY,
    PRODUCTION_CONFIG_APPROVAL_CONTEXT,
    ROLLBACK_APPROVAL_CONTEXT,
    find_successful_deployment,
    gh_json,
    parse_stable_tag,
    post_commit_status,
    read_stack_digest_text,
    read_stack_tag_text,
    repository_file,
    resolve_image_digest,
)


CONTEXT = "promotion/sec-dev-deployed"
GO_PROD_CONFIG = "infra/aws/Pulumi.go-prod.yaml"
ROLLBACK_WORKFLOW_PATH = ".github/workflows/request-cerebro-image-rollback.yml"
ROLLBACK_ENVIRONMENT = "production-rollback"
PRODUCTION_CONFIG_WORKFLOW_PATH = (
    ".github/workflows/approve-production-configuration.yml"
)
PRODUCTION_CONFIG_ENVIRONMENT = "production-config-change"


@dataclass(frozen=True)
class GateResult:
    state: str
    description: str
    target_url: str = ""


def evaluate_gate(
    *,
    base_tag: str,
    target_tag: str,
    rollback_approved: bool,
    sec_dev_receipt: DeploymentReceipt | None,
    base_digest: str = "",
    target_digest: str = "",
    production_config_changed: bool = False,
    production_config_approved: bool = False,
) -> GateResult:
    if production_config_changed and not production_config_approved:
        return GateResult(
            "pending", "Production configuration approval is required"
        )
    if target_tag == base_tag and target_digest == base_digest:
        return GateResult("success", "No production image change")
    base_version = parse_stable_tag(base_tag)
    target_version = parse_stable_tag(target_tag)
    if target_version < base_version and not rollback_approved:
        return GateResult(
            "failure", "Production rollback requires the approved rollback workflow"
        )
    if sec_dev_receipt is None:
        return GateResult("pending", f"Waiting for sec-dev deployment of {target_tag}")
    return GateResult(
        "success",
        f"sec-dev deployed {target_tag} with the production digest",
        sec_dev_receipt.target_url,
    )


def _pull_numbers(repository: str, explicit_number: int | None) -> list[int]:
    if explicit_number is not None:
        return [explicit_number]
    pulls = gh_json(
        ["api", f"repos/{repository}/pulls?state=open&base=main&per_page=100"]
    )
    if not isinstance(pulls, list):
        return []
    return [
        int(pull["number"])
        for pull in pulls
        if isinstance(pull, dict) and isinstance(pull.get("number"), int)
    ]


def _published_release(source_repository: str, tag: str) -> bool:
    try:
        release = gh_json(["api", f"repos/{source_repository}/releases/tags/{tag}"])
    except RuntimeError:
        return False
    return (
        isinstance(release, dict)
        and release.get("tag_name") == tag
        and not release.get("draft")
        and not release.get("prerelease")
    )


def _approved_environment_review(reviews: Any, environment_name: str) -> bool:
    if not isinstance(reviews, list):
        return False
    for review in reviews:
        if not isinstance(review, dict) or review.get("state") != "approved":
            continue
        environments = review.get("environments") or []
        if isinstance(environments, list) and any(
            isinstance(environment, dict)
            and environment.get("name") == environment_name
            for environment in environments
        ):
            return True
    return False


def _protected_workflow_approved(
    repository: str,
    head_sha: str,
    *,
    context: str,
    workflow_path: str,
    environment_name: str,
) -> bool:
    statuses = gh_json(
        ["api", f"repos/{repository}/commits/{head_sha}/statuses?per_page=100"]
    )
    if not isinstance(statuses, list):
        return False
    approval_status = next(
        (
            status
            for status in statuses
            if isinstance(status, dict)
            and status.get("context") == context
        ),
        None,
    )
    creator = approval_status.get("creator") or {} if approval_status else {}
    if (
        not isinstance(approval_status, dict)
        or approval_status.get("state") != "success"
        or not isinstance(creator, dict)
        or creator.get("login") != "github-actions[bot]"
    ):
        return False

    target_url = str(approval_status.get("target_url") or "")
    match = re.fullmatch(
        rf"https://github\.com/{re.escape(repository)}/actions/runs/(\d+)",
        target_url,
        flags=re.IGNORECASE,
    )
    if match is None:
        return False
    run_id = int(match.group(1))
    workflow_run = gh_json(["api", f"repos/{repository}/actions/runs/{run_id}"])
    if not isinstance(workflow_run, dict):
        return False
    run_repository = workflow_run.get("repository") or {}
    if (
        workflow_run.get("id") != run_id
        or workflow_run.get("event") != "workflow_dispatch"
        or workflow_run.get("head_branch") != "main"
        or workflow_run.get("path") != workflow_path
        or workflow_run.get("conclusion") != "success"
        or workflow_run.get("html_url") != target_url
        or not isinstance(run_repository, dict)
        or str(run_repository.get("full_name") or "").lower() != repository.lower()
    ):
        return False
    reviews = gh_json(
        ["api", f"repos/{repository}/actions/runs/{run_id}/approvals"]
    )
    return _approved_environment_review(reviews, environment_name)


def _rollback_approved(repository: str, head_sha: str) -> bool:
    return _protected_workflow_approved(
        repository,
        head_sha,
        context=ROLLBACK_APPROVAL_CONTEXT,
        workflow_path=ROLLBACK_WORKFLOW_PATH,
        environment_name=ROLLBACK_ENVIRONMENT,
    )


def _production_config_approved(repository: str, head_sha: str) -> bool:
    return _protected_workflow_approved(
        repository,
        head_sha,
        context=PRODUCTION_CONFIG_APPROVAL_CONTEXT,
        workflow_path=PRODUCTION_CONFIG_WORKFLOW_PATH,
        environment_name=PRODUCTION_CONFIG_ENVIRONMENT,
    )


def _without_release_lock(text: str) -> str:
    counts = {IMAGE_TAG_KEY: 0, IMAGE_DIGEST_KEY: 0}
    retained: list[str] = []
    patterns = {key: re.compile(rf"^\s*{re.escape(key)}\s*:") for key in counts}
    for line in text.splitlines(keepends=True):
        key = next(
            (key for key, pattern in patterns.items() if pattern.match(line)), None
        )
        if key is None:
            retained.append(line)
            continue
        counts[key] += 1
    for key, count in counts.items():
        if count != 1:
            raise ValueError(f"{key} must appear exactly once")
    return "".join(retained)


def _production_config_changed(base_text: str, target_text: str) -> bool:
    return _without_release_lock(base_text) != _without_release_lock(target_text)


def _refresh_pull(repository: str, source_repository: str, number: int) -> GateResult:
    pull = gh_json(["api", f"repos/{repository}/pulls/{number}"])
    if not isinstance(pull, dict):
        raise RuntimeError(f"Could not read pull request #{number}")
    head = pull.get("head") or {}
    base = pull.get("base") or {}
    head_sha = str(head.get("sha") or "") if isinstance(head, dict) else ""
    base_sha = str(base.get("sha") or "") if isinstance(base, dict) else ""
    if not head_sha or not base_sha:
        raise RuntimeError(f"Pull request #{number} is missing its head or base SHA")

    try:
        base_text = repository_file(repository, GO_PROD_CONFIG, base_sha)
        target_text = repository_file(repository, GO_PROD_CONFIG, head_sha)
        base_tag = read_stack_tag_text(base_text)
        target_tag = read_stack_tag_text(target_text)
        base_digest = read_stack_digest_text(base_text)
        target_digest = read_stack_digest_text(target_text)
        production_config_changed = _production_config_changed(base_text, target_text)
        parse_stable_tag(target_tag)
    except (RuntimeError, ValueError) as error:
        result = GateResult(
            "failure", f"Invalid production image configuration: {error}"
        )
    else:
        try:
            production_config_approved = not production_config_changed or (
                _production_config_approved(repository, head_sha)
            )
        except RuntimeError as error:
            result = GateResult(
                "error", "Production configuration approval unavailable; retry scheduled"
            )
            print(
                f"::error::PR #{number} production configuration approval failed: {error}",
                file=sys.stderr,
            )
        else:
            if production_config_changed and not production_config_approved:
                result = GateResult(
                    "pending", "Production configuration approval is required"
                )
            elif target_tag == base_tag and target_digest == base_digest:
                result = GateResult("success", "No production image change")
            elif not _published_release(source_repository, target_tag):
                result = GateResult(
                    "failure", f"{target_tag} is not a published stable release"
                )
            else:
                try:
                    resolved_digest = resolve_image_digest(target_tag)
                    if resolved_digest != target_digest:
                        result = GateResult(
                            "failure",
                            f"Reviewed digest does not match published {target_tag}",
                        )
                    else:
                        rollback_approved = False
                        if parse_stable_tag(target_tag) < parse_stable_tag(base_tag):
                            rollback_approved = _rollback_approved(repository, head_sha)
                        receipt = find_successful_deployment(
                            repository,
                            environment="sec-dev",
                            image_tag=target_tag,
                            image_digest=target_digest,
                        )
                        result = evaluate_gate(
                            base_tag=base_tag,
                            target_tag=target_tag,
                            rollback_approved=rollback_approved,
                            sec_dev_receipt=receipt,
                            base_digest=base_digest,
                            target_digest=target_digest,
                            production_config_changed=production_config_changed,
                            production_config_approved=production_config_approved,
                        )
                except RuntimeError as error:
                    result = GateResult(
                        "error", "Release verification unavailable; retry scheduled"
                    )
                    print(
                        f"::error::PR #{number} release verification failed: {error}",
                        file=sys.stderr,
                    )

    post_commit_status(
        repository,
        sha=head_sha,
        state=result.state,
        context=CONTEXT,
        description=result.description,
        target_url=result.target_url,
    )
    print(f"PR #{number}: {result.state}: {result.description}")
    return result


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Refresh the required production image promotion status."
    )
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--source-repository", default="writer/cerebro")
    parser.add_argument("--pr-number", type=int)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if not args.repository:
        raise RuntimeError("GITHUB_REPOSITORY or --repository is required")
    numbers = _pull_numbers(args.repository, args.pr_number)
    had_error = False
    for number in numbers:
        try:
            result = _refresh_pull(args.repository, args.source_repository, number)
        except Exception as error:
            had_error = True
            print(
                f"::error::PR #{number} promotion status refresh failed: {error}",
                file=sys.stderr,
            )
            continue
        had_error = had_error or result.state == "error"
    if not numbers:
        print("No open pull requests require a promotion status refresh")
    return 1 if had_error else 0


if __name__ == "__main__":
    raise SystemExit(main())
