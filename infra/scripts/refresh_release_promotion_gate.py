#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
import sys
from typing import Any

from release_promotion import (
    DeploymentReceipt,
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
ROLLBACK_LABEL = "approved-cerebro-rollback"


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
) -> GateResult:
    if target_tag == base_tag:
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


def _label_names(pull: dict[str, Any]) -> set[str]:
    labels = pull.get("labels") or []
    if not isinstance(labels, list):
        return set()
    return {
        str(label.get("name"))
        for label in labels
        if isinstance(label, dict) and label.get("name")
    }


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
        parse_stable_tag(target_tag)
    except (RuntimeError, ValueError) as error:
        result = GateResult(
            "failure", f"Invalid production image configuration: {error}"
        )
    else:
        if target_tag == base_tag:
            result = evaluate_gate(
                base_tag=base_tag,
                target_tag=target_tag,
                rollback_approved=False,
                sec_dev_receipt=None,
            )
        elif not _published_release(source_repository, target_tag):
            result = GateResult(
                "failure", f"{target_tag} is not a published stable release"
            )
        else:
            try:
                image_digest = read_stack_digest_text(target_text)
            except ValueError as error:
                result = GateResult(
                    "failure", f"Invalid production image digest: {error}"
                )
                image_digest = ""
            if not image_digest:
                post_commit_status(
                    repository,
                    sha=head_sha,
                    state=result.state,
                    context=CONTEXT,
                    description=result.description,
                )
                print(f"PR #{number}: {result.state}: {result.description}")
                return result
            resolved_digest = resolve_image_digest(target_tag)
            if resolved_digest != image_digest:
                result = GateResult(
                    "failure",
                    f"Reviewed digest does not match published {target_tag}",
                )
                post_commit_status(
                    repository,
                    sha=head_sha,
                    state=result.state,
                    context=CONTEXT,
                    description=result.description,
                )
                print(f"PR #{number}: {result.state}: {result.description}")
                return result
            receipt = find_successful_deployment(
                repository,
                environment="sec-dev",
                image_tag=target_tag,
                image_digest=image_digest,
            )
            result = evaluate_gate(
                base_tag=base_tag,
                target_tag=target_tag,
                rollback_approved=ROLLBACK_LABEL in _label_names(pull),
                sec_dev_receipt=receipt,
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
    for number in numbers:
        _refresh_pull(args.repository, args.source_repository, number)
    if not numbers:
        print("No open pull requests require a promotion status refresh")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
