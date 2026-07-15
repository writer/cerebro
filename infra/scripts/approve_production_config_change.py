#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import sys

from release_promotion import (
    PRODUCTION_CONFIG_APPROVAL_CONTEXT,
    gh_json,
    post_commit_status,
)


def approve_pull_request(repository: str, pr_number: int, head_sha: str) -> str:
    if re.fullmatch(r"[0-9a-f]{40}", head_sha) is None:
        raise RuntimeError("--head-sha must be a full lowercase commit SHA")
    pull = gh_json(["api", f"repos/{repository}/pulls/{pr_number}"])
    if not isinstance(pull, dict) or pull.get("state") != "open":
        raise RuntimeError(f"Pull request #{pr_number} is not open")
    base = pull.get("base") or {}
    head = pull.get("head") or {}
    head_repository = head.get("repo") or {} if isinstance(head, dict) else {}
    if (
        not isinstance(base, dict)
        or base.get("ref") != "main"
        or not isinstance(head, dict)
        or not isinstance(head_repository, dict)
        or str(head_repository.get("full_name") or "").lower()
        != repository.lower()
    ):
        raise RuntimeError(
            f"Pull request #{pr_number} must target main from this repository"
        )
    current_head_sha = str(head.get("sha") or "")
    if current_head_sha != head_sha:
        raise RuntimeError(
            f"Pull request #{pr_number} head changed; review and approve {current_head_sha}"
        )
    server_url = os.environ.get("GITHUB_SERVER_URL", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not server_url or not run_id.isdigit():
        raise RuntimeError("Could not record production configuration approval")
    target_url = f"{server_url}/{repository}/actions/runs/{run_id}"
    post_commit_status(
        repository,
        sha=head_sha,
        state="success",
        context=PRODUCTION_CONFIG_APPROVAL_CONTEXT,
        description=f"Protected production configuration approval for PR #{pr_number}",
        target_url=target_url,
    )
    return target_url


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Record a protected approval for a production configuration PR."
    )
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--pr-number", type=int, required=True)
    parser.add_argument("--head-sha", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if not args.repository:
        raise RuntimeError("GITHUB_REPOSITORY or --repository is required")
    target_url = approve_pull_request(args.repository, args.pr_number, args.head_sha)
    print(f"Production configuration PR #{args.pr_number} approved: {target_url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
