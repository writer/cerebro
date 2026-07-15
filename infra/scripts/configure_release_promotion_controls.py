#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from typing import Any
from urllib.parse import quote

from release_promotion import gh_json


RULESET_NAME = "Release promotion protection"
REQUIRED_STATUS = "promotion/sec-dev-deployed"
ACTIONS_INTEGRATION_ID = 15368
SECURITY_TEAM_ID = 6539261
SECURITY_CONTROL_PATTERNS = [
    ".github/CODEOWNERS",
    ".github/actions/**",
    ".github/scripts/**",
    ".github/workflows/**",
    "infra/aws/**/*.py",
    "infra/aws/Pulumi.yaml",
    "infra/pyproject.toml",
    "infra/scripts/**",
    "infra/uv.lock",
]


def ruleset_payload() -> dict[str, Any]:
    return {
        "name": RULESET_NAME,
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {
                "type": "pull_request",
                "parameters": {
                    "allowed_merge_methods": ["merge", "squash", "rebase"],
                    "dismiss_stale_reviews_on_push": True,
                    "require_code_owner_review": False,
                    "require_last_push_approval": False,
                    "required_approving_review_count": 0,
                    "required_review_thread_resolution": True,
                    "required_reviewers": [
                        {
                            "file_patterns": SECURITY_CONTROL_PATTERNS,
                            "minimum_approvals": 1,
                            "reviewer": {"id": SECURITY_TEAM_ID, "type": "Team"},
                        }
                    ],
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "required_status_checks": [
                        {
                            "context": REQUIRED_STATUS,
                            "integration_id": ACTIONS_INTEGRATION_ID,
                        }
                    ],
                    "strict_required_status_checks_policy": False,
                },
            },
        ],
    }


def _ruleset(repository: str) -> dict[str, Any] | None:
    summaries = gh_json(["api", f"repos/{repository}/rulesets"])
    if not isinstance(summaries, list):
        return None
    for summary in summaries:
        if isinstance(summary, dict) and summary.get("name") == RULESET_NAME:
            ruleset_id = summary.get("id")
            if isinstance(ruleset_id, int):
                detail = gh_json(["api", f"repos/{repository}/rulesets/{ruleset_id}"])
                return detail if isinstance(detail, dict) else None
    return None


def _environment(repository: str, name: str) -> dict[str, Any]:
    environment = gh_json(
        ["api", f"repos/{repository}/environments/{quote(name, safe='')}"]
    )
    if not isinstance(environment, dict):
        raise RuntimeError(f"Could not read the {name} environment")
    return environment


def _has_required_status(ruleset: dict[str, Any]) -> bool:
    rules = ruleset.get("rules") or []
    if not isinstance(rules, list):
        return False
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("type") != "required_status_checks":
            continue
        parameters = rule.get("parameters") or {}
        required = (
            parameters.get("required_status_checks") or []
            if isinstance(parameters, dict)
            else []
        )
        return any(
            isinstance(check, dict)
            and check.get("context") == REQUIRED_STATUS
            and check.get("integration_id") == ACTIONS_INTEGRATION_ID
            for check in required
        )
    return False


def _has_pull_request_rule(ruleset: dict[str, Any]) -> bool:
    rules = ruleset.get("rules") or []
    return isinstance(rules, list) and any(
        isinstance(rule, dict) and rule.get("type") == "pull_request" for rule in rules
    )


def _requires_security_control_review(ruleset: dict[str, Any]) -> bool:
    rules = ruleset.get("rules") or []
    if not isinstance(rules, list):
        return False
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("type") != "pull_request":
            continue
        parameters = rule.get("parameters") or {}
        if not isinstance(parameters, dict):
            return False
        required_reviewers = parameters.get("required_reviewers") or []
        return isinstance(required_reviewers, list) and any(
            isinstance(required, dict)
            and required.get("minimum_approvals") == 1
            and required.get("file_patterns") == SECURITY_CONTROL_PATTERNS
            and required.get("reviewer")
            == {"id": SECURITY_TEAM_ID, "type": "Team"}
            for required in required_reviewers
        )
    return False


def _has_rule(ruleset: dict[str, Any], rule_type: str) -> bool:
    rules = ruleset.get("rules") or []
    return isinstance(rules, list) and any(
        isinstance(rule, dict) and rule.get("type") == rule_type for rule in rules
    )


def _targets_default_branch(ruleset: dict[str, Any]) -> bool:
    conditions = ruleset.get("conditions") or {}
    ref_name = conditions.get("ref_name") or {} if isinstance(conditions, dict) else {}
    return (
        isinstance(ref_name, dict)
        and ref_name.get("include") == ["~DEFAULT_BRANCH"]
        and ref_name.get("exclude") == []
    )


def _protected_branch_environment(environment: dict[str, Any]) -> bool:
    policy = environment.get("deployment_branch_policy") or {}
    return (
        isinstance(policy, dict)
        and policy.get("protected_branches") is True
        and policy.get("custom_branch_policies") is False
    )


def _has_required_reviewer(environment: dict[str, Any]) -> bool:
    rules = environment.get("protection_rules") or []
    return isinstance(rules, list) and any(
        isinstance(rule, dict)
        and rule.get("type") == "required_reviewers"
        and isinstance(rule.get("reviewers"), list)
        and bool(rule["reviewers"])
        for rule in rules
    )


def _prevents_self_review(environment: dict[str, Any]) -> bool:
    return environment.get("prevent_self_review") is True


def verify_controls(repository: str) -> list[str]:
    errors: list[str] = []
    repo = gh_json(["api", f"repos/{repository}"])
    if not isinstance(repo, dict):
        errors.append("repository settings could not be read")
    else:
        if repo.get("allow_auto_merge") is not True:
            errors.append("repository auto-merge is disabled")
        if repo.get("delete_branch_on_merge") is not True:
            errors.append("merged automation branches are not deleted")

    ruleset = _ruleset(repository)
    if ruleset is None:
        errors.append(f"ruleset {RULESET_NAME!r} is missing")
    else:
        if ruleset.get("enforcement") != "active":
            errors.append(f"ruleset {RULESET_NAME!r} is not active")
        if ruleset.get("bypass_actors"):
            errors.append(f"ruleset {RULESET_NAME!r} has bypass actors")
        if not _targets_default_branch(ruleset):
            errors.append(
                f"ruleset {RULESET_NAME!r} does not target only the default branch"
            )
        if not _has_rule(ruleset, "deletion"):
            errors.append(f"ruleset {RULESET_NAME!r} allows default branch deletion")
        if not _has_rule(ruleset, "non_fast_forward"):
            errors.append(f"ruleset {RULESET_NAME!r} allows force pushes")
        if not _has_pull_request_rule(ruleset):
            errors.append(f"ruleset {RULESET_NAME!r} does not require pull requests")
        if not _requires_security_control_review(ruleset):
            errors.append(
                f"ruleset {RULESET_NAME!r} does not require security review for release controls"
            )
        if not _has_required_status(ruleset):
            errors.append(
                f"ruleset {RULESET_NAME!r} does not require {REQUIRED_STATUS}"
            )

    production = _environment(repository, "production")
    if not _protected_branch_environment(production):
        errors.append("production deployments are not limited to protected branches")

    rollback = _environment(repository, "production-rollback")
    if not _protected_branch_environment(rollback):
        errors.append(
            "production rollback requests are not limited to protected branches"
        )
    if not _has_required_reviewer(rollback):
        errors.append("production rollback requests do not require a reviewer")
    if not _prevents_self_review(rollback):
        errors.append("production rollback requests allow self-review")
    return errors


def apply_controls(repository: str, reviewer_ids: list[int]) -> None:
    gh_json(
        ["api", "--method", "PATCH", f"repos/{repository}"],
        input_payload={"allow_auto_merge": True, "delete_branch_on_merge": True},
    )

    existing = _ruleset(repository)
    if existing is None:
        gh_json(
            ["api", "--method", "POST", f"repos/{repository}/rulesets"],
            input_payload=ruleset_payload(),
        )
    else:
        ruleset_id = existing.get("id")
        if not isinstance(ruleset_id, int):
            raise RuntimeError(f"Ruleset {RULESET_NAME!r} has no numeric ID")
        gh_json(
            ["api", "--method", "PUT", f"repos/{repository}/rulesets/{ruleset_id}"],
            input_payload=ruleset_payload(),
        )

    branch_policy = {"protected_branches": True, "custom_branch_policies": False}
    gh_json(
        ["api", "--method", "PUT", f"repos/{repository}/environments/production"],
        input_payload={"deployment_branch_policy": branch_policy},
    )
    gh_json(
        [
            "api",
            "--method",
            "PUT",
            f"repos/{repository}/environments/production-rollback",
        ],
        input_payload={
            "wait_timer": 0,
            "prevent_self_review": True,
            "reviewers": [
                {"type": "User", "id": reviewer_id}
                for reviewer_id in reviewer_ids
            ],
            "deployment_branch_policy": branch_policy,
        },
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Apply or verify repository controls for release promotion."
    )
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--verify", action="store_true")
    parser.add_argument("--rollback-reviewer-id", type=int, action="append")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if not args.repository:
        raise RuntimeError("GITHUB_REPOSITORY or --repository is required")
    if args.apply:
        if not args.rollback_reviewer_id:
            raise RuntimeError("--rollback-reviewer-id is required with --apply")
        apply_controls(args.repository, args.rollback_reviewer_id)
    errors = verify_controls(args.repository)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("Release promotion repository controls are active")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
