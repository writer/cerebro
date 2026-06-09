#!/usr/bin/env python3
"""Summarize active Droid feedback and suggest local regression checks."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass


@dataclass
class DroidComment:
    kind: str
    url: str
    path: str
    line: int | None
    body: str


def gh_json(args: list[str]) -> object:
    completed = subprocess.run(
        ["gh", *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return json.loads(completed.stdout)


def collect_comments(pr_number: str) -> list[DroidComment]:
    repository = os.environ.get("GITHUB_REPOSITORY", "WriterInternal/cerebro")
    review_comments = gh_json(
        [
            "api",
            f"repos/{repository}/pulls/{pr_number}/comments",
            "--paginate",
        ]
    )
    issue_comments = gh_json(
        [
            "api",
            f"repos/{repository}/issues/{pr_number}/comments",
            "--paginate",
        ]
    )
    comments: list[DroidComment] = []
    for item in review_comments:
        if not is_droid(item):
            continue
        body = item.get("body", "")
        if is_superseded(body):
            continue
        comments.append(
            DroidComment(
                kind="review",
                url=item.get("html_url", ""),
                path=item.get("path", ""),
                line=item.get("line") or item.get("original_line"),
                body=body,
            )
        )
    for item in issue_comments:
        if not is_droid(item):
            continue
        body = item.get("body", "")
        if is_superseded(body):
            continue
        comments.append(
            DroidComment(
                kind="summary",
                url=item.get("html_url", ""),
                path="",
                line=None,
                body=body,
            )
        )
    return comments


def is_droid(item: dict[str, object]) -> bool:
    user = item.get("user") or {}
    if not isinstance(user, dict):
        return False
    return str(user.get("login", "")).lower() in {"factory-droid", "factory-droid[bot]"}


def is_superseded(body: str) -> bool:
    lowered = body.lower()
    return (
        "superseded" in lowered
        or "view job" in lowered and "encountered an error" in lowered
        or "lgtm" in lowered
        or "no issues found" in lowered
        or "no inline comments to post" in lowered
    )


def suggested_checks(comment: DroidComment) -> list[str]:
    text = f"{comment.path}\n{comment.body}".lower()
    checks: list[str] = []
    if ".github/workflows" in text or "workflow" in text or "permission" in text or "token" in text:
        checks.append("make droid-review-preflight")
        checks.append("python3 -m unittest discover -s infra/tests")
    if "iam" in text or "policy" in text or "pulumi" in text or "aws" in text:
        checks.append("python3 -m compileall -q infra/aws infra/scripts infra/tests")
        checks.append("python3 infra/scripts/validate_stack_config.py infra/aws/Pulumi.sec-dev.yaml infra/aws/Pulumi.go-prod.yaml")
    if "gcp" in text or "workload identity" in text:
        checks.append("python3 infra/scripts/validate_gcp_config.py")
    if not checks:
        checks.append("add or update a focused regression test near the changed infra/script surface")
    return checks


def classify_pass(comment: DroidComment) -> str:
    text = f"{comment.path}\n{comment.body}".lower()
    if "workflow" in text or ".github/workflows" in text or "permission" in text or "token" in text:
        return "workflow-permissions"
    if "iam" in text or "policy" in text or "pulumi" in text or "aws" in text:
        return "aws-infra-safety"
    if "gcp" in text:
        return "gcp-infra-safety"
    if "test" in text or "regression" in text or "flake" in text:
        return "tests-evals"
    return "changed-behavior"


def comments_json(comments: list[DroidComment]) -> dict[str, object]:
    return {
        "kind": "droid_feedback_context",
        "active_comments": [
            {
                "kind": comment.kind,
                "url": comment.url,
                "path": comment.path,
                "line": comment.line,
                "summary": first_sentence(comment.body),
                "pass": classify_pass(comment),
                "suggested_checks": suggested_checks(comment),
            }
            for comment in comments
        ],
    }


def first_sentence(markdown: str) -> str:
    for line in markdown.splitlines():
        stripped = line.strip(" #*>-")
        if stripped:
            return stripped[:180]
    return "(empty comment)"


def regression_checklist(comments: list[DroidComment]) -> str:
    lines = ["# Droid Feedback Regression Checklist", ""]
    if not comments:
        lines.append("No active Droid comments found.")
        lines.append("")
        return "\n".join(lines)
    for index, comment in enumerate(comments, start=1):
        location = comment.path
        if comment.line:
            location = f"{location}:{comment.line}"
        location = location or comment.kind
        lines.extend(
            [
                f"## {index}. {location}",
                "",
                f"- Comment: {first_sentence(comment.body)}",
                f"- URL: {comment.url}",
                "- Regression checks:",
            ]
        )
        for check in suggested_checks(comment):
            lines.append(f"  - [ ] `{check}`")
        lines.extend(
            [
                "- Local test added/updated:",
                "  - [ ] Yes",
                "- Notes:",
                "",
            ]
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pr", help="pull request number")
    parser.add_argument("--markdown-out", help="optional path for a markdown regression checklist")
    parser.add_argument("--json-out", help="optional path for structured feedback context")
    args = parser.parse_args()

    try:
        comments = collect_comments(args.pr)
    except subprocess.CalledProcessError as exc:
        print(exc.stderr, file=sys.stderr)
        return exc.returncode

    if not comments:
        print(f"No Droid comments found on PR #{args.pr}.")
        if args.markdown_out:
            ensure_parent_dir(args.markdown_out)
            with open(args.markdown_out, "w", encoding="utf-8") as handle:
                handle.write(regression_checklist(comments))
        if args.json_out:
            ensure_parent_dir(args.json_out)
            with open(args.json_out, "w", encoding="utf-8") as handle:
                json.dump(comments_json(comments), handle, indent=2, sort_keys=True)
                handle.write("\n")
        return 0

    print(f"Found {len(comments)} Droid comment(s) on PR #{args.pr}.\n")
    for index, comment in enumerate(comments, start=1):
        location = comment.path
        if comment.line:
            location = f"{location}:{comment.line}"
        location = location or comment.kind
        print(f"{index}. {location}")
        print(f"   {first_sentence(comment.body)}")
        print(f"   {comment.url}")
        print("   Suggested local checks:")
        for check in suggested_checks(comment):
            print(f"   - {check}")
        print()
    if args.markdown_out:
        ensure_parent_dir(args.markdown_out)
        with open(args.markdown_out, "w", encoding="utf-8") as handle:
            handle.write(regression_checklist(comments))
        print(f"Wrote regression checklist to {args.markdown_out}.")
    if args.json_out:
        ensure_parent_dir(args.json_out)
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(comments_json(comments), handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(f"Wrote feedback context JSON to {args.json_out}.")
    return 0


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
