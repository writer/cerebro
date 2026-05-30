#!/usr/bin/env python3
"""Summarize active Droid feedback and suggest local regression checks."""

from __future__ import annotations

import argparse
import json
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
    review_comments = gh_json(
        [
            "api",
            f"repos/writer/cerebro/pulls/{pr_number}/comments",
            "--paginate",
        ]
    )
    issue_comments = gh_json(
        [
            "api",
            f"repos/writer/cerebro/issues/{pr_number}/comments",
            "--paginate",
        ]
    )
    comments: list[DroidComment] = []
    for item in review_comments:
        if not is_droid(item):
            continue
        comments.append(
            DroidComment(
                kind="review",
                url=item.get("html_url", ""),
                path=item.get("path", ""),
                line=item.get("line") or item.get("original_line"),
                body=item.get("body", ""),
            )
        )
    for item in issue_comments:
        if not is_droid(item):
            continue
        comments.append(
            DroidComment(
                kind="summary",
                url=item.get("html_url", ""),
                path="",
                line=None,
                body=item.get("body", ""),
            )
        )
    return comments


def is_droid(item: dict[str, object]) -> bool:
    user = item.get("user") or {}
    if not isinstance(user, dict):
        return False
    return str(user.get("login", "")).lower() == "factory-droid[bot]"


def suggested_checks(comment: DroidComment) -> list[str]:
    text = f"{comment.path}\n{comment.body}".lower()
    checks: list[str] = []
    if "io.readall" in text or "limitreader" in text or "body read" in text:
        checks.append("make droid-review-preflight")
        checks.append("go test ./tools/droidreview/...")
        checks.append("go test ./tools/archtests -run '^TestProductionBodyReadsAreBounded$' -count=1 -v")
    if "cypher" in text or "graphagent" in text or "tenant" in text:
        checks.append("go test ./internal/graphagent -count=1")
    if "sourcehttp" in text or "ssrf" in text or "dns" in text:
        checks.append("go test ./tools/archtests -run '^TestSourcesUseSharedHTTPSafety$' -count=1 -v")
    if "candidate" in text or "compare-and-swap" in text or "atomic" in text:
        checks.append("go test ./internal/findings -count=1")
    if not checks:
        checks.append("add a focused regression test near the changed package")
    return checks


def first_sentence(markdown: str) -> str:
    for line in markdown.splitlines():
        stripped = line.strip(" #*>-")
        if stripped:
            return stripped[:180]
    return "(empty comment)"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pr", help="pull request number")
    args = parser.parse_args()

    try:
        comments = collect_comments(args.pr)
    except subprocess.CalledProcessError as exc:
        print(exc.stderr, file=sys.stderr)
        return exc.returncode

    if not comments:
        print(f"No Droid comments found on PR #{args.pr}.")
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
