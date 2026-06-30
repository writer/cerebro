#!/usr/bin/env python3
"""Conservative PR landing helper for Cerebro.

The helper exists to keep automated review branches alive until Droid has
finished. It intentionally waits for core checks, then merges and deletes the
branch only after the review gates and merge have succeeded.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time


PASS_BUCKETS = {"pass"}
DEFAULT_REQUIRED_CHECKS = (
    "tenant-data leak check",
    "gitleaks",
    "semgrep",
    "Semgrep OSS",
    "build",
    "test",
    "race",
    "coverage",
    "sdk",
    "sdk-dependency-audit",
    "mcp",
    "lint",
    "proto",
    "openapi",
    "catalog",
    "docs-drift",
    "readme",
    "oss-audit",
    "govulncheck",
    "release-smoke",
    "docker-smoke",
    "structural",
    "droid-review-preflight",
    "droid-review",
    "verify",
)
DEFAULT_MAX_CHANGED_LINES = 5000
DEFAULT_MAX_CHANGED_FILES = 50
DROID_BOT_LOGIN = "factory-droid[bot]"
DROID_FINISHED_MARKERS = ("Droid finished", "Review complete for PR")


def run_gh(args: list[str], repo: str, *, check: bool = True) -> str:
    command = ["gh", *args] if args and args[0] == "api" else ["gh", *args, "--repo", repo]
    result = subprocess.run(command, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(command)} failed:\n{result.stderr.strip()}")
    return result.stdout


def fetch_pr(pr_number: int, repo: str) -> dict[str, object]:
    raw = run_gh(
        [
            "pr",
            "view",
            str(pr_number),
            "--json",
            "number,state,headRefName,headRefOid,headRepository,headRepositoryOwner,url,additions,deletions,changedFiles,files",
        ],
        repo,
    )
    return json.loads(raw)


def fetch_checks(pr_number: int, repo: str) -> list[dict[str, object]]:
    raw = run_gh(
        [
            "pr",
            "checks",
            str(pr_number),
            "--json",
            "name,bucket,state,link,workflow",
        ],
        repo,
        check=False,
    )
    return json.loads(raw or "[]")


def fetch_comments(pr_number: int, repo: str) -> list[dict[str, object]]:
    raw = run_gh(
        [
            "api",
            f"repos/{repo}/issues/{pr_number}/comments?per_page=100",
            "--paginate",
            "--jq",
            "[.[] | {user:{login:.user.login,type:.user.type}, author_association:.author_association, body:.body, url:.html_url, created_at:.created_at}]",
        ],
        repo,
    )
    comments: list[dict[str, object]] = []
    for page in raw.splitlines():
        if not page.strip():
            continue
        parsed = json.loads(page)
        if isinstance(parsed, list):
            comments.extend(item for item in parsed if isinstance(item, dict))
    return comments


def repo_parts(repo: str) -> tuple[str, str]:
    owner, separator, name = repo.partition("/")
    if not owner or not separator or not name:
        raise RuntimeError(f"repo must be OWNER/NAME, got {repo!r}")
    return owner, name


def fetch_active_review_threads(pr_number: int, repo: str) -> list[dict[str, object]]:
    owner, name = repo_parts(repo)
    query = """
    query($owner:String!, $name:String!, $number:Int!, $after:String) {
      repository(owner:$owner, name:$name) {
        pullRequest(number:$number) {
          reviewThreads(first:100, after:$after) {
            nodes {
              isResolved
              isOutdated
              path
              line
              comments(last:1) {
                nodes {
                  url
                  body
                }
              }
            }
            pageInfo {
              hasNextPage
              endCursor
            }
          }
        }
      }
    }
    """
    active_threads = []
    cursor: str | None = None
    while True:
        args = [
            "api",
            "graphql",
            "-f",
            f"owner={owner}",
            "-f",
            f"name={name}",
            "-F",
            f"number={pr_number}",
            "-f",
            f"query={query}",
        ]
        if cursor:
            args.extend(["-f", f"after={cursor}"])
        else:
            args.extend(["-F", "after=null"])
        raw = run_gh(args, repo)
        parsed = json.loads(raw)
        review_threads = (
            parsed.get("data", {})
            .get("repository", {})
            .get("pullRequest", {})
            .get("reviewThreads", {})
        )
        for thread in review_threads.get("nodes", []):
            if thread.get("isResolved") or thread.get("isOutdated"):
                continue
            comments = thread.get("comments", {}).get("nodes", [])
            latest = comments[-1] if comments else {}
            active_threads.append(
                {
                    "path": thread.get("path") or "",
                    "line": thread.get("line"),
                    "url": latest.get("url") or "",
                    "body": latest.get("body") or "",
                }
            )
        page_info = review_threads.get("pageInfo", {})
        if not page_info.get("hasNextPage"):
            return active_threads
        cursor = str(page_info.get("endCursor") or "")
        if not cursor:
            raise RuntimeError("review thread pagination did not return an end cursor")


def check_named_status(checks: list[dict[str, object]], name: str) -> tuple[bool, str]:
    matches = [check for check in checks if check.get("name") == name]
    if not matches:
        return False, f"missing check {name!r}"
    latest = matches[-1]
    if latest.get("bucket") in PASS_BUCKETS:
        return True, ""
    return False, f"{name!r} is {latest.get('bucket') or latest.get('state')}: {latest.get('link') or ''}"


def check_required_statuses(checks: list[dict[str, object]], required: tuple[str, ...]) -> tuple[bool, str]:
    failures = []
    for name in required:
        ok, reason = check_named_status(checks, name)
        if not ok:
            failures.append(reason)
    if failures:
        return False, "; ".join(failures[:8])
    return True, ""


def pr_change_count(pr: dict[str, object], key: str) -> int:
    value = pr.get(key)
    return int(value) if isinstance(value, int) else 0


def check_pr_size(
    pr: dict[str, object],
    *,
    max_changed_lines: int,
    max_changed_files: int,
    allow_large_pr: bool,
) -> tuple[bool, str]:
    changed_lines = pr_change_count(pr, "additions") + pr_change_count(pr, "deletions")
    changed_files = pr_change_count(pr, "changedFiles")
    failures = []
    if changed_lines > max_changed_lines:
        failures.append(f"{changed_lines} changed lines exceeds {max_changed_lines}")
    if changed_files > max_changed_files:
        failures.append(f"{changed_files} changed files exceeds {max_changed_files}")
    if not failures:
        return True, ""
    reason = "; ".join(failures)
    if allow_large_pr:
        print(f"large PR override: {reason}")
        return True, ""
    return False, f"{reason}; rerun with --allow-large-pr after confirming the diff is intentionally large"


def is_droid_comment(comment: dict[str, object]) -> bool:
    user = comment.get("user")
    if isinstance(user, dict):
        login = str(user.get("login") or "").lower()
        user_type = str(user.get("type") or "")
    else:
        login = str(user or "").lower()
        user_type = str(comment.get("user_type") or "")
    return login == DROID_BOT_LOGIN and (not user_type or user_type == "Bot")


def is_finished_droid_review(body: object) -> bool:
    text = str(body or "")
    return any(marker in text for marker in DROID_FINISHED_MARKERS)


def latest_droid_comment(comments: list[dict[str, object]]) -> dict[str, object] | None:
    droid_comments = [comment for comment in comments if is_droid_comment(comment)]
    return droid_comments[-1] if droid_comments else None


def check_droid_finished(comments: list[dict[str, object]]) -> tuple[bool, str]:
    droid_comments = [comment for comment in comments if is_droid_comment(comment)]
    for comment in droid_comments:
        body = str(comment.get("body") or "")
        superseded = "Superseded Droid error" in body or "Superseded Droid review" in body
        if "Droid encountered an error" in body and not superseded:
            return False, f"Droid has an unsuperseded error comment: {comment.get('url') or ''}"
        if "Droid is reviewing code and running a security check" in body and not superseded:
            return False, f"Droid has an unsuperseded in progress comment: {comment.get('url') or ''}"
    comment = latest_droid_comment(comments)
    if not comment:
        return False, "missing Droid review comment"
    body = str(comment.get("body") or "")
    if not is_finished_droid_review(body):
        return False, f"Droid latest comment is not a finished review: {comment.get('url') or ''}"
    return True, ""


def check_no_active_review_threads(threads: list[dict[str, object]]) -> tuple[bool, str]:
    if not threads:
        return True, ""
    first = threads[0]
    location = str(first.get("path") or "review thread")
    if first.get("line"):
        location = f"{location}:{first['line']}"
    url = str(first.get("url") or "")
    suffix = f" ({url})" if url else ""
    return False, f"{len(threads)} active review thread(s), first at {location}{suffix}"


def wait_for_gate(label: str, timeout_seconds: int, interval_seconds: int, predicate) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_reason = ""
    while True:
        ok, reason = predicate()
        if ok:
            print(f"{label}: ok")
            return
        last_reason = reason
        if time.monotonic() >= deadline:
            raise RuntimeError(f"{label} timed out: {last_reason}")
        print(f"{label}: waiting - {last_reason}", flush=True)
        time.sleep(interval_seconds)


def delete_branch_if_safe(pr: dict[str, object], repo: str) -> None:
    head_repo = pr.get("headRepository") if isinstance(pr.get("headRepository"), dict) else {}
    head_owner = pr.get("headRepositoryOwner") if isinstance(pr.get("headRepositoryOwner"), dict) else {}
    if head_repo.get("nameWithOwner") != repo or head_owner.get("login") != repo.split("/", 1)[0]:
        print("branch delete: skipped for cross-repository PR")
        return
    branch = str(pr.get("headRefName") or "")
    if not branch:
        print("branch delete: skipped because headRefName is empty")
        return
    probe = subprocess.run(
        ["git", "ls-remote", "--exit-code", "--heads", "origin", branch],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if probe.returncode == 2:
        print(f"branch delete: skipped because {branch} is already absent on origin")
        return
    if probe.returncode != 0:
        raise RuntimeError(f"branch delete: unable to inspect origin/{branch}:\n{probe.stderr.strip()}")
    deleted = subprocess.run(
        ["git", "push", "origin", "--delete", branch],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if deleted.returncode != 0:
        combined = f"{deleted.stdout}\n{deleted.stderr}".lower()
        if "remote ref does not exist" in combined or "unable to delete" in combined:
            print(f"branch delete: skipped because {branch} is already absent on origin")
            return
        raise RuntimeError(f"branch delete: failed to delete origin/{branch}:\n{deleted.stderr.strip()}")
    print(f"branch delete: deleted {branch}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Wait for Droid/leak checks, merge, then delete the PR branch.")
    parser.add_argument("pr_number", type=int)
    parser.add_argument("--repo", default="writer/cerebro")
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--interval-seconds", type=int, default=20)
    parser.add_argument("--admin", action="store_true", help="Pass --admin to gh pr merge.")
    parser.add_argument("--keep-branch", action="store_true", help="Do not delete the PR branch after merge.")
    parser.add_argument(
        "--required-check",
        action="append",
        default=[],
        help="Required check name. Defaults to Cerebro's core PR checks when omitted.",
    )
    parser.add_argument(
        "--allow-large-pr",
        action="store_true",
        help="Allow landing PRs above the default size guardrail after manual diff inspection.",
    )
    parser.add_argument("--max-changed-lines", type=int, default=DEFAULT_MAX_CHANGED_LINES)
    parser.add_argument("--max-changed-files", type=int, default=DEFAULT_MAX_CHANGED_FILES)
    args = parser.parse_args()

    pr = fetch_pr(args.pr_number, args.repo)
    if pr.get("state") != "OPEN":
        raise RuntimeError(f"PR #{args.pr_number} is {pr.get('state')}, not OPEN.")
    ok, reason = check_pr_size(
        pr,
        max_changed_lines=args.max_changed_lines,
        max_changed_files=args.max_changed_files,
        allow_large_pr=args.allow_large_pr,
    )
    if not ok:
        raise RuntimeError(f"PR size guard failed: {reason}")

    wait_for_gate(
        "core PR checks",
        args.timeout_seconds,
        args.interval_seconds,
        lambda: check_required_statuses(
            fetch_checks(args.pr_number, args.repo),
            tuple(args.required_check) if args.required_check else DEFAULT_REQUIRED_CHECKS,
        ),
    )
    wait_for_gate(
        "Droid review",
        args.timeout_seconds,
        args.interval_seconds,
        lambda: check_droid_finished(fetch_comments(args.pr_number, args.repo)),
    )
    wait_for_gate(
        "review threads",
        args.timeout_seconds,
        args.interval_seconds,
        lambda: check_no_active_review_threads(fetch_active_review_threads(args.pr_number, args.repo)),
    )

    merge_args = ["pr", "merge", str(args.pr_number), "--squash", "--match-head-commit", str(pr.get("headRefOid") or "")]
    if args.admin:
        merge_args.append("--admin")
    run_gh(merge_args, args.repo)
    print(f"merge: merged PR #{args.pr_number}")

    if not args.keep_branch:
        delete_branch_if_safe(pr, args.repo)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
