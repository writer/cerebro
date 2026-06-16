#!/usr/bin/env python3
"""Conservative PR landing helper for Cerebro.

The helper exists to keep automated review branches alive until Droid has
finished. It intentionally merges first and deletes the branch only after the
review gates and merge have succeeded.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time


PASS_BUCKETS = {"pass"}
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
            "number,state,headRefName,headRefOid,headRepository,headRepositoryOwner,url",
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


def check_named_status(checks: list[dict[str, object]], name: str) -> tuple[bool, str]:
    matches = [check for check in checks if check.get("name") == name]
    if not matches:
        return False, f"missing check {name!r}"
    latest = matches[-1]
    if latest.get("bucket") in PASS_BUCKETS:
        return True, ""
    return False, f"{name!r} is {latest.get('bucket') or latest.get('state')}: {latest.get('link') or ''}"


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
    args = parser.parse_args()

    pr = fetch_pr(args.pr_number, args.repo)
    if pr.get("state") != "OPEN":
        raise RuntimeError(f"PR #{args.pr_number} is {pr.get('state')}, not OPEN.")

    wait_for_gate(
        "tenant-data leak check",
        args.timeout_seconds,
        args.interval_seconds,
        lambda: check_named_status(fetch_checks(args.pr_number, args.repo), "tenant-data leak check"),
    )
    wait_for_gate(
        "Droid review",
        args.timeout_seconds,
        args.interval_seconds,
        lambda: check_droid_finished(fetch_comments(args.pr_number, args.repo)),
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
