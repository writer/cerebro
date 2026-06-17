#!/usr/bin/env python3
"""Summarize post-merge main workflow health for Droid fix context."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

COMMENT_MARKER = "<!-- droid-post-merge-health -->"
DROID_BOT_LOGIN = "factory-droid[bot]"
DROID_FINISHED_MARKERS = ("Droid finished", "Review complete for PR")
TERMINAL_DROID_STATUSES = {"ok", "skipped"}
DROID_REVIEW_REQUIRED_EXACT = {"go.mod", "go.sum", "Makefile"}
DROID_REVIEW_REQUIRED_PREFIXES = (
    ".github/workflows/",
    "api/",
    "cmd/",
    "gen/",
    "internal/",
    "scripts/",
    "sources/",
    "tools/",
)
STABLE_RELEASE_TAG = re.compile(r"^v\d+\.\d+\.\d+$")


def request_json(path: str, token: str, repository: str) -> object:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/{path.lstrip('/')}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)


def collect_runs(branch: str, token: str, repository: str, limit: int) -> list[dict[str, object]]:
    raw = request_json(f"/actions/runs?branch={branch}&per_page={limit}", token, repository)
    runs = raw.get("workflow_runs") if isinstance(raw, dict) else []
    results = []
    if not isinstance(runs, list):
        return results
    for item in runs:
        if not isinstance(item, dict):
            continue
        results.append(
            {
                "id": item.get("id"),
                "workflow_name": item.get("name") or "",
                "head_sha": item.get("head_sha") or "",
                "status": item.get("status") or "",
                "conclusion": item.get("conclusion") or "",
                "created_at": item.get("created_at") or "",
                "url": item.get("html_url") or "",
            }
        )
    return results


def collect_pull_requests_for_commit(head_sha: str, token: str, repository: str) -> list[dict[str, object]]:
    if not head_sha:
        return []
    raw = request_json(f"/commits/{head_sha}/pulls?per_page=20", token, repository)
    if not isinstance(raw, list):
        return []
    pull_requests = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        user = item.get("user") if isinstance(item.get("user"), dict) else {}
        head = item.get("head") if isinstance(item.get("head"), dict) else {}
        base = item.get("base") if isinstance(item.get("base"), dict) else {}
        head_repo = head.get("repo") if isinstance(head.get("repo"), dict) else {}
        base_repo = base.get("repo") if isinstance(base.get("repo"), dict) else {}
        pull_requests.append(
            {
                "number": item.get("number"),
                "title": item.get("title") or "",
                "url": item.get("html_url") or "",
                "state": item.get("state") or "",
                "merged_at": item.get("merged_at") or "",
                "author": user.get("login") or "",
                "head_repository": head_repo.get("full_name") or "",
                "base_repository": base_repo.get("full_name") or repository,
                "head_label": head.get("label") or "",
                "base_label": base.get("label") or "",
            }
        )
    return pull_requests


def collect_pull_request_files(pr_number: object, token: str, repository: str) -> list[str]:
    if not pr_number:
        return []
    files: list[str] = []
    page = 1
    while True:
        raw = request_json(f"/pulls/{pr_number}/files?per_page=100&page={page}", token, repository)
        if not isinstance(raw, list) or not raw:
            break
        for item in raw:
            if isinstance(item, dict) and item.get("filename"):
                files.append(str(item.get("filename") or ""))
        page += 1
    return files


def collect_issue_comments(pr_number: object, token: str, repository: str) -> list[dict[str, object]]:
    if not pr_number:
        return []
    comments: list[dict[str, object]] = []
    page = 1
    while True:
        raw = request_json(f"/issues/{pr_number}/comments?per_page=100&page={page}", token, repository)
        if not isinstance(raw, list) or not raw:
            break
        for item in raw:
            if isinstance(item, dict):
                comments.append(item)
        page += 1
    return comments


def is_droid_comment(comment: dict[str, object]) -> bool:
    user = comment.get("user") if isinstance(comment.get("user"), dict) else {}
    login = str(user.get("login") or "").lower()
    user_type = str(user.get("type") or "")
    return login == DROID_BOT_LOGIN and (not user_type or user_type == "Bot")


def is_finished_droid_review(body: object) -> bool:
    text = str(body or "")
    return any(marker in text for marker in DROID_FINISHED_MARKERS)


def is_post_merge_checkout_error(pr: dict[str, object], comment: dict[str, object]) -> bool:
    body = str(comment.get("body") or "")
    if "Droid encountered an error" not in body:
        return False
    if "Failed to checkout PR #" not in body or "branch for review" not in body:
        return False
    merged_at = str(pr.get("merged_at") or "")
    if not merged_at:
        return False
    created_at = str(comment.get("created_at") or "")
    return not created_at or created_at >= merged_at


def requires_droid_review(file: str) -> bool:
    normalized = file.replace("\\", "/")
    return (
        normalized.endswith(".go")
        or normalized in DROID_REVIEW_REQUIRED_EXACT
        or any(normalized.startswith(prefix) for prefix in DROID_REVIEW_REQUIRED_PREFIXES)
    )


def has_no_review_required_changes(pr: dict[str, object]) -> bool:
    files = pr.get("changed_files")
    if not isinstance(files, list) or not files:
        return False
    return not any(requires_droid_review(str(file)) for file in files)


def is_cross_repository_pr(pr: dict[str, object]) -> bool:
    head_repository = str(pr.get("head_repository") or "").lower()
    base_repository = str(pr.get("base_repository") or "").lower()
    if head_repository and base_repository and head_repository != base_repository:
        return True
    if head_repository or not base_repository:
        return False

    head_label = str(pr.get("head_label") or "")
    head_owner = head_label.split(":", 1)[0].lower() if ":" in head_label else ""
    base_owner = base_repository.split("/", 1)[0]
    return bool(head_owner and head_owner != base_owner)


def classify_droid_review(pr: dict[str, object], comments: list[dict[str, object]]) -> dict[str, object]:
    droid_comments = []
    for comment in comments:
        if is_droid_comment(comment):
            droid_comments.append(comment)

    active_errors = []
    active_progress = []
    post_merge_checkout_errors = []
    finished = []
    for comment in droid_comments:
        body = comment.get("body") or ""
        superseded = "Superseded Droid error" in body or "Superseded Droid review" in body
        if "Droid encountered an error" in body and not superseded:
            if is_post_merge_checkout_error(pr, comment):
                post_merge_checkout_errors.append(comment)
            else:
                active_errors.append(comment)
        if "Droid is reviewing code and running a security check" in body and not superseded:
            active_progress.append(comment)
        if is_finished_droid_review(body):
            finished.append(comment)

    author = str(pr.get("author") or "")
    latest = droid_comments[-1] if droid_comments else {}
    latest_report_comment = latest
    if active_errors:
        status = "error"
        reason = "Droid has an unsuperseded error comment."
    elif active_progress:
        status = "in_progress"
        reason = "Droid has an unsuperseded in-progress comment."
    elif post_merge_checkout_errors and finished:
        status = "ok"
        reason = "Droid finished before a post-merge branch checkout error."
        latest_report_comment = finished[-1]
    elif latest and is_finished_droid_review(latest.get("body")):
        status = "ok"
        reason = "Droid has a finished review comment."
    elif author == "dependabot[bot]":
        status = "skipped"
        reason = "Dependabot PRs skip the secret-backed Droid execution job."
    elif is_cross_repository_pr(pr):
        status = "skipped"
        reason = "Cross-repository PRs skip the secret-backed Droid execution job."
    elif has_no_review_required_changes(pr):
        status = "skipped"
        reason = "Changed files do not require the secret-backed Droid execution job."
    else:
        status = "missing"
        reason = (
            "Latest Droid comment is not a finished review."
            if latest
            else "No finished Droid review comment was found."
        )

    return {
        "number": pr.get("number"),
        "title": pr.get("title") or "",
        "url": pr.get("url") or "",
        "author": author,
        "status": status,
        "reason": reason,
        "latest_comment_url": latest_report_comment.get("html_url") or "",
        "droid_comment_count": len(droid_comments),
        "active_error_count": len(active_errors),
        "active_progress_count": len(active_progress),
        "post_merge_checkout_error_count": len(post_merge_checkout_errors),
        "finished_count": len(finished),
        "changed_files": pr.get("changed_files") or [],
    }


def git_output(args: list[str]) -> str:
    result = subprocess.run(["git", *args], check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.strip()


def collect_release_status(head_sha: str) -> dict[str, object]:
    try:
        head = head_sha or git_output(["rev-parse", "HEAD"])
        tags = [
            tag
            for tag in git_output(["tag", "--list", "v[0-9]*.[0-9]*.[0-9]*", "--sort=-v:refname"]).splitlines()
            if STABLE_RELEASE_TAG.match(tag.strip())
        ]
        head_tags = [
            tag
            for tag in git_output(["tag", "--points-at", head, "--list", "v*"]).splitlines()
            if tag.strip()
        ]
        if not tags:
            return {
                "latest_tag": "",
                "latest_tag_target": "",
                "head_tags": head_tags,
                "head_has_release_tag": bool(head_tags),
                "latest_tag_on_head": False,
                "commits_since_latest_tag": None,
                "status": "missing_release_tags",
            }
        latest = tags[0].strip()
        target = git_output(["rev-parse", f"{latest}^{{}}"])
        commits_since: int | None
        try:
            commits_since = int(git_output(["rev-list", "--count", f"{target}..{head}"]))
        except (subprocess.CalledProcessError, ValueError):
            commits_since = None
        latest_on_head = target == head
        return {
            "latest_tag": latest,
            "latest_tag_target": target,
            "head_tags": head_tags,
            "head_has_release_tag": bool(head_tags),
            "latest_tag_on_head": latest_on_head,
            "commits_since_latest_tag": commits_since,
            "status": "current" if latest_on_head else "tag_lag",
        }
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        return {
            "latest_tag": "",
            "latest_tag_target": "",
            "head_tags": [],
            "head_has_release_tag": False,
            "latest_tag_on_head": False,
            "commits_since_latest_tag": None,
            "status": "unavailable",
            "reason": str(exc)[:240],
        }


def summarize(
    branch: str,
    head_sha: str,
    runs: list[dict[str, object]],
    pull_requests: list[dict[str, object]] | None = None,
    droid_reviews: list[dict[str, object]] | None = None,
    current_run_id: str = "",
    release_status: dict[str, object] | None = None,
) -> dict[str, object]:
    relevant = [
        run
        for run in runs
        if (not head_sha or run.get("head_sha") == head_sha)
        and (not current_run_id or str(run.get("id") or "") != current_run_id)
    ]
    if not relevant:
        relevant = [
            run for run in runs[:5] if not current_run_id or str(run.get("id") or "") != current_run_id
        ]
    failures = [
        run
        for run in relevant
        if run.get("status") == "completed" and run.get("conclusion") not in {"success", "skipped", "neutral"}
    ]
    pending = [run for run in relevant if run.get("status") != "completed"]
    reviews = droid_reviews or []
    failed_reviews = [review for review in reviews if review.get("status") not in TERMINAL_DROID_STATUSES]
    return {
        "kind": "droid_post_merge_health",
        "branch": branch,
        "head_sha": head_sha,
        "runs": relevant,
        "failed_runs": failures,
        "pending_runs": pending,
        "pull_requests": pull_requests or [],
        "droid_reviews": reviews,
        "failed_droid_reviews": failed_reviews,
        "release_status": release_status or {},
        "healthy": not failures and not failed_reviews and bool(relevant),
    }


def render_markdown(context: dict[str, object]) -> str:
    failed = context.get("failed_runs") if isinstance(context.get("failed_runs"), list) else []
    pending = context.get("pending_runs") if isinstance(context.get("pending_runs"), list) else []
    droid_reviews = context.get("droid_reviews") if isinstance(context.get("droid_reviews"), list) else []
    failed_droid_reviews = (
        context.get("failed_droid_reviews") if isinstance(context.get("failed_droid_reviews"), list) else []
    )
    release_status = context.get("release_status") if isinstance(context.get("release_status"), dict) else {}
    lines = [
        COMMENT_MARKER,
        "## Droid Post-Merge Health",
        "",
        "Compare the merged commit's main-branch workflows against PR-green expectations.",
        "",
        f"- Branch: `{context.get('branch', '')}`",
        f"- Head: `{context.get('head_sha', '')}`",
        f"- Healthy: `{context.get('healthy', False)}`",
        f"- Failed runs: `{len(failed)}`",
        f"- Pending runs: `{len(pending)}`",
        f"- Droid review issues: `{len(failed_droid_reviews)}`",
        f"- Latest release tag: `{release_status.get('latest_tag', '')}`",
        f"- Latest tag on head: `{release_status.get('latest_tag_on_head', False)}`",
        f"- Commits since latest release tag: `{release_status.get('commits_since_latest_tag', '')}`",
        "",
    ]
    if release_status and not release_status.get("latest_tag_on_head"):
        lines.append("### Release Status")
        lines.append("")
        lines.append(
            "- `{tag}` is not on the selected head yet. This is informational release-train lag unless release workflows are failing.".format(
                tag=release_status.get("latest_tag", "")
            )
        )
        if release_status.get("reason"):
            lines.append(f"- Status detail: {release_status.get('reason')}")
    if failed:
        lines.append("### Failures")
        lines.append("")
        for run in failed:
            if isinstance(run, dict):
                lines.append(f"- `{run.get('workflow_name', '')}` {run.get('conclusion', '')}: {run.get('url', '')}")
    if pending:
        lines.append("### Pending")
        lines.append("")
        for run in pending:
            if isinstance(run, dict):
                lines.append(f"- `{run.get('workflow_name', '')}` {run.get('status', '')}: {run.get('url', '')}")
    if droid_reviews:
        lines.append("### Droid Reviews")
        lines.append("")
        for review in droid_reviews:
            if isinstance(review, dict):
                lines.append(
                    "- PR #{number} `{status}`: {reason} {url}".format(
                        number=review.get("number", ""),
                        status=review.get("status", ""),
                        reason=review.get("reason", ""),
                        url=review.get("latest_comment_url") or review.get("url") or "",
                    )
                )
    if not failed and not pending:
        lines.append("No failed or pending main workflow runs for the selected commit.")
    if not droid_reviews:
        lines.append("No merged pull request association was found for the selected commit.")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--branch", default=os.environ.get("DROID_POST_MERGE_BRANCH", "main"))
    parser.add_argument("--head", default=os.environ.get("DROID_POST_MERGE_HEAD", os.environ.get("GITHUB_SHA", "")))
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--markdown-out", default=os.environ.get("DROID_POST_MERGE_OUT", "tmp/droid-post-merge-health.md"))
    parser.add_argument("--json-out", default=os.environ.get("DROID_POST_MERGE_JSON_OUT", "tmp/droid-post-merge-health.json"))
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when post-merge health is not healthy.")
    args = parser.parse_args()

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if not token or not repository:
        context = {
            "kind": "droid_post_merge_health",
            "branch": args.branch,
            "head_sha": args.head,
            "runs": [],
            "failed_runs": [],
            "pending_runs": [],
            "healthy": False,
            "release_status": collect_release_status(args.head),
            "notes": ["GitHub token or repository missing."],
        }
    else:
        try:
            pull_requests = collect_pull_requests_for_commit(args.head, token, repository)
            for pr in pull_requests:
                pr["changed_files"] = collect_pull_request_files(pr.get("number"), token, repository)
            droid_reviews = [
                classify_droid_review(pr, collect_issue_comments(pr.get("number"), token, repository))
                for pr in pull_requests
            ]
            context = summarize(
                args.branch,
                args.head,
                collect_runs(args.branch, token, repository, args.limit),
                pull_requests=pull_requests,
                droid_reviews=droid_reviews,
                current_run_id=os.environ.get("GITHUB_RUN_ID", ""),
                release_status=collect_release_status(args.head),
            )
        except (urllib.error.URLError, TimeoutError, RuntimeError) as exc:
            context = {
                "kind": "droid_post_merge_health",
                "branch": args.branch,
                "head_sha": args.head,
                "runs": [],
                "failed_runs": [],
                "pending_runs": [],
                "healthy": False,
                "release_status": collect_release_status(args.head),
                "notes": [str(exc)[:240]],
            }
    markdown = render_markdown(context)
    markdown_path = Path(args.markdown_out)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.write_text(markdown, encoding="utf-8")
    json_path = Path(args.json_out)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(context, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(markdown)
    if args.strict and not context.get("healthy"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
