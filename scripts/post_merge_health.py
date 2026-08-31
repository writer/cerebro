#!/usr/bin/env python3
"""Summarize post-merge main workflow and release health."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Collection
from pathlib import Path

COMMENT_MARKER = "<!-- post-merge-health -->"
POST_MERGE_HEALTH_WORKFLOW = "Post-Merge Health"
STABLE_RELEASE_TAG = re.compile(r"^v\d+\.\d+\.\d+$")
SUCCESSFUL_CONCLUSIONS = {"success", "skipped", "neutral"}
REQUIRED_WORKFLOW_NAMES = frozenset(
    {
        "Candidate Build",
        "CI",
        "CodeQL",
        "Leak Check",
        "Rust-only Candidate",
        "Secret Scan",
        "Semgrep",
    }
)


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


def collect_runs(
    branch: str,
    head_sha: str,
    token: str,
    repository: str,
    limit: int,
) -> list[dict[str, object]]:
    if not head_sha:
        return []
    query = urllib.parse.urlencode(
        {
            "branch": branch,
            "head_sha": head_sha,
            "event": "push",
            "per_page": limit,
        }
    )
    raw = request_json(f"/actions/runs?{query}", token, repository)
    runs = raw.get("workflow_runs") if isinstance(raw, dict) else []
    if not isinstance(runs, list):
        return []
    results = []
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


def git_output(args: list[str]) -> str:
    result = subprocess.run(["git", *args], check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.strip()


def collect_release_status(head_sha: str) -> dict[str, object]:
    try:
        head = head_sha or git_output(["rev-parse", "HEAD"])
        tags = [
            tag.strip()
            for tag in git_output(["tag", "--list", "v[0-9]*.[0-9]*.[0-9]*", "--sort=-v:refname"]).splitlines()
            if STABLE_RELEASE_TAG.match(tag.strip())
        ]
        head_tags = [
            tag.strip()
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
        latest = tags[0]
        target = git_output(["rev-parse", f"{latest}^{{}}"])
        try:
            commits_since: int | None = int(git_output(["rev-list", "--count", f"{target}..{head}"]))
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
    current_run_id: str = "",
    release_status: dict[str, object] | None = None,
    required_workflows: Collection[str] = REQUIRED_WORKFLOW_NAMES,
) -> dict[str, object]:
    relevant = [
        run
        for run in runs
        if head_sha
        and run.get("head_sha") == head_sha
        and (not current_run_id or str(run.get("id") or "") != current_run_id)
        and run.get("workflow_name") != POST_MERGE_HEALTH_WORKFLOW
    ]
    required = {name.strip() for name in required_workflows if name.strip()}
    observed = {str(run.get("workflow_name") or "") for run in relevant}
    missing = sorted(required - observed)
    failures = [
        run
        for run in relevant
        if run.get("status") == "completed" and run.get("conclusion") not in SUCCESSFUL_CONCLUSIONS
    ]
    pending = [run for run in relevant if run.get("status") != "completed"]
    return {
        "kind": "post_merge_health",
        "branch": branch,
        "head_sha": head_sha,
        "runs": relevant,
        "failed_runs": failures,
        "pending_runs": pending,
        "required_workflows": sorted(required),
        "missing_workflows": missing,
        "release_status": release_status or {},
        "healthy": bool(relevant) and not failures and not pending and not missing,
    }


def wait_for_terminal_summary(
    branch: str,
    head_sha: str,
    collect: Callable[[], list[dict[str, object]]],
    *,
    current_run_id: str = "",
    release_status: dict[str, object] | None = None,
    required_workflows: Collection[str] = REQUIRED_WORKFLOW_NAMES,
    wait_seconds: float = 0,
    poll_seconds: float = 30,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, object]:
    deadline = monotonic() + max(wait_seconds, 0)
    interval = max(poll_seconds, 1)
    while True:
        context = summarize(
            branch,
            head_sha,
            collect(),
            current_run_id=current_run_id,
            release_status=release_status,
            required_workflows=required_workflows,
        )
        if context["healthy"] or context["failed_runs"] or not head_sha:
            return context
        remaining = deadline - monotonic()
        if remaining <= 0:
            return context
        sleep(min(interval, remaining))


def render_markdown(context: dict[str, object]) -> str:
    failed = context.get("failed_runs") if isinstance(context.get("failed_runs"), list) else []
    pending = context.get("pending_runs") if isinstance(context.get("pending_runs"), list) else []
    missing = context.get("missing_workflows") if isinstance(context.get("missing_workflows"), list) else []
    release_status = context.get("release_status") if isinstance(context.get("release_status"), dict) else {}
    lines = [
        COMMENT_MARKER,
        "## Post-Merge Health",
        "",
        "Healthy requires exact-head sibling workflow evidence with every observed run terminal and non-failing.",
        "",
        f"- Branch: `{context.get('branch', '')}`",
        f"- Head: `{context.get('head_sha', '')}`",
        f"- Healthy: `{context.get('healthy', False)}`",
        f"- Failed runs: `{len(failed)}`",
        f"- Pending runs: `{len(pending)}`",
        f"- Missing required workflows: `{len(missing)}`",
        f"- Latest release tag: `{release_status.get('latest_tag', '')}`",
        f"- Latest tag on head: `{release_status.get('latest_tag_on_head', False)}`",
        f"- Commits since latest release tag: `{release_status.get('commits_since_latest_tag', '')}`",
        "",
    ]
    if release_status and release_status.get("latest_tag") and not release_status.get("latest_tag_on_head"):
        lines.extend(
            [
                "### Release Status",
                "",
                "- `{tag}` is not on the selected head yet. This is informational release-train lag unless release workflows are failing.".format(
                    tag=release_status.get("latest_tag", "")
                ),
            ]
        )
        if release_status.get("reason"):
            lines.append(f"- Status detail: {release_status.get('reason')}")
    if failed:
        lines.extend(["### Failures", ""])
        for run in failed:
            if isinstance(run, dict):
                lines.append(f"- `{run.get('workflow_name', '')}` {run.get('conclusion', '')}: {run.get('url', '')}")
    if pending:
        lines.extend(["### Pending", ""])
        for run in pending:
            if isinstance(run, dict):
                lines.append(f"- `{run.get('workflow_name', '')}` {run.get('status', '')}: {run.get('url', '')}")
    if missing:
        lines.extend(["### Missing Required Workflows", ""])
        for workflow_name in missing:
            lines.append(f"- `{workflow_name}`")
    runs = context.get("runs") if isinstance(context.get("runs"), list) else []
    if not runs:
        lines.append("No exact-head sibling workflow evidence was found; health remains false.")
    elif not failed and not pending and not missing:
        lines.append("All observed exact-head sibling workflow runs are terminal and non-failing.")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--branch", default=os.environ.get("POST_MERGE_BRANCH", "main"))
    parser.add_argument("--head", default=os.environ.get("POST_MERGE_HEAD", os.environ.get("GITHUB_SHA", "")))
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument(
        "--wait-seconds", type=float, default=os.environ.get("POST_MERGE_WAIT_SECONDS", "0")
    )
    parser.add_argument(
        "--poll-seconds", type=float, default=os.environ.get("POST_MERGE_POLL_SECONDS", "30")
    )
    parser.add_argument("--markdown-out", default=os.environ.get("POST_MERGE_OUT", "tmp/post-merge-health.md"))
    parser.add_argument("--json-out", default=os.environ.get("POST_MERGE_JSON_OUT", "tmp/post-merge-health.json"))
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when post-merge health is not healthy.")
    args = parser.parse_args()

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    release_status = collect_release_status(args.head)
    if not token or not repository:
        context = {
            "kind": "post_merge_health",
            "branch": args.branch,
            "head_sha": args.head,
            "runs": [],
            "failed_runs": [],
            "pending_runs": [],
            "healthy": False,
            "release_status": release_status,
            "notes": ["GitHub token or repository missing."],
        }
    else:
        try:
            context = wait_for_terminal_summary(
                args.branch,
                args.head,
                lambda: collect_runs(args.branch, args.head, token, repository, args.limit),
                current_run_id=os.environ.get("GITHUB_RUN_ID", ""),
                release_status=release_status,
                wait_seconds=args.wait_seconds,
                poll_seconds=args.poll_seconds,
            )
        except (urllib.error.URLError, TimeoutError, RuntimeError) as exc:
            context = {
                "kind": "post_merge_health",
                "branch": args.branch,
                "head_sha": args.head,
                "runs": [],
                "failed_runs": [],
                "pending_runs": [],
                "healthy": False,
                "release_status": release_status,
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
    return 1 if args.strict and not context.get("healthy") else 0


if __name__ == "__main__":
    raise SystemExit(main())
