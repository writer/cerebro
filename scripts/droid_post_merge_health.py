#!/usr/bin/env python3
"""Summarize post-merge main workflow health for Droid fix context."""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

COMMENT_MARKER = "<!-- droid-post-merge-health -->"


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


def summarize(branch: str, head_sha: str, runs: list[dict[str, object]]) -> dict[str, object]:
    relevant = [run for run in runs if not head_sha or run.get("head_sha") == head_sha]
    if not relevant:
        relevant = runs[:5]
    failures = [
        run
        for run in relevant
        if run.get("status") == "completed" and run.get("conclusion") not in {"success", "skipped", "neutral"}
    ]
    pending = [run for run in relevant if run.get("status") != "completed"]
    return {
        "kind": "droid_post_merge_health",
        "branch": branch,
        "head_sha": head_sha,
        "runs": relevant,
        "failed_runs": failures,
        "pending_runs": pending,
        "healthy": not failures and not pending and bool(relevant),
    }


def render_markdown(context: dict[str, object]) -> str:
    failed = context.get("failed_runs") if isinstance(context.get("failed_runs"), list) else []
    pending = context.get("pending_runs") if isinstance(context.get("pending_runs"), list) else []
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
        "",
    ]
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
    if not failed and not pending:
        lines.append("No failed or pending main workflow runs for the selected commit.")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--branch", default=os.environ.get("DROID_POST_MERGE_BRANCH", "main"))
    parser.add_argument("--head", default=os.environ.get("DROID_POST_MERGE_HEAD", os.environ.get("GITHUB_SHA", "")))
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--markdown-out", default=os.environ.get("DROID_POST_MERGE_OUT", "tmp/droid-post-merge-health.md"))
    parser.add_argument("--json-out", default=os.environ.get("DROID_POST_MERGE_JSON_OUT", "tmp/droid-post-merge-health.json"))
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
            "notes": ["GitHub token or repository missing."],
        }
    else:
        try:
            context = summarize(args.branch, args.head, collect_runs(args.branch, token, repository, args.limit))
        except (urllib.error.URLError, TimeoutError, RuntimeError) as exc:
            context = {
                "kind": "droid_post_merge_health",
                "branch": args.branch,
                "head_sha": args.head,
                "runs": [],
                "failed_runs": [],
                "pending_runs": [],
                "healthy": False,
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
