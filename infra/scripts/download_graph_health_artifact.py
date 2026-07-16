#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import UTC, datetime
from io import BytesIO
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request
from zipfile import ZipFile


def _request_json(url: str, token: str) -> dict:
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def _request_bytes(url: str, token: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _matching_workflow_run(
    artifact: dict,
    token: str,
    repository: str,
    *,
    workflow_name: str,
    head_branch: str,
    require_success: bool,
    cache: dict[int, dict],
) -> bool:
    if not workflow_name and not head_branch and not require_success:
        return True
    workflow_run = artifact.get("workflow_run") or {}
    run_id = workflow_run.get("id")
    if not isinstance(run_id, int):
        return False
    if run_id not in cache:
        cache[run_id] = _request_json(
            f"https://api.github.com/repos/{repository}/actions/runs/{run_id}",
            token,
        )
    run = cache[run_id]
    if workflow_name and str(run.get("name") or "") != workflow_name:
        return False
    if head_branch and str(run.get("head_branch") or "") != head_branch:
        return False
    if require_success and (
        str(run.get("status") or "") != "completed"
        or str(run.get("conclusion") or "") != "success"
    ):
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Download a recent graph-health artifact when one is available."
    )
    parser.add_argument("--artifact-name", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-age-seconds", type=int, default=3600)
    parser.add_argument("--workflow-name", default="")
    parser.add_argument("--head-branch", default="")
    parser.add_argument("--require-success", action="store_true")
    args = parser.parse_args(argv)

    token = os.environ.get("GITHUB_TOKEN")
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not token or not repository:
        print(
            "GITHUB_TOKEN/GITHUB_REPOSITORY missing; graph health cache unavailable",
            file=sys.stderr,
        )
        return 0

    encoded_name = urllib.parse.quote(args.artifact_name, safe="")
    try:
        artifacts = _request_json(
            f"https://api.github.com/repos/{repository}/actions/artifacts?name={encoded_name}&per_page=20",
            token,
        ).get("artifacts", [])
    except urllib.error.URLError as exc:
        print(f"Graph health cache artifact list unavailable: {exc}", file=sys.stderr)
        return 0
    now = datetime.now(UTC)
    workflow_runs: dict[int, dict] = {}
    for artifact in artifacts:
        if artifact.get("expired"):
            continue
        created_at = _parse_time(str(artifact.get("created_at") or ""))
        if (now - created_at).total_seconds() > args.max_age_seconds:
            continue
        try:
            matches = _matching_workflow_run(
                artifact,
                token,
                repository,
                workflow_name=args.workflow_name,
                head_branch=args.head_branch,
                require_success=args.require_success,
                cache=workflow_runs,
            )
        except urllib.error.URLError as exc:
            print(
                f"Graph health workflow provenance unavailable: {exc}", file=sys.stderr
            )
            continue
        if not matches:
            continue
        try:
            archive = _request_bytes(str(artifact["archive_download_url"]), token)
        except urllib.error.URLError as exc:
            print(
                f"Graph health cache artifact download unavailable: {exc}",
                file=sys.stderr,
            )
            continue
        with ZipFile(BytesIO(archive)) as zipped:
            member = next(
                (name for name in zipped.namelist() if name.endswith(".tsv")), None
            )
            if member is None:
                continue
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(zipped.read(member))
            print(
                f"Downloaded graph health cache artifact {args.artifact_name} from {created_at.isoformat()}"
            )
            return 0
    print(
        f"No recent graph health cache artifact found for {args.artifact_name}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
