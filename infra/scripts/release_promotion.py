#!/usr/bin/env python3
from __future__ import annotations

import base64
from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any
from urllib.parse import quote


IMAGE_TAG_KEY = "cerebro:imageTag"
IMAGE_DIGEST_KEY = "cerebro:imageDigest"
IMAGE = "ghcr.io/writer/cerebro"
STABLE_TAG_PATTERN = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
IMAGE_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class DeploymentReceipt:
    deployment_id: int
    environment: str
    image_tag: str
    image_digest: str
    ref: str
    created_at: str
    target_url: str


def run(
    command: list[str],
    *,
    input_text: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    print(f"Running: {' '.join(command)}", file=sys.stderr, flush=True)
    completed = subprocess.run(
        command,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.stdout:
        print(completed.stdout, end="", flush=True)
    if completed.stderr:
        print(completed.stderr, end="", file=sys.stderr, flush=True)
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"{' '.join(command)} failed with exit code {completed.returncode}"
        )
    return completed


def gh_json(
    arguments: list[str],
    *,
    input_payload: dict[str, Any] | None = None,
) -> Any:
    command = ["gh", *arguments]
    input_text = None
    if input_payload is not None:
        command.extend(["--input", "-"])
        input_text = json.dumps(input_payload)
    completed = run(command, input_text=input_text)
    if not completed.stdout.strip():
        return None
    return json.loads(completed.stdout)


def parse_stable_tag(tag: str) -> tuple[int, int, int]:
    match = STABLE_TAG_PATTERN.fullmatch(tag.strip())
    if not match:
        raise ValueError(f"{tag!r} is not a stable vMAJOR.MINOR.PATCH tag")
    return tuple(int(part) for part in match.groups())


def read_stack_tag_text(text: str) -> str:
    pattern = re.compile(rf"^\s*{re.escape(IMAGE_TAG_KEY)}\s*:\s*['\"]?([^'\"\s#]+)")
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            return match.group(1).strip()
    raise ValueError(f"{IMAGE_TAG_KEY} is missing")


def read_stack_tag(path: Path) -> str:
    return read_stack_tag_text(path.read_text(encoding="utf-8"))


def read_stack_digest_text(text: str) -> str:
    pattern = re.compile(rf"^\s*{re.escape(IMAGE_DIGEST_KEY)}\s*:\s*['\"]?([^'\"\s#]+)")
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            digest = match.group(1).strip()
            if IMAGE_DIGEST_PATTERN.fullmatch(digest) is None:
                raise ValueError(f"{IMAGE_DIGEST_KEY} must be a sha256 digest")
            return digest
    raise ValueError(f"{IMAGE_DIGEST_KEY} is missing")


def read_stack_digest(path: Path) -> str:
    return read_stack_digest_text(path.read_text(encoding="utf-8"))


def resolve_image_digest(tag: str, *, image: str = IMAGE) -> str:
    parse_stable_tag(tag)
    completed = run(
        [
            "docker",
            "buildx",
            "imagetools",
            "inspect",
            f"{image}:{tag}",
            "--format",
            "{{.Manifest.Digest}}",
        ]
    )
    digest = completed.stdout.strip()
    if not digest.startswith("sha256:"):
        raise RuntimeError(f"Could not resolve an image digest for {image}:{tag}")
    return digest


def _deployment_payload(deployment: dict[str, Any]) -> dict[str, Any]:
    payload = deployment.get("payload") or {}
    if isinstance(payload, str):
        try:
            loaded = json.loads(payload)
        except json.JSONDecodeError:
            return {}
        return loaded if isinstance(loaded, dict) else {}
    return payload if isinstance(payload, dict) else {}


def find_successful_deployment(
    repository: str,
    *,
    environment: str,
    image_tag: str,
    image_digest: str,
) -> DeploymentReceipt | None:
    deployments = gh_json(
        [
            "api",
            f"repos/{repository}/deployments?environment={quote(environment)}&per_page=100",
        ]
    )
    if not isinstance(deployments, list):
        return None

    for deployment in deployments:
        if not isinstance(deployment, dict):
            continue
        payload = _deployment_payload(deployment)
        if (
            payload.get("imageTag") != image_tag
            or payload.get("imageDigest") != image_digest
        ):
            continue
        deployment_id = deployment.get("id")
        if not isinstance(deployment_id, int):
            continue
        statuses = gh_json(
            [
                "api",
                f"repos/{repository}/deployments/{deployment_id}/statuses?per_page=1",
            ]
        )
        if (
            not isinstance(statuses, list)
            or not statuses
            or statuses[0].get("state") != "success"
        ):
            continue
        status = statuses[0]
        return DeploymentReceipt(
            deployment_id=deployment_id,
            environment=environment,
            image_tag=image_tag,
            image_digest=image_digest,
            ref=str(deployment.get("ref") or ""),
            created_at=str(deployment.get("created_at") or ""),
            target_url=str(
                status.get("target_url") or payload.get("workflowRun") or ""
            ),
        )
    return None


def repository_file(repository: str, path: str, ref: str) -> str:
    response = gh_json(
        ["api", f"repos/{repository}/contents/{quote(path)}?ref={quote(ref, safe='')}"]
    )
    if not isinstance(response, dict):
        raise RuntimeError(f"Could not read {path} at {ref}")
    encoded = str(response.get("content") or "").replace("\n", "")
    if not encoded:
        raise RuntimeError(f"GitHub returned no content for {path} at {ref}")
    return base64.b64decode(encoded).decode("utf-8")


def post_commit_status(
    repository: str,
    *,
    sha: str,
    state: str,
    context: str,
    description: str,
    target_url: str = "",
) -> None:
    if state not in {"error", "failure", "pending", "success"}:
        raise ValueError(f"Unsupported commit status state {state}")
    body: dict[str, Any] = {
        "state": state,
        "context": context,
        "description": description[:140],
    }
    if target_url:
        body["target_url"] = target_url
    gh_json(
        ["api", "--method", "POST", f"repos/{repository}/statuses/{sha}"],
        input_payload=body,
    )
