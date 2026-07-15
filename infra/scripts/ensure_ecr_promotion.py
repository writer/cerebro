#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


IMAGE_TAG_KEY = "cerebro:imageTag"
WEB_IMAGE_TAG_KEY = "cerebro:webImageTag"
DEFAULT_REGION = "us-east-1"
DEFAULT_REPOSITORY = "cerebro"
DEFAULT_SOURCE_IMAGE = "ghcr.io/writer/cerebro"


@dataclass(frozen=True)
class RequiredImage:
    label: str
    tag: str


@dataclass(frozen=True)
class EcrImage:
    label: str
    tag: str
    digest: str
    image_uri: str
    pushed_at: str | None = None


class ImageMissingError(RuntimeError):
    def __init__(self, image: RequiredImage, stderr: str) -> None:
        super().__init__(f"{image.label} image tag {image.tag} is missing from ECR")
        self.image = image
        self.stderr = stderr


def _stack_name(path: Path) -> str:
    name = path.name
    if name.startswith("Pulumi.") and name.endswith(".yaml"):
        return name.removeprefix("Pulumi.").removesuffix(".yaml")
    return path.stem


def _read_stack_value(stack_file: Path, key: str) -> str:
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*:\s*['\"]?([^'\"\s#]+)")
    for line in stack_file.read_text(encoding="utf-8").splitlines():
        match = pattern.match(line)
        if match:
            return match.group(1).strip()
    return ""


def _required_images(stack_file: Path) -> list[RequiredImage]:
    image_tag = _read_stack_value(stack_file, IMAGE_TAG_KEY)
    if not image_tag:
        raise RuntimeError(f"{IMAGE_TAG_KEY} not found in {stack_file}")
    images = [RequiredImage("api", image_tag)]
    web_image_tag = _read_stack_value(stack_file, WEB_IMAGE_TAG_KEY)
    if web_image_tag:
        images.append(RequiredImage("web", web_image_tag))
    return images


def _run(
    command: list[str], *, env: dict[str, str] | None = None, check: bool = True
) -> subprocess.CompletedProcess[str]:
    print(f"Running: {' '.join(command)}", file=sys.stderr, flush=True)
    completed = subprocess.run(
        command, check=False, text=True, capture_output=True, env=env
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


def _is_missing_image_error(stderr: str) -> bool:
    text = stderr.lower()
    return (
        "imagenotfoundexception" in text
        or "requested image not found" in text
        or "does not exist in the repository" in text
    )


def _ecr_image_uri(
    registry_id: str, region: str, repository_name: str, tag: str
) -> str:
    return f"{registry_id}.dkr.ecr.{region}.amazonaws.com/{repository_name}:{tag}"


def _normalize_pushed_at(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, UTC).isoformat().replace("+00:00", "Z")
    return str(value)


def _describe_ecr_image(
    image: RequiredImage, *, repository_name: str, region: str
) -> EcrImage:
    completed = _run(
        [
            "aws",
            "ecr",
            "describe-images",
            "--repository-name",
            repository_name,
            "--image-ids",
            f"imageTag={image.tag}",
            "--region",
            region,
            "--output",
            "json",
        ],
        check=False,
    )
    if completed.returncode != 0:
        if _is_missing_image_error(completed.stderr):
            raise ImageMissingError(image, completed.stderr)
        raise RuntimeError(
            f"failed to describe ECR image {image.tag}: {completed.stderr.strip()}"
        )
    payload = json.loads(completed.stdout or "{}")
    details = payload.get("imageDetails") or []
    if not details:
        raise ImageMissingError(image, "describe-images returned no imageDetails")
    detail = details[0]
    digest = str(detail.get("imageDigest") or "").strip()
    registry_id = str(detail.get("registryId") or "").strip()
    if not digest or not registry_id:
        raise RuntimeError(
            f"describe-images response for {image.tag} did not include registryId and imageDigest"
        )
    return EcrImage(
        label=image.label,
        tag=image.tag,
        digest=digest,
        image_uri=_ecr_image_uri(registry_id, region, repository_name, image.tag),
        pushed_at=_normalize_pushed_at(detail.get("imagePushedAt")),
    )


def _find_missing_images(
    images: list[RequiredImage], *, repository_name: str, region: str
) -> tuple[list[EcrImage], list[RequiredImage]]:
    found: list[EcrImage] = []
    missing: list[RequiredImage] = []
    for image in images:
        try:
            found.append(
                _describe_ecr_image(
                    image, repository_name=repository_name, region=region
                )
            )
        except ImageMissingError:
            missing.append(image)
    return found, missing


def _gh_env(token: str | None) -> dict[str, str]:
    env = os.environ.copy()
    if token:
        env["GH_TOKEN"] = token
    return env


def _parse_github_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _dispatch_workflow(args: argparse.Namespace) -> datetime:
    if not args.github_repository:
        raise RuntimeError(
            "cannot dispatch promotion recovery without GITHUB_REPOSITORY or --github-repository"
        )
    started_at = datetime.now(UTC)
    _run(
        [
            "gh",
            "workflow",
            "run",
            args.workflow,
            "--repo",
            args.github_repository,
            "--ref",
            args.workflow_ref,
        ],
        env=_gh_env(args.github_token),
    )
    print(
        f"::notice::Dispatched {args.workflow} on {args.workflow_ref} to recover missing ECR image promotion",
        flush=True,
    )
    return started_at


def _workflow_dispatch_runs(args: argparse.Namespace) -> list[dict[str, object]]:
    completed = _run(
        [
            "gh",
            "run",
            "list",
            "--repo",
            args.github_repository,
            "--workflow",
            args.workflow,
            "--event",
            "workflow_dispatch",
            "--branch",
            args.workflow_ref,
            "--limit",
            "20",
            "--json",
            "databaseId,status,conclusion,createdAt,url",
        ],
        env=_gh_env(args.github_token),
    )
    loaded = json.loads(completed.stdout or "[]")
    if not isinstance(loaded, list):
        return []
    return [run for run in loaded if isinstance(run, dict)]


def _wait_for_dispatched_workflow(
    args: argparse.Namespace, started_at: datetime
) -> str:
    deadline = time.monotonic() + args.wait_seconds
    matched_run: dict[str, object] | None = None
    while time.monotonic() < deadline:
        candidates: list[dict[str, object]] = []
        for run in _workflow_dispatch_runs(args):
            created_at = str(run.get("createdAt") or "")
            if not created_at:
                continue
            try:
                created = _parse_github_datetime(created_at)
            except ValueError:
                continue
            if created >= started_at - timedelta(seconds=60):
                candidates.append(run)
        if candidates:
            candidates.sort(
                key=lambda run: str(run.get("createdAt") or ""), reverse=True
            )
            matched_run = candidates[0]
            break
        time.sleep(args.poll_seconds)
    if matched_run is None:
        raise RuntimeError(
            f"timed out waiting for {args.workflow} workflow_dispatch run to appear"
        )

    run_id = str(matched_run.get("databaseId") or "").strip()
    run_url = str(matched_run.get("url") or "").strip()
    if not run_id:
        raise RuntimeError("matched workflow_dispatch run did not include databaseId")

    while time.monotonic() < deadline:
        completed = _run(
            [
                "gh",
                "run",
                "view",
                run_id,
                "--repo",
                args.github_repository,
                "--json",
                "status,conclusion,url",
            ],
            env=_gh_env(args.github_token),
        )
        payload = json.loads(completed.stdout or "{}")
        status = str(payload.get("status") or "")
        conclusion = str(payload.get("conclusion") or "")
        run_url = str(payload.get("url") or run_url)
        if status == "completed":
            if conclusion == "success":
                print(
                    f"::notice::Promotion recovery workflow completed successfully: {run_url}"
                )
                return run_url
            raise RuntimeError(
                f"promotion recovery workflow completed with conclusion {conclusion}: {run_url}"
            )
        time.sleep(args.poll_seconds)
    raise RuntimeError(
        f"timed out waiting for promotion recovery workflow to complete: {run_url}"
    )


def _write_receipt(
    *,
    path: Path,
    stack_file: Path,
    repository_name: str,
    region: str,
    source: str,
    images: list[EcrImage],
    recovery_run_url: str | None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    payload = {
        "schemaVersion": 1,
        "stack": _stack_name(stack_file),
        "stackFile": str(stack_file),
        "repositoryName": repository_name,
        "region": region,
        "checkedAt": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "source": source,
        "workflowRun": {
            "repository": repository,
            "runId": run_id,
            "runAttempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
            "url": f"{server_url}/{repository}/actions/runs/{run_id}"
            if repository and run_id
            else "",
        },
        "recoveryRunUrl": recovery_run_url or "",
        "images": [
            {
                "label": image.label,
                "tag": image.tag,
                "digest": image.digest,
                "imageUri": image.image_uri,
                "pushedAt": image.pushed_at or "",
            }
            for image in images
        ],
    }
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"::notice::Wrote ECR promotion receipt to {path}")


def _write_github_output(
    path: Path | None, *, receipt: Path | None, recovered: bool, images: list[EcrImage]
) -> None:
    output_path = path or (
        Path(os.environ["GITHUB_OUTPUT"]) if os.environ.get("GITHUB_OUTPUT") else None
    )
    if output_path is None:
        return
    with output_path.open("a", encoding="utf-8") as handle:
        handle.write(f"promotion_recovered={str(recovered).lower()}\n")
        if receipt is not None:
            handle.write(f"promotion_receipt={receipt}\n")
        handle.write(f"promotion_images={','.join(image.tag for image in images)}\n")
        for image in images:
            handle.write(f"promotion_{image.label}_digest={image.digest}\n")


def _missing_image_message(
    missing: list[RequiredImage], args: argparse.Namespace
) -> str:
    missing_tags = ", ".join(f"{image.label}:{image.tag}" for image in missing)
    command = f"gh workflow run {args.workflow} --repo {args.github_repository or '<repo>'} --ref {args.workflow_ref}"
    return (
        f"Missing required ECR image promotion(s): {missing_tags}. "
        f"Run `{command}` or re-run this deploy with --dispatch-if-missing enabled."
    )


def _source_release_digests(source_image: str, expected_digest: str) -> set[str]:
    completed = _run(
        [
            "docker",
            "buildx",
            "imagetools",
            "inspect",
            f"{source_image}@{expected_digest}",
            "--raw",
        ]
    )
    manifest = json.loads(completed.stdout or "{}")
    if not isinstance(manifest, dict):
        raise RuntimeError(
            f"Could not read the locked release manifest for {source_image}"
        )
    allowed = {expected_digest}
    for item in manifest.get("manifests") or []:
        if not isinstance(item, dict):
            continue
        platform = item.get("platform") or {}
        annotations = item.get("annotations") or {}
        if not isinstance(platform, dict) or not isinstance(annotations, dict):
            continue
        if annotations.get("vnd.docker.reference.type") == "attestation-manifest":
            continue
        operating_system = str(platform.get("os") or "")
        architecture = str(platform.get("architecture") or "")
        if not operating_system or not architecture:
            continue
        if operating_system == "unknown" or architecture == "unknown":
            continue
        digest = str(item.get("digest") or "")
        if digest:
            allowed.add(digest)
    return allowed


def _verify_expected_api_digest(
    images: list[EcrImage], expected_digest: str, source_image: str
) -> bool:
    if not expected_digest:
        return True
    api_image = next((image for image in images if image.label == "api"), None)
    if api_image is None:
        print("::error::ECR promotion did not resolve the api image.", file=sys.stderr)
        return False
    allowed_digests = _source_release_digests(source_image, expected_digest)
    if api_image.digest not in allowed_digests:
        print(
            f"::error::ECR digest {api_image.digest} for {api_image.tag} is not the locked release digest "
            f"{expected_digest} or one of its runnable platform manifests.",
            file=sys.stderr,
        )
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify ECR image promotion and optionally dispatch CI recovery before deploy."
    )
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument(
        "--repository-name",
        default=os.environ.get("ECR_REPOSITORY", DEFAULT_REPOSITORY),
    )
    parser.add_argument(
        "--region", default=os.environ.get("AWS_REGION", DEFAULT_REGION)
    )
    parser.add_argument(
        "--receipt-output",
        type=Path,
        help="Write a JSON promotion receipt for the verified ECR image tags.",
    )
    parser.add_argument(
        "--github-output", type=Path, help="Write GitHub Actions step outputs."
    )
    parser.add_argument(
        "--expected-api-digest",
        default="",
        help="Require the promoted API image to match this digest.",
    )
    parser.add_argument(
        "--source-image",
        default=DEFAULT_SOURCE_IMAGE,
        help="Source image whose locked release manifest is promoted.",
    )
    parser.add_argument(
        "--dispatch-if-missing",
        action="store_true",
        help="Dispatch CI and wait when required ECR image tags are missing.",
    )
    parser.add_argument(
        "--workflow",
        default="ci.yml",
        help="Promotion workflow file to dispatch for missing-image recovery.",
    )
    parser.add_argument(
        "--workflow-ref", default=os.environ.get("PROMOTION_WORKFLOW_REF", "main")
    )
    parser.add_argument(
        "--github-repository", default=os.environ.get("GITHUB_REPOSITORY", "")
    )
    parser.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN", ""))
    parser.add_argument("--wait-seconds", type=int, default=1200)
    parser.add_argument("--poll-seconds", type=int, default=10)
    args = parser.parse_args(argv)

    if args.wait_seconds < 1 or args.poll_seconds < 1:
        raise SystemExit("--wait-seconds and --poll-seconds must be >= 1")

    required_images = _required_images(args.stack_file)
    found, missing = _find_missing_images(
        required_images, repository_name=args.repository_name, region=args.region
    )
    recovered = False
    recovery_run_url: str | None = None
    if missing:
        if not args.dispatch_if_missing:
            print(f"::error::{_missing_image_message(missing, args)}", file=sys.stderr)
            return 1
        started_at = _dispatch_workflow(args)
        recovery_run_url = _wait_for_dispatched_workflow(args, started_at)
        deadline = time.monotonic() + args.wait_seconds
        while time.monotonic() < deadline:
            found, missing = _find_missing_images(
                required_images,
                repository_name=args.repository_name,
                region=args.region,
            )
            if not missing:
                recovered = True
                break
            time.sleep(args.poll_seconds)
        if missing:
            print(f"::error::{_missing_image_message(missing, args)}", file=sys.stderr)
            return 1

    if not _verify_expected_api_digest(
        found, args.expected_api_digest, args.source_image
    ):
        return 1

    if args.receipt_output is not None:
        _write_receipt(
            path=args.receipt_output,
            stack_file=args.stack_file,
            repository_name=args.repository_name,
            region=args.region,
            source="recovered_by_ci_dispatch" if recovered else "existing_ecr",
            images=found,
            recovery_run_url=recovery_run_url,
        )
    _write_github_output(
        args.github_output,
        receipt=args.receipt_output,
        recovered=recovered,
        images=found,
    )
    print(
        f"Verified ECR promotion for {_stack_name(args.stack_file)}: "
        + ", ".join(
            f"{image.label} {image.image_uri}@{image.digest}" for image in found
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
