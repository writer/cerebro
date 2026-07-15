#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any

try:
    from scripts import verify_source_runtime_ecs as runtime_verifier
except ImportError:  # pragma: no cover - used when executed as scripts/prepare_candidate_runtime_smoke.py
    import verify_source_runtime_ecs as runtime_verifier


CANDIDATE_TASK_FAMILY_SUFFIX = "-candidate-smoke"
REGISTER_TASK_DEFINITION_KEYS = (
    "taskRoleArn",
    "executionRoleArn",
    "networkMode",
    "containerDefinitions",
    "volumes",
    "placementConstraints",
    "requiresCompatibilities",
    "cpu",
    "memory",
    "pidMode",
    "ipcMode",
    "proxyConfiguration",
    "inferenceAccelerators",
    "ephemeralStorage",
    "runtimePlatform",
    "enableFaultInjection",
)
ECR_DIGEST_IMAGE_PATTERN = (
    r"^[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$"
)


def _candidate_task_family(family: str) -> str:
    family = family.strip()
    if not family:
        raise ValueError("task definition is missing family")
    if family.endswith(CANDIDATE_TASK_FAMILY_SUFFIX):
        return family
    return f"{family[: 255 - len(CANDIDATE_TASK_FAMILY_SUFFIX)]}{CANDIDATE_TASK_FAMILY_SUFFIX}"


def _validate_candidate_image(image: str, ecr_base_uri: str) -> str:
    image = image.strip()
    ecr_base_uri = ecr_base_uri.strip().removesuffix("/")
    if not re.fullmatch(ECR_DIGEST_IMAGE_PATTERN, image):
        raise ValueError("candidate image must be an exact ECR image digest")
    if not ecr_base_uri or not image.startswith(f"{ecr_base_uri}@sha256:"):
        raise ValueError("candidate image must use the stack's configured ECR repository")
    return image


def _task_definition_with_candidate_image(
    task_definition: dict[str, Any],
    candidate_image: str,
) -> dict[str, Any]:
    containers = task_definition.get("containerDefinitions") or []
    cerebro_containers = [container for container in containers if container.get("name") == "cerebro"]
    if len(cerebro_containers) != 1:
        raise ValueError(f"task definition must contain exactly one cerebro container, found {len(cerebro_containers)}")

    updated_containers: list[dict[str, Any]] = []
    for container in containers:
        updated = dict(container)
        if updated.get("name") == "cerebro":
            updated["image"] = candidate_image
        updated_containers.append(updated)

    payload = {
        key: task_definition[key]
        for key in REGISTER_TASK_DEFINITION_KEYS
        if key in task_definition and task_definition[key] not in (None, [], {})
    }
    payload["family"] = _candidate_task_family(str(task_definition.get("family") or ""))
    payload["containerDefinitions"] = updated_containers
    return payload


def prepare_candidate_task_definition(
    stack_file: Path,
    runtime_id: str,
    candidate_image: str,
    region: str,
) -> str:
    config = runtime_verifier._load_config(stack_file)
    stack = runtime_verifier._stack_name(stack_file)
    environment = str(config.get("environment") or stack).strip()
    candidate_image = _validate_candidate_image(candidate_image, str(config.get("ecrBaseUri") or ""))
    runtime_ids = runtime_verifier._declared_runtime_ids(config, "", {runtime_id})
    if runtime_ids != [runtime_id]:
        raise ValueError("candidate smoke requires one enabled declared runtime ID")

    targets = runtime_verifier._runtime_targets(
        config,
        runtime_ids,
        f"cerebro-{environment}",
        region,
    )
    if len(targets) != 1:
        raise ValueError(f"candidate smoke requires one deployed runtime target, found {len(targets)}")

    scheduled_task_definition = targets[0].target["EcsParameters"]["TaskDefinitionArn"]
    base_task_definition = runtime_verifier._latest_active_task_definition(scheduled_task_definition, region)
    response = runtime_verifier._aws(
        ["ecs", "describe-task-definition", "--task-definition", base_task_definition],
        region,
    )
    payload = _task_definition_with_candidate_image(response.get("taskDefinition") or {}, candidate_image)
    registered = runtime_verifier._aws(
        [
            "ecs",
            "register-task-definition",
            "--cli-input-json",
            json.dumps(payload, separators=(",", ":")),
        ],
        region,
    )
    arn = str(((registered or {}).get("taskDefinition") or {}).get("taskDefinitionArn") or "").strip()
    if not arn:
        raise RuntimeError("candidate task definition registration did not return an ARN")
    print(json.dumps({"event": "candidate_runtime_task_definition_registered", "family": payload["family"]}, sort_keys=True))
    return arn


def _append_github_output(path: Path, task_definition: str) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"task_definition={task_definition}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Register a temporary source-runtime task definition pinned to a candidate digest.")
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument("--runtime-id", required=True)
    parser.add_argument("--candidate-image", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)

    task_definition = prepare_candidate_task_definition(
        args.stack_file,
        args.runtime_id.strip(),
        args.candidate_image,
        args.region,
    )
    if args.github_output:
        _append_github_output(args.github_output, task_definition)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
