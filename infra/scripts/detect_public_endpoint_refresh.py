#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
from typing import Any

import yaml


ATTACK_PATH_RELATION_MIN_TAG = (2, 1, 46)


def _stack_name(path: Path) -> str:
    name = path.name
    if name.startswith("Pulumi.") and name.endswith(".yaml"):
        return name.removeprefix("Pulumi.").removesuffix(".yaml")
    return path.stem


def _load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    config = loaded.get("config")
    if not isinstance(config, dict):
        raise ValueError(f"{path} must contain a top-level config mapping")
    return {
        key.removeprefix("cerebro:"): value
        for key, value in config.items()
        if isinstance(key, str) and key.startswith("cerebro:")
    }


def _resource_prefix(config: dict[str, Any], stack: str) -> str:
    environment = str(config.get("environment") or stack).strip()
    if not environment:
        raise ValueError("cerebro:environment is required")
    return f"cerebro-{environment}"


def _image_tag_version(value: Any) -> tuple[int, int, int] | None:
    match = re.match(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$", str(value or "").strip())
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def _has_public_endpoint_runtime(config: dict[str, Any]) -> bool:
    runtimes = config.get("sourceRuntimes") or []
    if not isinstance(runtimes, list):
        return False
    for runtime in runtimes:
        if not isinstance(runtime, dict) or str(runtime.get("sourceId") or runtime.get("source_id") or "").strip() != "aws":
            continue
        runtime_config = runtime.get("config") or {}
        if isinstance(runtime_config, dict) and str(runtime_config.get("family") or "").strip() == "public_endpoint":
            return True
    return False


def _should_refresh_public_endpoint_runtimes(config: dict[str, Any], deployed_image_tag: str) -> bool:
    old_version = _image_tag_version(deployed_image_tag)
    new_version = _image_tag_version(config.get("imageTag"))
    return bool(
        old_version
        and new_version
        and old_version < ATTACK_PATH_RELATION_MIN_TAG <= new_version
        and _has_public_endpoint_runtime(config)
    )


def _aws(args: list[str], region: str) -> Any:
    command = ["aws", *args, "--region", region, "--output", "json"]
    completed = subprocess.run(command, check=True, text=True, capture_output=True)
    if not completed.stdout.strip():
        return None
    return json.loads(completed.stdout)


def _deployed_image_tag(config: dict[str, Any], stack: str, region: str) -> str:
    resource_prefix = _resource_prefix(config, stack)
    cluster = f"{resource_prefix}-cluster"
    service_name = f"{resource_prefix}-api"
    service_response = _aws(["ecs", "describe-services", "--cluster", cluster, "--services", service_name], region)
    services = service_response.get("services") or []
    if len(services) != 1:
        raise RuntimeError(f"expected one service named {service_name}, got {len(services)}")
    task_definition = str(services[0].get("taskDefinition") or "").strip()
    if not task_definition:
        raise RuntimeError(f"{service_name} is missing a task definition")
    task_response = _aws(["ecs", "describe-task-definition", "--task-definition", task_definition], region)
    containers = (task_response.get("taskDefinition") or {}).get("containerDefinitions") or []
    container = next((item for item in containers if item.get("name") == "cerebro"), None)
    image = str((container or {}).get("image") or "").strip()
    if ":" not in image:
        raise RuntimeError(f"cerebro container image does not include a tag: {image}")
    return image.rsplit(":", 1)[1]


def _write_github_output(path: Path, values: dict[str, str]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect whether AWS public-endpoint runtimes need a one-time refresh.")
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)

    stack = _stack_name(args.stack_file)
    config = _load_config(args.stack_file)
    old_tag = _deployed_image_tag(config, stack, args.region)
    new_tag = str(config.get("imageTag") or "").strip()
    should_refresh = _should_refresh_public_endpoint_runtimes(config, old_tag)
    values = {
        "old_image_tag": old_tag,
        "new_image_tag": new_tag,
        "should_refresh": str(should_refresh).lower(),
    }
    if args.github_output:
        _write_github_output(args.github_output, values)
    print(json.dumps(values, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
