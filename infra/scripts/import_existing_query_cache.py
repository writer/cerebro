#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
from typing import Any

import yaml


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


def _config_bool(config: dict[str, Any], key: str, default: bool = False) -> bool:
    value = config.get(key, default)
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _cache_name(config: dict[str, Any], stack: str) -> str:
    environment = str(config.get("environment") or stack).strip()
    if not environment:
        raise ValueError("cerebro:environment is required")
    return f"cerebro-{environment}-query-cache"


def _run(command: list[str], cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, check=check, text=True, capture_output=True)


def _cache_in_state(cache_name: str, stack: str, work_dir: Path) -> bool:
    completed = _run(["pulumi", "stack", "--show-urns", "--stack", stack], cwd=work_dir)
    return f"::aws:elasticache/serverlessCache:ServerlessCache::{cache_name}" in completed.stdout


def _cache_exists(cache_name: str, region: str) -> bool:
    completed = _run(
        [
            "aws",
            "elasticache",
            "describe-serverless-caches",
            "--serverless-cache-name",
            cache_name,
            "--region",
            region,
            "--output",
            "json",
        ],
        check=False,
    )
    if completed.returncode == 0:
        return bool(json.loads(completed.stdout or "{}").get("ServerlessCaches"))
    if "ServerlessCacheNotFoundFault" in completed.stderr or "not found" in completed.stderr.lower():
        return False
    raise RuntimeError(completed.stderr.strip() or f"aws describe-serverless-caches failed for {cache_name}")


def import_existing_query_cache(stack_file: Path, region: str, work_dir: Path | None = None) -> str:
    stack_file = stack_file.resolve()
    stack = _stack_name(stack_file)
    config = _load_config(stack_file)
    if not _config_bool(config, "cacheEnabled", False):
        return "cache_disabled"

    resolved_work_dir = (work_dir or stack_file.parent).resolve()
    cache_name = _cache_name(config, stack)
    if _cache_in_state(cache_name, stack, resolved_work_dir):
        return "already_managed"
    if not _cache_exists(cache_name, region):
        return "absent"

    _run(
        [
            "pulumi",
            "import",
            "--yes",
            "--stack",
            stack,
            "aws:elasticache/serverlessCache:ServerlessCache",
            cache_name,
            cache_name,
        ],
        cwd=resolved_work_dir,
    )
    return "imported"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import an existing ElastiCache query cache into Pulumi state if needed.")
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--work-dir", type=Path)
    args = parser.parse_args(argv)

    result = import_existing_query_cache(args.stack_file, args.region, args.work_dir)
    print(json.dumps({"result": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
