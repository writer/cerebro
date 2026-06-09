#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import yaml

try:
    from aws.source_rollouts import apply_source_runtime_rollouts
except ModuleNotFoundError:  # pragma: no cover - used when executed as scripts/plan_aws_deploy_verifications.py
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from aws.source_rollouts import apply_source_runtime_rollouts


def _repo_root(stack_file: Path) -> Path:
    resolved = stack_file.resolve()
    if resolved.parent.name == "aws" and resolved.parent.parent.name == "infra":
        return resolved.parent.parent.parent
    return Path.cwd()


def _load_config_text(text: str) -> dict[str, Any]:
    loaded = yaml.safe_load(text) or {}
    config = loaded.get("config") or {}
    config = {
        key.removeprefix("cerebro:"): value
        for key, value in config.items()
        if isinstance(key, str) and key.startswith("cerebro:")
    }
    return apply_source_runtime_rollouts(config)


def _load_current_config(stack_file: Path) -> dict[str, Any]:
    return _load_config_text(stack_file.read_text(encoding="utf-8"))


def _load_config_at_ref(repo_root: Path, ref: str, stack_file: Path) -> dict[str, Any] | None:
    if not ref:
        return None
    relative = stack_file.resolve().relative_to(repo_root)
    completed = subprocess.run(
        ["git", "-C", str(repo_root), "show", f"{ref}:{relative.as_posix()}"],
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        return None
    return _load_config_text(completed.stdout)


def _runtime_map(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    runtimes = config.get("sourceRuntimes") or []
    if not isinstance(runtimes, list):
        return {}
    return {
        str(runtime.get("id") or "").strip(): runtime
        for runtime in runtimes
        if isinstance(runtime, dict) and str(runtime.get("id") or "").strip()
    }


def _changed_runtime_ids(previous: dict[str, Any] | None, current: dict[str, Any]) -> list[str]:
    if previous is None:
        return []
    old_runtimes = _runtime_map(previous)
    new_runtimes = _runtime_map(current)
    changed: list[str] = []
    for runtime_id in sorted(set(old_runtimes) | set(new_runtimes)):
        if old_runtimes.get(runtime_id) != new_runtimes.get(runtime_id):
            changed.append(runtime_id)
    return changed


def _source_id(runtime: dict[str, Any] | None) -> str:
    if not isinstance(runtime, dict):
        return ""
    return str(runtime.get("sourceId") or runtime.get("source_id") or "").strip()


def _write_outputs(path: Path | None, outputs: dict[str, str]) -> None:
    if path is None:
        return
    with path.open("a", encoding="utf-8") as handle:
        for key, value in outputs.items():
            handle.write(f"{key}={value}\n")


def plan(previous: dict[str, Any] | None, current: dict[str, Any]) -> dict[str, str]:
    changed_ids = _changed_runtime_ids(previous, current)
    current_runtimes = _runtime_map(current)
    source_ids = {_source_id(current_runtimes.get(runtime_id)) for runtime_id in changed_ids}
    source_ids.discard("")
    if changed_ids and len(source_ids) == 1:
        return {
            "source_id": next(iter(source_ids)),
            "runtime_ids": ",".join(changed_ids),
            "source_runtime_scope": "targeted",
        }
    return {
        "source_id": "cosmo",
        "runtime_ids": "",
        "source_runtime_scope": "smoke",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Plan fast AWS deploy verification scope from a stack diff.")
    parser.add_argument("--stack-file", type=Path, required=True)
    parser.add_argument("--base-ref", default="")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)

    repo_root = _repo_root(args.stack_file)
    current = _load_current_config(args.stack_file)
    previous = _load_config_at_ref(repo_root, args.base_ref, args.stack_file)
    outputs = plan(previous, current)
    print(json.dumps(outputs, sort_keys=True))
    _write_outputs(args.github_output, outputs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
