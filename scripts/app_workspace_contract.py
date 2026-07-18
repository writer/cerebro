#!/usr/bin/env python3
"""Validate portable application ownership in the npm monorepo."""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any


CANONICAL_REPOSITORY = "git+https://github.com/writer/cerebro.git"
DIGEST_PINNED_IMAGE_PATTERN = r"^[^\s@]+:[^\s/@:]+@sha256:[0-9a-f]{64}$"


@dataclass(frozen=True)
class ContractFailure:
    path: str
    message: str


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def workspace_matches(patterns: list[str], relative_path: str) -> bool:
    return any(fnmatch.fnmatchcase(relative_path, pattern) for pattern in patterns)


def is_app_dockerfile(path: Path) -> bool:
    name = path.name
    if name.endswith(".dockerignore"):
        return False
    return (
        name == "Dockerfile"
        or name.startswith("Dockerfile.")
        or name.endswith(".Dockerfile")
    )


def docker_instructions(path: Path) -> list[tuple[int, str]]:
    instructions: list[tuple[int, str]] = []
    logical_line = ""
    start_line = 0
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = raw_line.strip()
        if not logical_line and (not stripped or stripped.startswith("#")):
            continue
        if not logical_line:
            start_line = line_number
        continued = stripped.endswith("\\")
        content = stripped[:-1].rstrip() if continued else stripped
        logical_line = f"{logical_line} {content}".strip()
        if continued:
            continue
        instructions.append((start_line, logical_line))
        logical_line = ""
    if logical_line:
        instructions.append((start_line, logical_line))
    return instructions


def validate_dockerfile(path: Path, repo: Path) -> list[ContractFailure]:
    relative = path.relative_to(repo).as_posix()
    failures: list[ContractFailure] = []
    from_count = 0
    for line_number, instruction in docker_instructions(path):
        try:
            tokens = shlex.split(instruction, comments=False, posix=True)
        except ValueError:
            tokens = []
        if not tokens or tokens[0].upper() != "FROM":
            continue
        from_count += 1
        index = 1
        while index < len(tokens) and tokens[index].startswith("--"):
            if "=" not in tokens[index]:
                failures.append(
                    ContractFailure(
                        f"{relative}:{line_number}",
                        "FROM flags must use --name=value syntax",
                    )
                )
                index = len(tokens)
                break
            index += 1
        if index >= len(tokens):
            failures.append(
                ContractFailure(
                    f"{relative}:{line_number}",
                    "FROM must name a digest-pinned base image",
                )
            )
            continue

        image = tokens[index]
        remainder = tokens[index + 1 :]
        valid_alias = not remainder or (
            len(remainder) == 2
            and remainder[0].upper() == "AS"
            and bool(re.fullmatch(r"[A-Za-z0-9_.-]+", remainder[1]))
        )
        if not valid_alias:
            failures.append(
                ContractFailure(
                    f"{relative}:{line_number}",
                    "FROM must contain only an optional AS stage alias after the image",
                )
            )
        if not re.fullmatch(DIGEST_PINNED_IMAGE_PATTERN, image) or ":latest@sha256:" in image.lower():
            failures.append(
                ContractFailure(
                    f"{relative}:{line_number}",
                    "base image must use name:tag@sha256 with a 64-character lowercase digest",
                )
            )

    if from_count == 0:
        failures.append(
            ContractFailure(
                relative,
                "Dockerfile must declare at least one digest-pinned FROM instruction",
            )
        )
    return failures


def validate_app_workspaces(repo: Path) -> list[ContractFailure]:
    failures: list[ContractFailure] = []
    root_manifest = load_json(repo / "package.json")
    lock = load_json(repo / "package-lock.json")
    workspaces = root_manifest.get("workspaces")
    if not isinstance(workspaces, list) or not all(isinstance(item, str) for item in workspaces):
        return [ContractFailure("package.json", "workspaces must be a string array")]

    lock_packages = lock.get("packages")
    if not isinstance(lock_packages, dict):
        return [ContractFailure("package-lock.json", "packages must be an object")]
    lock_root = lock_packages.get("")
    if not isinstance(lock_root, dict) or lock_root.get("workspaces") != workspaces:
        failures.append(
            ContractFailure(
                "package-lock.json",
                "root workspace declarations must match package.json",
            )
        )

    app_root = repo / "apps"
    app_dirs = sorted(path for path in app_root.iterdir() if (path / "package.json").is_file())
    if not app_dirs:
        failures.append(ContractFailure("apps", "at least one application workspace is required"))

    for app_dir in app_dirs:
        relative = app_dir.relative_to(repo).as_posix()
        manifest_path = f"{relative}/package.json"
        manifest = load_json(app_dir / "package.json")
        expected_name = f"@writer/cerebro-{app_dir.name}"

        if not workspace_matches(workspaces, relative):
            failures.append(ContractFailure(manifest_path, "application is not covered by root workspaces"))
        if manifest.get("name") != expected_name:
            failures.append(ContractFailure(manifest_path, f"name must be {expected_name}"))
        if manifest.get("private") is not True:
            failures.append(ContractFailure(manifest_path, "application packages must be private"))
        if not isinstance(manifest.get("license"), str) or not manifest["license"].strip():
            failures.append(ContractFailure(manifest_path, "license must be declared"))

        repository = manifest.get("repository")
        if not isinstance(repository, dict):
            failures.append(ContractFailure(manifest_path, "repository must be an object"))
        else:
            if repository.get("type") != "git" or repository.get("url") != CANONICAL_REPOSITORY:
                failures.append(ContractFailure(manifest_path, "repository must point to the canonical monorepo"))
            if repository.get("directory") != relative:
                failures.append(ContractFailure(manifest_path, f"repository.directory must be {relative}"))

        scripts = manifest.get("scripts")
        if not isinstance(scripts, dict):
            failures.append(ContractFailure(manifest_path, "scripts must be an object"))
        else:
            for script in ("build", "check", "test"):
                if not isinstance(scripts.get(script), str) or not scripts[script].strip():
                    failures.append(ContractFailure(manifest_path, f"scripts.{script} must be declared"))
            if any("publish" in key.lower() for key in scripts):
                failures.append(ContractFailure(manifest_path, "application packages must not declare publish scripts"))

        if "publishConfig" in manifest:
            failures.append(ContractFailure(manifest_path, "application packages must not declare publishConfig"))
        if (app_dir / "package-lock.json").exists():
            failures.append(ContractFailure(f"{relative}/package-lock.json", "use the root workspace lockfile"))

        lock_entry = lock_packages.get(relative)
        if not isinstance(lock_entry, dict):
            failures.append(ContractFailure("package-lock.json", f"missing workspace entry for {relative}"))
        elif lock_entry.get("name") != expected_name:
            failures.append(ContractFailure("package-lock.json", f"workspace entry for {relative} has the wrong name"))

    dockerfiles = sorted(
        path
        for path in app_root.rglob("*")
        if path.is_file() and is_app_dockerfile(path)
    )
    for dockerfile in dockerfiles:
        failures.extend(validate_dockerfile(dockerfile, repo))

    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    args = parser.parse_args()

    failures = validate_app_workspaces(args.repo.resolve())
    if failures:
        for failure in failures:
            print(f"app-workspace-contract: {failure.path}: {failure.message}")
        return 1
    print("app-workspace-contract: application workspaces are owned by the monorepo")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
