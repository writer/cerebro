#!/usr/bin/env python3
"""Select focused validation commands from changed Cerebro paths."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


class CommandPlan:
    def __init__(self, name: str, argv: list[str], reason: str) -> None:
        self.name = name
        self.argv = argv
        self.reason = reason

    def as_dict(self) -> dict[str, object]:
        return {"name": self.name, "argv": self.argv, "reason": self.reason}


def git_lines(args: list[str], repo: Path) -> list[str]:
    result = subprocess.run(["git", *args], cwd=repo, check=True, text=True, stdout=subprocess.PIPE)
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def changed_files(base: str, head: str, repo: Path) -> list[str]:
    files: set[str] = set()
    probes = [
        ["diff", "--name-only", "--diff-filter=ACMR", f"{base}...{head}"],
        ["diff", "--name-only", "--diff-filter=ACMR"],
        ["diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        ["ls-files", "--others", "--exclude-standard"],
    ]
    for probe in probes:
        try:
            files.update(git_lines(probe, repo))
        except subprocess.CalledProcessError:
            if probe[0] == "diff" and "..." in probe[-1]:
                files.update(git_lines(["diff", "--name-only", "--diff-filter=ACMR", base, head], repo))
            else:
                raise
    return sorted(files)


def path_matches(path: str, prefixes: tuple[str, ...] = (), suffixes: tuple[str, ...] = (), exact: tuple[str, ...] = ()) -> bool:
    return path in exact or any(path.startswith(prefix) for prefix in prefixes) or any(path.endswith(suffix) for suffix in suffixes)


def package_for_go_file(path: str, repo: Path) -> str:
    directory = Path(path).parent
    if str(directory) in {"vendor", "gen"} or str(directory).startswith("vendor/"):
        return ""
    abs_dir = repo / directory
    for parent in (abs_dir, *abs_dir.parents):
        if parent == repo:
            break
        if (parent / "go.mod").exists():
            return ""
    if not abs_dir.exists() or not any(candidate.suffix == ".go" for candidate in abs_dir.iterdir() if candidate.is_file()):
        return ""
    if str(directory) == ".":
        return "."
    return "./" + directory.as_posix()


def go_packages(files: list[str], repo: Path) -> list[str]:
    packages = {package_for_go_file(path, repo) for path in files if path.endswith(".go")}
    packages.discard("")
    return sorted(packages)


def add_command(commands: list[CommandPlan], seen: set[str], name: str, argv: list[str], reason: str) -> None:
    key = "\x00".join(argv)
    if key in seen:
        return
    seen.add(key)
    commands.append(CommandPlan(name, argv, reason))


def select_commands(files: list[str], repo: Path) -> list[CommandPlan]:
    commands: list[CommandPlan] = []
    seen: set[str] = set()
    packages = go_packages(files, repo)
    if packages:
        add_command(commands, seen, "go-test-changed-packages", ["go", "test", *packages, "-count=1"], "Go package files changed.")

    if any(path_matches(path, prefixes=("internal/connectorcatalog/catalog/", "internal/connectordefinitions/", "internal/sourcegen/"), exact=("cmd/cerebro/source_runtime_sdk.go",)) for path in files):
        add_command(commands, seen, "sourcegen-check", ["make", "sourcegen-check"], "Connector definition or sourcegen contract changed.")

    if any(path_matches(path, prefixes=("internal/graphactions/", "tools/graphactiongen/")) for path in files):
        add_command(commands, seen, "graph-action-check", ["make", "graph-action-check"], "Graph action catalog, generated registry, or generator changed.")

    if any(path_matches(path, prefixes=("sources/", "policies/", "internal/compliance/", "internal/findings/", "tools/catalogcheck/", "internal/connectorcatalog/catalog/")) for path in files):
        add_command(commands, seen, "catalog-check", ["make", "catalog-check"], "Source, policy, finding, connector, or compliance catalog changed.")

    if any(path_matches(path, prefixes=("internal/connectorcatalog/", "internal/connectordefinitions/", "internal/sourcegen/", "tools/connectorcatalogreview/"), exact=("Makefile", ".github/workflows/connector-catalog-maintenance.yml")) for path in files):
        add_command(commands, seen, "connector-catalog-review", ["make", "connector-catalog-review"], "Connector catalog metadata, generation, or maintenance review changed.")

    if any(path_matches(path, prefixes=("policies/", "schemas/", "tools/findingdsl/", "internal/findingdsl/", "tools/policyrulegen/"), exact=("internal/compliance/policy_rule_extensions.yaml",)) for path in files):
        add_command(commands, seen, "finding-dsl-check", ["make", "finding-dsl-check"], "Policy DSL authoring changed.")
        add_command(commands, seen, "policy-rule-check", ["make", "policy-rule-check"], "Policy authoring or generated rule enrichment changed.")
        add_command(commands, seen, "detection-catalog-check", ["make", "detection-catalog-check"], "Policy rule changes affect the public detection catalog.")

    if any(path_matches(path, prefixes=("internal/compliance/", "tools/controlindex/")) for path in files):
        add_command(commands, seen, "control-index-check", ["make", "control-index-check"], "Compliance controls, profiles, or control-index tooling changed.")

    if any(path_matches(path, prefixes=("proto/",), suffixes=(".proto",)) for path in files):
        add_command(commands, seen, "proto-generate-check", ["make", "proto-generate-check"], "Protobuf contracts changed.")
        add_command(commands, seen, "proto-breaking", ["make", "proto-breaking"], "Protobuf compatibility must be checked.")

    if any(path_matches(path, prefixes=("api/",), suffixes=("openapi.yaml",)) for path in files):
        add_command(commands, seen, "openapi-check", ["make", "openapi-check"], "OpenAPI or route contract changed.")
        add_command(commands, seen, "openapi-lint", ["make", "openapi-lint"], "OpenAPI lint should match CI.")

    if any(path_matches(path, prefixes=("docs/",), exact=("README.md",)) for path in files):
        add_command(commands, seen, "docs-drift-check", ["make", "docs-drift-check"], "Documentation changed.")
    if any(
        path_matches(
            path,
            prefixes=("internal/config/",),
            exact=(
                ".env.example",
                "README.md",
                "cmd/cerebro/main.go",
                "docs/domains/compliance-controls.md",
                "internal/sourceregistry/registry.go",
                "tools/controlindex/main.go",
            ),
        )
        for path in files
    ):
        add_command(commands, seen, "readme-check", ["make", "readme-check"], "README source-of-truth path changed.")

    if any(path_matches(path, prefixes=("scripts/", ".github/workflows/", ".factory/")) for path in files):
        add_command(commands, seen, "python-script-tests", ["python3", "-m", "unittest", "discover", "-s", "scripts/tests"], "Automation, review context, or workflow-adjacent files changed.")

    if any(path_matches(path, prefixes=("tools/archtests/", "tools/linters/"), exact=("Makefile",)) for path in files):
        add_command(commands, seen, "structural-checks", ["make", "check-structural-test", "check-arch"], "Structural lint or Makefile wiring changed.")

    if not commands:
        add_command(commands, seen, "no-focused-checks", ["true"], "No focused validation mapped to changed paths.")
    return commands


def run_commands(commands: list[CommandPlan], repo: Path) -> int:
    for command in commands:
        print(f"changed-check: {command.name}: {' '.join(command.argv)}", flush=True)
        print(f"changed-check: reason: {command.reason}", flush=True)
        result = subprocess.run(command.argv, cwd=repo, check=False)
        if result.returncode != 0:
            return result.returncode
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default=os.environ.get("DROID_REVIEW_BASE", "origin/main"))
    parser.add_argument("--head", default=os.environ.get("DROID_REVIEW_HEAD", "HEAD"))
    parser.add_argument("--repo", default=".")
    parser.add_argument("--json", action="store_true", help="Print the command plan as JSON.")
    parser.add_argument("--run", action="store_true", help="Execute the selected commands.")
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    files = changed_files(args.base, args.head, repo)
    commands = select_commands(files, repo)
    payload = {"base": args.base, "head": args.head, "changed_files": files, "commands": [command.as_dict() for command in commands]}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"changed-check: {len(files)} changed file(s), {len(commands)} command(s) selected", flush=True)
        for command in commands:
            print(f"- {command.name}: {' '.join(command.argv)}", flush=True)
            print(f"  reason: {command.reason}", flush=True)
    if args.run:
        return run_commands(commands, repo)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
