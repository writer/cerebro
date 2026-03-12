#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BASE_REF = "origin/main"
CODEGEN_CATALOG_PATH = REPO_ROOT / "devex" / "codegen_catalog.json"


@dataclass
class Step:
    key: str
    summary: str
    command: list[str]
    reasons: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "key": self.key,
            "summary": self.summary,
            "command": self.command,
            "reasons": self.reasons,
            "env": self.env,
        }


@dataclass
class CodegenCheck:
    key: str
    summary: str
    command: list[str]
    make_target: str = ""
    env: dict[str, str] = field(default_factory=dict)
    include_in_pr_generated_step: bool = False


@dataclass
class CodegenFamily:
    id: str
    title: str
    summary: str
    change_reason: str
    triggers: list[str]
    checks: list[CodegenCheck]


def run_git(args: list[str]) -> str:
    result = subprocess.run(["git", *args], cwd=REPO_ROOT, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def load_codegen_families() -> list[CodegenFamily]:
    payload = json.loads(CODEGEN_CATALOG_PATH.read_text())
    families: list[CodegenFamily] = []
    for raw_family in payload.get("families", []):
        checks = [
            CodegenCheck(
                key=raw_check["key"],
                summary=raw_check["summary"],
                command=list(raw_check["command"]),
                make_target=raw_check.get("make_target", ""),
                env=dict(raw_check.get("env", {})),
                include_in_pr_generated_step=bool(raw_check.get("include_in_pr_generated_step", False)),
            )
            for raw_check in raw_family.get("checks", [])
        ]
        families.append(
            CodegenFamily(
                id=raw_family["id"],
                title=raw_family["title"],
                summary=raw_family["summary"],
                change_reason=raw_family["change_reason"],
                triggers=list(raw_family.get("triggers", [])),
                checks=checks,
            )
        )
    return families


def changed_files(base_ref: str, staged: bool) -> list[str]:
    if staged:
        output = run_git(["diff", "--cached", "--name-only", "--diff-filter=ACMRTUXB"])
        return [line.strip() for line in output.splitlines() if line.strip()]

    merge_base = run_git(["merge-base", "HEAD", base_ref])
    outputs = [
        run_git(["diff", "--name-only", "--diff-filter=ACMRTUXB", f"{merge_base}...HEAD"]),
        run_git(["diff", "--name-only", "--diff-filter=ACMRTUXB"]),
        run_git(["diff", "--cached", "--name-only", "--diff-filter=ACMRTUXB"]),
        run_git(["ls-files", "--others", "--exclude-standard"]),
    ]
    combined: list[str] = []
    for output in outputs:
        combined.extend(line.strip() for line in output.splitlines() if line.strip())
    return sorted(dict.fromkeys(combined))


def norm_path(path: str) -> str:
    path = path.strip()
    if path.startswith("./"):
        return path[2:]
    return path


def match_any(path: str, patterns: Iterable[str]) -> bool:
    path = norm_path(path)
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)


def any_match(files: Iterable[str], patterns: Iterable[str]) -> bool:
    return any(match_any(path, patterns) for path in files)


def go_package_dirs(files: Iterable[str]) -> list[str]:
    dirs: set[str] = set()
    for path in files:
        path = norm_path(path)
        if not path.endswith(".go") or path.startswith("vendor/"):
            continue
        directory = os.path.dirname(path) or "."
        if directory == ".":
            dirs.add("./")
        else:
            dirs.add(f"./{directory}")
    return sorted(filter_build_ignored_dirs(dirs))


def filter_build_ignored_dirs(dirs: Iterable[str]) -> list[str]:
    filtered: list[str] = []
    for directory in dirs:
        result = subprocess.run(
            ["go", "list", directory],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            filtered.append(directory)
            continue
        combined = "\n".join(part for part in (result.stdout, result.stderr) if part)
        if "build constraints exclude all Go files" in combined:
            continue
        filtered.append(directory)
    return filtered


def resolve_command(command: list[str]) -> list[str]:
    if not command:
        return command
    executable = command[0]
    if executable in {"golangci-lint", "gosec", "govulncheck", "goimports"}:
        try:
            candidate = Path(
                subprocess.run(["go", "env", "GOPATH"], cwd=REPO_ROOT, check=True, capture_output=True, text=True).stdout.strip()
            ) / "bin" / executable
            if candidate.exists():
                return [str(candidate), *command[1:]]
        except (subprocess.CalledProcessError, FileNotFoundError):
            return command
    resolved = shutil.which(executable)
    if resolved:
        return [resolved, *command[1:]]
    return command


def add_step(steps: dict[str, Step], step: Step) -> None:
    existing = steps.get(step.key)
    if existing is None:
        steps[step.key] = step
        return
    for reason in step.reasons:
        if reason not in existing.reasons:
            existing.reasons.append(reason)


def render_template(value: str, base_ref: str) -> str:
    return value.replace("{base_ref}", base_ref)


def render_command(command: list[str], base_ref: str) -> list[str]:
    return [render_template(part, base_ref) for part in command]


def render_env(values: dict[str, str], base_ref: str) -> dict[str, str]:
    return {key: render_template(value, base_ref) for key, value in values.items()}


def add_codegen_changed_steps(steps: dict[str, Step], files: list[str], base_ref: str, families: list[CodegenFamily]) -> None:
    for family in families:
        if not any_match(files, family.triggers):
            continue
        for check in family.checks:
            add_step(
                steps,
                Step(
                    key=check.key,
                    summary=check.summary,
                    command=render_command(check.command, base_ref),
                    reasons=[family.change_reason],
                    env=render_env(check.env, base_ref),
                ),
            )


def pr_generated_targets(families: list[CodegenFamily]) -> list[str]:
    targets: list[str] = []
    seen: set[str] = set()
    for family in families:
        for check in family.checks:
            if not check.include_in_pr_generated_step or not check.make_target:
                continue
            if check.make_target in seen:
                continue
            seen.add(check.make_target)
            targets.append(check.make_target)
    return targets


def pr_individual_codegen_steps(base_ref: str, families: list[CodegenFamily]) -> list[Step]:
    steps: list[Step] = []
    for family in families:
        for check in family.checks:
            if check.include_in_pr_generated_step and check.make_target:
                continue
            steps.append(
                Step(
                    key=check.key,
                    summary=check.summary,
                    command=render_command(check.command, base_ref),
                    reasons=["full PR preflight"],
                    env=render_env(check.env, base_ref),
                )
            )
    return steps


def plan_changed(files: list[str], base_ref: str) -> list[Step]:
    steps: dict[str, Step] = {}
    families = load_codegen_families()
    packages = go_package_dirs(files)
    if packages:
        add_step(
            steps,
            Step(
                key="changed-go-tests",
                summary="Run go test on changed Go package directories",
                command=["go", "test", "-count=1", *packages],
                reasons=["go source changed"],
            ),
        )
        add_step(
            steps,
            Step(
                key="changed-go-lint",
                summary="Run golangci-lint on changed Go package directories",
                command=["golangci-lint", "run", "--timeout", "5m", *packages],
                reasons=["go source changed"],
            ),
        )

    if any_match(files, ["go.mod", "go.sum", "vendor/**"]):
        add_step(
            steps,
            Step(
                key="vendor-check",
                summary="Verify vendored dependencies are in sync",
                command=["make", "vendor-check"],
                reasons=["module or vendor inputs changed"],
            ),
        )

    add_codegen_changed_steps(steps, files, base_ref, families)

    if any_match(files, ["policies/**", "internal/policy/**"]):
        add_step(
            steps,
            Step(
                key="policy-validate",
                summary="Validate policy bundle",
                command=["make", "policy-validate"],
                reasons=["policy sources changed"],
            ),
        )

    if any_match(files, [
        "Makefile",
        ".githooks/**",
        "docs/DEVELOPMENT.md",
        "scripts/devex.py",
        "devex/**",
        "internal/devex/**",
        "scripts/generate_devex_codegen_docs/**",
        "docs/DEVEX_CODEGEN_AUTOGEN.md",
        "docs/DEVEX_CODEGEN_CATALOG.json",
        "internal/app/devex_static_test.go",
    ]):
        add_step(
            steps,
            Step(
                key="devex-static-tests",
                summary="Run DevEx static workflow tests",
                command=["go", "test", "./internal/app", "-run", "Test(PreCommitHookRunsFastLintOnStagedGoFiles|PrePushHookRunsChangedDevexPreflight|DockerBuildCommandsPassGoVersionBuildArg|DevelopmentGuideDocumentsDevexPreflight|DevexScriptPlansRelevantChecks|DevexScriptChangedModeIncludesWorkspaceDiffSources)"],
                reasons=["developer workflow files changed"],
            ),
        )

    return sorted(steps.values(), key=lambda item: item.key)


def plan_pr(base_ref: str) -> list[Step]:
    families = load_codegen_families()
    steps = [
        Step(
            key="go-test-all",
            summary="Run the full Go test suite",
            command=["go", "test", "./...", "-count=1"],
            reasons=["full PR preflight"],
        ),
        Step(
            key="lint-all",
            summary="Run full golangci-lint across cmd/internal/api",
            command=["golangci-lint", "run", "--timeout", "15m", "./cmd/...", "./internal/...", "./api/..."],
            reasons=["full PR preflight"],
        ),
        Step(
            key="generated-contracts",
            summary="Verify generated artifacts and contract docs",
            command=["make", "vendor-check", *pr_generated_targets(families)],
            reasons=["full PR preflight"],
        ),
        Step(
            key="policy-validate",
            summary="Validate policy bundle",
            command=["make", "policy-validate"],
            reasons=["full PR preflight"],
        ),
        Step(
            key="gosec",
            summary="Run gosec locally",
            command=["make", "gosec"],
            reasons=["full PR preflight"],
        ),
        Step(
            key="govulncheck",
            summary="Run govulncheck locally",
            command=["make", "govulncheck"],
            reasons=["full PR preflight"],
        ),
    ]
    steps[3:3] = pr_individual_codegen_steps(base_ref, families)
    return steps


def build_plan(mode: str, files: list[str], base_ref: str, staged: bool) -> dict[str, object]:
    if mode == "changed":
        changed = sorted(dict.fromkeys(norm_path(path) for path in (files or changed_files(base_ref, staged))))
        steps = plan_changed(changed, base_ref)
    else:
        changed = sorted(dict.fromkeys(norm_path(path) for path in files)) if files else []
        steps = plan_pr(base_ref)
    return {
        "mode": mode,
        "base_ref": base_ref,
        "staged": staged,
        "changed_files": changed,
        "step_count": len(steps),
        "steps": [step.as_dict() for step in steps],
    }


def print_plan(plan: dict[str, object]) -> None:
    print(f"Mode: {plan['mode']}", flush=True)
    if plan["mode"] == "changed":
        print(f"Base ref: {plan['base_ref']}", flush=True)
        changed = plan["changed_files"]
        if changed:
            print("Changed files:", flush=True)
            for path in changed:
                print(f"- {path}", flush=True)
        else:
            print("Changed files: none", flush=True)
    print("Steps:", flush=True)
    steps = plan["steps"]
    if not steps:
        print("- none", flush=True)
        return
    for step in steps:
        command = " ".join(shlex.quote(part) for part in step["command"])
        reasons = ", ".join(step["reasons"])
        print(f"- {step['key']}: {step['summary']}", flush=True)
        print(f"  command: {command}", flush=True)
        if reasons:
            print(f"  reasons: {reasons}", flush=True)


def run_steps(plan: dict[str, object]) -> int:
    steps = [Step(**step) for step in plan["steps"]]
    if not steps:
        print("devex: no steps selected", flush=True)
        return 0
    for index, step in enumerate(steps, start=1):
        resolved_command = resolve_command(step.command)
        command = " ".join(shlex.quote(part) for part in resolved_command)
        print(f"[{index}/{len(steps)}] {step.key}: {step.summary}", flush=True)
        print(f"  $ {command}", flush=True)
        env = os.environ.copy()
        env.update(step.env)
        try:
            result = subprocess.run(resolved_command, cwd=REPO_ROOT, env=env)
        except FileNotFoundError as err:
            print(f"devex: missing executable for step {step.key}: {err.filename}", file=sys.stderr)
            return 127
        if result.returncode != 0:
            print(f"devex: step failed: {step.key}", file=sys.stderr)
            return result.returncode
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cerebro developer-experience preflight runner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    for name in ("plan", "run"):
        sub = subparsers.add_parser(name)
        sub.add_argument("--mode", choices=["changed", "pr"], default="changed")
        sub.add_argument("--base-ref", default=DEFAULT_BASE_REF)
        sub.add_argument("--staged", action="store_true", help="inspect staged files instead of comparing HEAD to base-ref")
        sub.add_argument("--files", nargs="*", default=[], help="explicit file list to plan against")
        sub.add_argument("--json", action="store_true", help="emit the plan as JSON")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    plan = build_plan(args.mode, args.files, args.base_ref, args.staged)
    if args.json:
        json.dump(plan, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print_plan(plan)
    if args.command == "run":
        return run_steps(plan)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
