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


def run_git(args: list[str]) -> str:
    result = subprocess.run(["git", *args], cwd=REPO_ROOT, check=True, capture_output=True, text=True)
    return result.stdout.strip()


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
    return sorted(dirs)


def compat_env(base_ref: str) -> dict[str, str]:
    return {
        "MAPPER_CONTRACT_BASE_REF": base_ref,
        "REPORT_CONTRACT_BASE_REF": base_ref,
        "ENTITY_FACET_BASE_REF": base_ref,
        "AGENT_SDK_CONTRACT_BASE_REF": base_ref,
    }


def resolve_command(command: list[str]) -> list[str]:
    if not command:
        return command
    executable = command[0]
    resolved = shutil.which(executable)
    if resolved:
        return [resolved, *command[1:]]
    if executable in {"golangci-lint", "gosec", "govulncheck", "goimports"}:
        try:
            candidate = Path(
                subprocess.run(["go", "env", "GOPATH"], cwd=REPO_ROOT, check=True, capture_output=True, text=True).stdout.strip()
            ) / "bin" / executable
            if candidate.exists():
                return [str(candidate), *command[1:]]
        except (subprocess.CalledProcessError, FileNotFoundError):
            return command
    return command


def add_step(steps: dict[str, Step], step: Step) -> None:
    existing = steps.get(step.key)
    if existing is None:
        steps[step.key] = step
        return
    for reason in step.reasons:
        if reason not in existing.reasons:
            existing.reasons.append(reason)


def plan_changed(files: list[str], base_ref: str) -> list[Step]:
    steps: dict[str, Step] = {}
    compat = compat_env(base_ref)
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

    if any_match(files, ["api/openapi.yaml", "internal/api/**", "scripts/openapi_route_parity.go"]):
        add_step(
            steps,
            Step(
                key="openapi-check",
                summary="Verify route parity and OpenAPI linting",
                command=["make", "openapi-check"],
                reasons=["API route or OpenAPI surface changed"],
            ),
        )

    if any_match(files, ["internal/app/app_config.go", "internal/config/**", "scripts/generate_config_docs/**", "docs/CONFIG_ENV_VARS.md"]):
        add_step(
            steps,
            Step(
                key="config-docs-check",
                summary="Verify generated config docs are up to date",
                command=["make", "config-docs-check"],
                reasons=["config loading or config docs changed"],
            ),
        )

    if any_match(files, [
        "internal/graph/node.go",
        "internal/graph/edge.go",
        "internal/graph/schema_registry.go",
        "internal/graph/schema_registry_test.go",
        "internal/graphingest/**",
        "scripts/generate_graph_ontology_docs/**",
        "docs/GRAPH_ONTOLOGY_AUTOGEN.md",
    ]):
        add_step(
            steps,
            Step(
                key="ontology-docs-check",
                summary="Verify generated ontology docs are up to date",
                command=["make", "ontology-docs-check"],
                reasons=["ontology or ingest mapping inputs changed"],
            ),
        )
        add_step(
            steps,
            Step(
                key="graph-ontology-guardrails",
                summary="Run graph ingest ontology guardrail tests",
                command=["make", "graph-ontology-guardrails"],
                reasons=["ontology or ingest mapping inputs changed"],
            ),
        )

    if any_match(files, [
        "internal/platformevents/**",
        "internal/webhooks/**",
        "internal/graphingest/**",
        "internal/api/server_handlers_graph_writeback.go",
        "scripts/generate_cloudevents_docs/**",
        "scripts/check_cloudevents_contract_compat/**",
        "docs/CLOUDEVENTS_AUTOGEN.md",
        "docs/CLOUDEVENTS_CONTRACTS.json",
    ]):
        add_step(
            steps,
            Step(
                key="cloudevents-docs-check",
                summary="Verify generated CloudEvents docs are up to date",
                command=["make", "cloudevents-docs-check"],
                reasons=["CloudEvents-producing surfaces changed"],
            ),
        )
        add_step(
            steps,
            Step(
                key="cloudevents-contract-compat",
                summary="Enforce CloudEvents contract compatibility",
                command=["go", "run", "./scripts/check_cloudevents_contract_compat/main.go", "--require-baseline", f"--base-ref={base_ref}"],
                reasons=["CloudEvents-producing surfaces changed"],
                env=compat,
            ),
        )

    if any_match(files, [
        "internal/graph/report*",
        "internal/api/server_handlers_graph_intelligence.go",
        "internal/api/server_handlers_platform.go",
        "scripts/generate_report_contract_docs/**",
        "scripts/check_report_contract_compat/**",
        "docs/GRAPH_REPORT_CONTRACTS_AUTOGEN.md",
        "docs/GRAPH_REPORT_CONTRACTS.json",
    ]):
        add_step(
            steps,
            Step(
                key="report-contract-docs-check",
                summary="Verify generated report contract docs are up to date",
                command=["make", "report-contract-docs-check"],
                reasons=["report runtime or report contracts changed"],
            ),
        )
        add_step(
            steps,
            Step(
                key="report-contract-compat",
                summary="Enforce report contract compatibility",
                command=["go", "run", "./scripts/check_report_contract_compat/main.go", "--require-baseline", f"--base-ref={base_ref}"],
                reasons=["report runtime or report contracts changed"],
                env=compat,
            ),
        )

    if any_match(files, [
        "internal/graph/entity_facet*",
        "internal/graph/entity_facets.go",
        "internal/graph/entity_subresources.go",
        "internal/graph/entity_summary_report.go",
        "internal/api/server_handlers_platform_entities.go",
        "scripts/generate_entity_facet_docs/**",
        "scripts/check_entity_facet_compat/**",
        "docs/GRAPH_ENTITY_FACETS_AUTOGEN.md",
        "docs/GRAPH_ENTITY_FACETS.json",
        "docs/GRAPH_ENTITY_FACET_ARCHITECTURE.md",
    ]):
        add_step(
            steps,
            Step(
                key="entity-facet-docs-check",
                summary="Verify generated entity facet docs are up to date",
                command=["make", "entity-facet-docs-check"],
                reasons=["entity facet surfaces changed"],
            ),
        )
        add_step(
            steps,
            Step(
                key="entity-facet-contract-compat",
                summary="Enforce entity facet contract compatibility",
                command=["go", "run", "./scripts/check_entity_facet_compat/main.go", "--require-baseline", f"--base-ref={base_ref}"],
                reasons=["entity facet surfaces changed"],
                env=compat,
            ),
        )

    if any_match(files, [
        "internal/agentsdk/**",
        "internal/api/server_handlers_agent_sdk*",
        "internal/app/app_agent_sdk*",
        "internal/app/app_cerebro_tools*",
        "sdk/**",
        "scripts/generate_agent_sdk_docs/**",
        "scripts/generate_agent_sdk_packages/**",
        "scripts/check_agent_sdk_contract_compat/**",
        "docs/AGENT_SDK_AUTOGEN.md",
        "docs/AGENT_SDK_CONTRACTS.json",
        "docs/AGENT_SDK_PACKAGES_AUTOGEN.md",
    ]):
        add_step(
            steps,
            Step(
                key="agent-sdk-docs-check",
                summary="Verify generated Agent SDK docs are up to date",
                command=["make", "agent-sdk-docs-check"],
                reasons=["Agent SDK contracts changed"],
            ),
        )
        add_step(
            steps,
            Step(
                key="agent-sdk-contract-compat",
                summary="Enforce Agent SDK contract compatibility",
                command=["go", "run", "./scripts/check_agent_sdk_contract_compat/main.go", "--require-baseline", f"--base-ref={base_ref}"],
                reasons=["Agent SDK contracts changed"],
                env=compat,
            ),
        )
        add_step(
            steps,
            Step(
                key="agent-sdk-packages-check",
                summary="Verify generated Agent SDK packages are up to date and valid",
                command=["make", "agent-sdk-packages-check"],
                reasons=["Agent SDK packages or contracts changed"],
            ),
        )

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

    if any_match(files, ["Makefile", ".githooks/**", "docs/DEVELOPMENT.md", "scripts/devex.py", "internal/app/devex_static_test.go"]):
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
    compat = compat_env(base_ref)
    return [
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
            command=["make", "vendor-check", "openapi-check", "config-docs-check", "ontology-docs-check", "cloudevents-docs-check", "report-contract-docs-check", "entity-facet-docs-check", "agent-sdk-docs-check", "agent-sdk-packages-check"],
            reasons=["full PR preflight"],
        ),
        Step(
            key="graph-ontology-guardrails",
            summary="Run ontology guardrail tests",
            command=["make", "graph-ontology-guardrails"],
            reasons=["full PR preflight"],
        ),
        Step(
            key="policy-validate",
            summary="Validate policy bundle",
            command=["make", "policy-validate"],
            reasons=["full PR preflight"],
        ),
        Step(
            key="cloudevents-contract-compat",
            summary="Enforce CloudEvents contract compatibility",
            command=["go", "run", "./scripts/check_cloudevents_contract_compat/main.go", "--require-baseline", f"--base-ref={base_ref}"],
            reasons=["full PR preflight"],
            env=compat,
        ),
        Step(
            key="report-contract-compat",
            summary="Enforce report contract compatibility",
            command=["go", "run", "./scripts/check_report_contract_compat/main.go", "--require-baseline", f"--base-ref={base_ref}"],
            reasons=["full PR preflight"],
            env=compat,
        ),
        Step(
            key="entity-facet-contract-compat",
            summary="Enforce entity facet contract compatibility",
            command=["go", "run", "./scripts/check_entity_facet_compat/main.go", "--require-baseline", f"--base-ref={base_ref}"],
            reasons=["full PR preflight"],
            env=compat,
        ),
        Step(
            key="agent-sdk-contract-compat",
            summary="Enforce Agent SDK contract compatibility",
            command=["go", "run", "./scripts/check_agent_sdk_contract_compat/main.go", "--require-baseline", f"--base-ref={base_ref}"],
            reasons=["full PR preflight"],
            env=compat,
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
