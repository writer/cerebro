#!/usr/bin/env python3
"""Build fast Droid review preflight context for WriterInternal/cerebro."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess
from pathlib import Path


REVIEW_REQUIRED_PATTERNS = [
    ".github/workflows/**",
    ".github/scripts/**",
    ".pre-commit-config.yaml",
    ".infisical.json",
    "renovate.json",
    "infra/aws/**",
    "infra/gcp/**",
    "infra/scripts/**",
    "infra/tests/**",
    "infra/**/*.yaml",
]
EXCLUDED_PATTERNS = ["tmp/**", "**/__pycache__/**", "**/*.pyc"]
SKIPPED_REVIEW_ACTORS = {"writer-cerebro-deploy[bot]", "app/writer-cerebro-deploy"}

PASS_RULES = [
    {
        "name": "workflow-permissions",
        "path_globs": [".github/workflows/**", ".github/scripts/**"],
        "why": "GitHub Actions changes can affect token scope, secret exposure, or privileged automation.",
        "commands": ["python3 -m unittest discover -s infra/tests"],
    },
    {
        "name": "aws-infra-safety",
        "path_globs": ["infra/aws/**"],
        "why": "AWS infrastructure changes can affect IAM, network exposure, storage, or deployment safety.",
        "commands": [
            "python3 -m compileall -q infra/aws infra/scripts infra/tests",
            "python3 infra/scripts/validate_stack_config.py infra/aws/Pulumi.sec-dev.yaml infra/aws/Pulumi.go-prod.yaml",
        ],
    },
    {
        "name": "gcp-infra-safety",
        "path_globs": ["infra/gcp/**"],
        "why": "GCP infrastructure changes can affect workload identity, IAM, or scanner access.",
        "commands": ["python3 infra/scripts/validate_gcp_config.py"],
    },
    {
        "name": "script-regression",
        "path_globs": ["infra/scripts/**", "scripts/**"],
        "why": "Operational scripts need focused regression checks and safe error handling.",
        "commands": ["python3 -m compileall -q infra/scripts scripts", "python3 -m unittest discover -s infra/tests"],
    },
    {
        "name": "test-contracts",
        "path_globs": ["infra/tests/**"],
        "why": "Test changes can weaken deployment guardrails or make CI give false confidence.",
        "commands": ["python3 -m unittest discover -s infra/tests"],
    },
]


def run_git(args: list[str]) -> str:
    completed = subprocess.run(
        ["git", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=60,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
    return completed.stdout


def changed_files(base: str, head: str) -> list[str]:
    files: set[str] = set()
    for args in (
        ["diff", "--name-only", "--diff-filter=ACMR", f"{base}...{head}"],
        ["diff", "--name-only", "--diff-filter=ACMR"],
        ["diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        ["ls-files", "--others", "--exclude-standard"],
    ):
        for line in run_git(args).splitlines():
            stripped = line.strip()
            if stripped:
                files.add(stripped)
    return sorted(file for file in files if not matches_any(file, EXCLUDED_PATTERNS))


def matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)


def selected_passes(files: list[str]) -> list[dict[str, object]]:
    selected = []
    for rule in PASS_RULES:
        patterns = [str(pattern) for pattern in rule["path_globs"]]
        if any(matches_any(file, patterns) for file in files):
            selected.append(
                {
                    "name": rule["name"],
                    "why": rule["why"],
                    "commands": rule["commands"],
                }
            )
    return selected


def is_skipped_review_actor(actor: str) -> bool:
    return actor.lower() in SKIPPED_REVIEW_ACTORS


def review_required(files: list[str], actor: str = "") -> bool:
    if is_skipped_review_actor(actor):
        return False
    if not files:
        return False
    return any(matches_any(file, REVIEW_REQUIRED_PATTERNS) for file in files)


def review_reason(required: bool, actor: str) -> str:
    if is_skipped_review_actor(actor):
        return "deploy automation bot PR"
    return "infra/workflow/security-sensitive files changed" if required else "no sensitive infra files changed"


def build_context(base: str, head: str, actor: str = "") -> dict[str, object]:
    files = changed_files(base, head)
    probes = selected_passes(files)
    required = review_required(files, actor)
    return {
        "kind": "droid_review_preflight",
        "base": base,
        "head": head,
        "actor": actor,
        "changed_files": files,
        "review_required": required,
        "review_model": "claude-opus-4-8" if required else "claude-sonnet-4.6",
        "review_reason": review_reason(required, actor),
        "probe_plan": probes,
    }


def write_outputs(context: dict[str, object]) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with open(output_path, "a", encoding="utf-8") as handle:
        handle.write(f"run_droid_review={str(bool(context['review_required'])).lower()}\n")
        handle.write(f"review_model={context['review_model']}\n")
        handle.write(f"review_reason={context['review_reason']}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default=os.environ.get("DROID_REVIEW_BASE", "origin/main"))
    parser.add_argument("--head", default=os.environ.get("DROID_REVIEW_HEAD", "HEAD"))
    parser.add_argument("--json-out", default=os.environ.get("DROID_PREFLIGHT_JSON_OUT", "tmp/droid-preflight.json"))
    args = parser.parse_args()

    context = build_context(args.base, args.head, os.environ.get("DROID_REVIEW_ACTOR", ""))
    out_path = Path(args.json_out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(context, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_outputs(context)
    print(json.dumps(context, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
