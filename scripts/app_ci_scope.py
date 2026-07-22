#!/usr/bin/env python3
"""Select first-class application and core CI scopes from changed paths."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TextIO


ROOT_NPM_PATHS = frozenset({"package.json", "package-lock.json"})
MAPPED_APP_DIRS = frozenset({"slack-companion", "slack-companion-host", "web"})
CI_CONTROLLER_PATHS = frozenset(
    {
        ".github/workflows/ci.yml",
        "Makefile",
        "scripts/app_ci_scope.py",
        "scripts/app_workspace_contract.py",
        "scripts/tests/test_app_ci_scope.py",
        "scripts/tests/test_app_ci_workflow.py",
        "scripts/tests/test_app_workspace_contract.py",
    }
)
WEB_CONTRACT_PATHS = frozenset({"api/openapi.yaml"})
WEB_INTEGRATION_EXACT_PATHS = frozenset(
    {
        "api/openapi.yaml",
        "go.mod",
        "go.sum",
        "package.json",
        "package-lock.json",
    }
)
WEB_INTEGRATION_PREFIXES = (
    "cmd/cerebro/",
    "gen/cerebro/v1/",
    "internal/bootstrap/",
    "internal/config/",
    "internal/eventregistry/",
    "internal/findings/",
    "internal/graphquery/",
    "internal/graphstore/neo4j/",
    "internal/grc",
    "internal/ports/",
    "internal/querycache/",
    "internal/sourcecoverage/",
    "internal/sourcehttp/",
    "internal/sourceruntime/",
    "internal/statestore/postgres/",
)
SLACK_CONTRACT_PREFIXES = (
    "internal/agentplatform/lifecyclecontract/",
    "schemas/agent-service-lifecycle",
)
JAVASCRIPT_ONLY_PREFIXES = (
    "apps/",
    "sdk/typescript/",
)


@dataclass(frozen=True)
class CIScope:
    core: bool
    sdk: bool
    slack: bool
    web: bool
    web_image: bool
    web_integration: bool = False

    @classmethod
    def all(cls) -> "CIScope":
        return cls(
            core=True,
            sdk=True,
            slack=True,
            web=True,
            web_image=True,
            web_integration=True,
        )

    def as_outputs(self) -> dict[str, str]:
        return {
            key: "true" if value else "false"
            for key, value in asdict(self).items()
        }


def normalize_paths(paths: list[str]) -> list[str]:
    return sorted(
        {
            path.strip().removeprefix("./")
            for path in paths
            if path.strip()
        }
    )


def is_web_integration_path(path: str) -> bool:
    if path in WEB_INTEGRATION_EXACT_PATHS:
        return True
    if path.startswith("apps/web/"):
        return path not in {"apps/web/LICENSE", "apps/web/README.md"}
    return path.startswith(WEB_INTEGRATION_PREFIXES)


def select_scope(paths: list[str], *, run_all: bool = False) -> CIScope:
    normalized = normalize_paths(paths)
    if run_all or not normalized:
        return CIScope.all()
    if any(path in CI_CONTROLLER_PATHS for path in normalized):
        return CIScope.all()
    if any(
        path.startswith("apps/")
        and path != "apps/README.md"
        and not any(
            path == f"apps/{app_dir}" or path.startswith(f"apps/{app_dir}/")
            for app_dir in MAPPED_APP_DIRS
        )
        for path in normalized
    ):
        return CIScope.all()

    root_npm_changed = any(path in ROOT_NPM_PATHS for path in normalized)
    web = root_npm_changed or any(path.startswith("apps/web/") for path in normalized)
    web_integration = any(is_web_integration_path(path) for path in normalized)
    slack = root_npm_changed or any(
        path.startswith("apps/slack-companion/")
        or path.startswith("apps/slack-companion-host/")
        or path.startswith("sdk/typescript/")
        or path.startswith(SLACK_CONTRACT_PREFIXES)
        for path in normalized
    )
    sdk_contract_changed = any(
        path in WEB_CONTRACT_PATHS or path.startswith(SLACK_CONTRACT_PREFIXES)
        for path in normalized
    )
    sdk = root_npm_changed or sdk_contract_changed or any(
        path.startswith("sdk/typescript/") for path in normalized
    )

    if any(path in WEB_CONTRACT_PATHS for path in normalized):
        web = True
    if "apps/README.md" in normalized:
        web = True
        slack = True

    javascript_only = all(
        path in ROOT_NPM_PATHS
        or path == "apps/README.md"
        or path.startswith(JAVASCRIPT_ONLY_PREFIXES)
        for path in normalized
    )
    return CIScope(
        core=not javascript_only,
        sdk=sdk,
        slack=slack,
        web=web,
        web_image=web,
        web_integration=web_integration,
    )


def write_github_outputs(scope: CIScope, output: TextIO) -> None:
    for key, value in scope.as_outputs().items():
        output.write(f"{key}={value}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--all",
        action="store_true",
        dest="run_all",
        help="Select every scope, as required for main branch pushes.",
    )
    parser.add_argument(
        "--github-output",
        type=Path,
        help="Append constant-key Boolean outputs for GitHub Actions.",
    )
    parser.add_argument(
        "--null",
        action="store_true",
        help="Read NUL-delimited paths from stdin.",
    )
    args = parser.parse_args()

    input_data = sys.stdin.read()
    paths = input_data.split("\0") if args.null else input_data.splitlines()
    scope = select_scope(paths, run_all=args.run_all)
    if args.github_output is not None:
        with args.github_output.open("a", encoding="utf-8") as output:
            write_github_outputs(scope, output)
    else:
        json.dump(asdict(scope), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
