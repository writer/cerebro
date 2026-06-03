from __future__ import annotations

import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
README = REPO_ROOT / "README.md"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def workflow_references(markdown: str) -> set[str]:
    return set(re.findall(r"`?(\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml)`?", markdown))


def stack_names(root: Path = REPO_ROOT) -> set[str]:
    names: set[str] = set()
    for path in [*(root / "infra" / "aws").glob("Pulumi.*.yaml"), *(root / "infra" / "gcp").glob("Pulumi.*.yaml")]:
        match = re.fullmatch(r"Pulumi\.(.+)\.yaml", path.name)
        if match:
            names.add(match.group(1))
    return names


def require_text(markdown: str, snippets: list[str]) -> list[str]:
    return [snippet for snippet in snippets if snippet not in markdown]


def validate(markdown: str, root: Path = REPO_ROOT) -> list[str]:
    errors: list[str] = []

    for ref in sorted(workflow_references(markdown)):
        if not (root / ref).exists():
            errors.append(f"README references missing workflow: {ref}")

    stacks = stack_names(root)
    for stack in ["sec-dev", "go-prod", "gcp-dev", "gcp-prod"]:
        if stack not in stacks:
            errors.append(f"stack file missing for documented stack: {stack}")
        if stack not in markdown:
            errors.append(f"README does not mention stack: {stack}")

    missing = require_text(
        markdown,
        [
            "## Cross-repo contract",
            "`writer/cerebro` is authoritative for runtime behavior",
            "`WriterInternal/cerebro` is authoritative for Pulumi stacks",
            "cerebro-runtime-contract.json",
            "## Rollback and post-merge watch",
            "Rollback is a reviewed config change",
            ".github/workflows/source-runtime-drift.yml",
            ".github/workflows/graph-health-insight.yml",
        ],
    )
    errors.extend(f"README missing required text: {snippet}" for snippet in missing)

    return errors


def main() -> int:
    errors = validate(read(README))
    if errors:
        for error in errors:
            print(f"validate-readme: {error}", file=sys.stderr)
        return 1
    print("validate-readme: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
