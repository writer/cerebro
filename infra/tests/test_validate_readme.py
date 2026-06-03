from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import validate_readme


VALID_MARKDOWN = """\
# WriterInternal Cerebro

## Cross-repo contract

- `writer/cerebro` is authoritative for runtime behavior, CLI/API contracts, source catalogs, release artifacts, and runtime deploy contracts.
- `WriterInternal/cerebro` is authoritative for Pulumi stacks, environment config, image promotion, deployment workflows, and operational verification.
- The release bridge is the signed runtime image plus `cerebro-runtime-contract.json`.

Stacks: sec-dev, go-prod, gcp-dev, gcp-prod.

Use `.github/workflows/infra-deploy.yml`.

## Rollback and post-merge watch

Rollback is a reviewed config change.
Watch `.github/workflows/source-runtime-drift.yml` and `.github/workflows/graph-health-insight.yml`.
"""


def make_repo(root: Path, workflows: list[str] | None = None) -> None:
    workflows = workflows or ["infra-deploy.yml", "source-runtime-drift.yml", "graph-health-insight.yml"]
    for directory in [root / "infra" / "aws", root / "infra" / "gcp", root / ".github" / "workflows"]:
        directory.mkdir(parents=True, exist_ok=True)
    for stack in ["sec-dev", "go-prod"]:
        (root / "infra" / "aws" / f"Pulumi.{stack}.yaml").write_text("config: {}\n", encoding="utf-8")
    for stack in ["gcp-dev", "gcp-prod"]:
        (root / "infra" / "gcp" / f"Pulumi.{stack}.yaml").write_text("config: {}\n", encoding="utf-8")
    for workflow in workflows:
        (root / ".github" / "workflows" / workflow).write_text("name: test\n", encoding="utf-8")


class ValidateReadmeTest(unittest.TestCase):
    def test_valid_readme_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_repo(root)
            self.assertEqual(validate_readme.validate(VALID_MARKDOWN, root), [])

    def test_missing_workflow_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_repo(root, workflows=["source-runtime-drift.yml", "graph-health-insight.yml"])
            errors = validate_readme.validate(VALID_MARKDOWN, root)
            self.assertIn("README references missing workflow: .github/workflows/infra-deploy.yml", errors)

    def test_missing_contract_anchor_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_repo(root)
            errors = validate_readme.validate(VALID_MARKDOWN.replace("cerebro-runtime-contract.json", ""), root)
            self.assertTrue(any("cerebro-runtime-contract.json" in error for error in errors))

    def test_missing_rollback_guidance_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_repo(root)
            markdown = VALID_MARKDOWN.replace("Rollback is a reviewed config change.", "")
            errors = validate_readme.validate(markdown, root)
            self.assertTrue(any("Rollback is a reviewed config change" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
