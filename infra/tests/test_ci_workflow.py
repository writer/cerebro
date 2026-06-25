from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
INFRA_DEPLOY_WORKFLOW = ROOT / ".github" / "workflows" / "infra-deploy.yml"


class CIWorkflowTest(unittest.TestCase):
    def test_main_image_promotion_runs_are_not_cancelled(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        concurrency_block = workflow.split("concurrency:", 1)[1].split("\nenv:", 1)[0]

        self.assertIn(
            "group: ci-${{ github.workflow }}-${{ github.event_name }}-${{ github.event_name == 'pull_request' && github.ref || github.run_id }}",
            concurrency_block,
        )
        self.assertIn("cancel-in-progress: ${{ github.event_name == 'pull_request' }}", concurrency_block)
        self.assertNotIn("cancel-in-progress: true", concurrency_block)

    def test_sec_prod_publish_runs_on_main_pushes_and_manual_recovery(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        publish_block = workflow.split("  publish-sec-prod:", 1)[1]

        self.assertIn("name: Publish to sec-prod ECR", publish_block)
        self.assertIn("(github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main')", publish_block)
        self.assertIn("(github.event_name == 'push' && github.ref == 'refs/heads/main'", publish_block)
        self.assertIn("infra/aws/Pulumi.go-prod.yaml", publish_block)

    def test_publish_jobs_upload_promotion_receipts(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("Record sec-dev promotion receipt", workflow)
        self.assertIn("Record sec-prod promotion receipt", workflow)
        self.assertIn("infra/scripts/ensure_ecr_promotion.py --stack-file infra/aws/Pulumi.sec-dev.yaml", workflow)
        self.assertIn("infra/scripts/ensure_ecr_promotion.py --stack-file infra/aws/Pulumi.go-prod.yaml", workflow)
        self.assertIn("name: promotion-receipt-sec-dev", workflow)
        self.assertIn("name: promotion-receipt-go-prod", workflow)

    def test_ci_workflow_contract_changes_do_not_trigger_deploys(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        filter_block = workflow.split("- name: Filter changed paths", 1)[1].split("\n      - name:", 1)[0]
        static_only_pattern = next(
            (
                match
                for match in re.finditer(r"grep -Ev '([^']+)' changed\.txt", filter_block)
                if "ci_workflow" in match.group(1)
            ),
            None,
        )

        self.assertIsNotNone(static_only_pattern)
        assert static_only_pattern is not None
        static_only_paths = re.compile(static_only_pattern.group(1))
        self.assertRegex("infra/tests/test_ci_workflow.py", static_only_paths)

    def test_gcp_main_deploy_only_runs_for_gcp_program_changes(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        filter_block = workflow.split("- name: Filter changed paths", 1)[1].split("\n      - name:", 1)[0]
        deps_block = filter_block.split("if grep -Eq '^infra/(pyproject.toml|uv.lock)$' changed.txt; then", 1)[
            1
        ].split("\n          fi", 1)[0]
        helper_block = filter_block.split(
            "grep -Eq '^infra/scripts/|^infra/tests/'; then",
            1,
        )[1].split("\n          fi", 1)[0]

        self.assertIn("gcp_deploy: ${{ steps.filter.outputs.gcp_deploy }}", workflow)
        self.assertIn("gcp_deploy=false", filter_block)
        self.assertRegex(
            filter_block,
            r"if grep -Eq '\^infra/gcp/' changed\.txt; then\n\s+gcp=true\n\s+gcp_deploy=true\n\s+fi",
        )
        self.assertIn("gcp=true", deps_block)
        self.assertNotIn("gcp_deploy=true", deps_block)
        self.assertIn("gcp=true", helper_block)
        self.assertNotIn("gcp_deploy=true", helper_block)
        self.assertIn("needs.changes.outputs.gcp_deploy == 'true'", workflow)


if __name__ == "__main__":
    unittest.main()
