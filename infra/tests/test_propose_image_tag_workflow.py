from __future__ import annotations

import unittest
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "propose-image-tag.yml"
INFRA_DEPLOY_WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "infra-deploy.yml"


class ProposeImageTagWorkflowTest(unittest.TestCase):
    def _apply_step(self) -> str:
        return WORKFLOW.read_text(encoding="utf-8").split("      - name: Apply stack config update", 1)[1]

    def test_apply_step_refreshes_from_main_before_pr_commit(self) -> None:
        apply_step = self._apply_step()

        self.assertIn("CONTRACT_PATH: ${{ steps.contract.outputs.path }}", apply_step)
        self.assertIn("refresh_from_main_and_apply_update()", apply_step)
        self.assertIn("git fetch origin main:refs/remotes/origin/main", apply_step)
        self.assertIn('git checkout -f -B "${branch}" origin/main', apply_step)
        self.assertIn(
            'refresh_from_main_and_apply_update\n\n          git add "infra/aws/Pulumi.${STACK_NAME}.yaml"',
            apply_step,
        )

    def test_direct_push_refreshes_from_main_before_file_guard(self) -> None:
        apply_step = self._apply_step()
        direct_push_block = apply_step.split('if [ "${APPLY_MODE}" = "direct_push" ]; then', 1)[1].split(
            'if [ "${APPLY_MODE}" != "pull_request" ]; then',
            1,
        )[0]

        self.assertLess(
            direct_push_block.index("refresh_from_main_and_apply_update"),
            direct_push_block.index('changed_files="$(git diff --name-only)"'),
        )

    def test_pulumi_preview_jobs_have_timeout(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        for job_name in ("Preview sec-dev", "Preview go-prod", "Preview gcp-dev", "Preview gcp-prod"):
            with self.subTest(job_name=job_name):
                job_block = workflow.split(f"name: {job_name}", 1)[1].split("    steps:", 1)[0]
                self.assertIn("timeout-minutes: 20", job_block)


if __name__ == "__main__":
    unittest.main()
