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

    def test_repository_dispatch_superseded_releases_skip_promotion(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("- name: Resolve latest stable release", workflow)
        self.assertIn("superseded=true", workflow)
        self.assertIn("if: steps.latest.outputs.superseded != 'true'", workflow)
        self.assertIn("- name: Report superseded release", workflow)

    def test_release_pr_body_surfaces_runtime_contract_evidence(self) -> None:
        apply_step = self._apply_step()

        self.assertIn("contract_sources=", apply_step)
        self.assertIn("contract_runtimes=", apply_step)
        self.assertIn("contract_receipts=", apply_step)
        self.assertIn("source_health_receipt", apply_step)
        self.assertIn("Runtime contract:", apply_step)

    def test_go_prod_auto_merge_rechecks_latest_and_sec_dev_success(self) -> None:
        apply_step = self._apply_step()
        auto_merge_block = apply_step.split("auto_merge_trusted_pr() {", 1)[1].split(
            'gh pr merge "${pr_url}" --merge --delete-branch',
            1,
        )[0]

        self.assertIn('release_is_still_latest "${pr_url}"', auto_merge_block)
        self.assertIn("wait_for_sec_dev_release", auto_merge_block)
        self.assertLess(
            auto_merge_block.rindex('release_is_still_latest "${pr_url}"'),
            auto_merge_block.index("wait_for_sec_dev_release"),
        )

    def test_pulumi_preview_jobs_have_timeout(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        for job_name in ("Preview sec-dev", "Preview go-prod", "Preview gcp-dev", "Preview gcp-prod"):
            with self.subTest(job_name=job_name):
                job_block = workflow.split(f"name: {job_name}", 1)[1].split("    steps:", 1)[0]
                self.assertIn("timeout-minutes: 20", job_block)

    def test_main_aws_deploy_jobs_fetch_history_for_verification_diff(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        for job_name in ("Deploy sec-dev", "Deploy go-prod"):
            with self.subTest(job_name=job_name):
                job_block = workflow.split(f"name: {job_name}", 1)[1].split("      - name: Install uv", 1)[0]
                self.assertIn("fetch-depth: 0", job_block)

    def test_sec_dev_autorelease_push_uses_explicit_deploy_dispatch(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        deploy_block = workflow.split("  deploy-sec-dev-main:", 1)[1].split("  # Main merge: Pulumi up for go-prod stack", 1)[0]

        self.assertIn("!startsWith(github.event.head_commit.message, 'chore: deploy sec-dev Cerebro ')", deploy_block)

    def test_go_prod_deploy_runs_cosmo_guard_before_pulumi_up(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        deploy_block = workflow.split("name: Deploy go-prod", 1)[1]
        self.assertLess(deploy_block.index("Verify Cosmo source canary (go-prod)"), deploy_block.index("Pulumi Up (go-prod)"))

    def test_go_prod_deploy_runs_secret_guard_before_pulumi_up(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        deploy_block = workflow.split("name: Deploy go-prod", 1)[1]
        self.assertLess(deploy_block.index("Verify AWS secret imports (go-prod)"), deploy_block.index("Pulumi Up (go-prod)"))
        self.assertIn("scripts/verify_aws_secret_imports.py --stack-file aws/Pulumi.go-prod.yaml", deploy_block)

    def test_go_prod_deploy_runs_scan_role_guard_before_pulumi_up(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        deploy_block = workflow.split("name: Deploy go-prod", 1)[1]
        self.assertLess(deploy_block.index("Verify AWS scan-role trust (go-prod)"), deploy_block.index("Pulumi Up (go-prod)"))
        self.assertIn("scripts/verify_aws_scan_role_trust.py --stack-file aws/Pulumi.go-prod.yaml --same-account-only", deploy_block)

    def test_manual_aws_deploy_runs_guards_before_pulumi_up(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        deploy_block = workflow.split("  deploy-manual:", 1)[1]
        self.assertLess(deploy_block.index("Verify AWS scan-role trust (AWS)"), deploy_block.index("Pulumi Up (AWS)"))
        self.assertLess(deploy_block.index("Verify AWS secret imports (AWS)"), deploy_block.index("Pulumi Up (AWS)"))
        self.assertLess(deploy_block.index("Verify Cosmo source canary (AWS)"), deploy_block.index("Pulumi Up (AWS)"))
        self.assertIn("if: github.event.inputs.environment == 'go-prod'", deploy_block)


if __name__ == "__main__":
    unittest.main()
