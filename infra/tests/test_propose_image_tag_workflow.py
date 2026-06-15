from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "propose-image-tag.yml"
INFRA_DEPLOY_WORKFLOW = ROOT / ".github" / "workflows" / "infra-deploy.yml"
DEPLOY_APP_ACTION = ROOT / ".github" / "actions" / "deploy-app-token" / "action.yml"
DEPLOYMENT_SCRIPT = ROOT / ".github" / "scripts" / "github-deployment-status.sh"


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

    def test_trusted_sec_dev_release_uses_pr_auto_merge_not_main_push(self) -> None:
        apply_step = self._apply_step()

        self.assertNotIn('"HEAD:main"', apply_step)
        self.assertNotIn("dispatch_and_require_run", apply_step)
        self.assertIn('promotion_mode="trusted_sec_dev_release"', apply_step)
        self.assertIn("apply_mode=direct_push is deprecated", apply_step)
        self.assertIn("Trusted release promotion:", apply_step)
        self.assertIn('gh pr merge "${pr_url}" --merge --delete-branch', apply_step)

    def test_release_automation_prefers_deploy_app_token_with_pat_fallback(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        action = DEPLOY_APP_ACTION.read_text(encoding="utf-8")
        apply_step = self._apply_step()

        self.assertIn("- name: Resolve release automation auth", workflow)
        self.assertIn("actions: write", workflow)
        self.assertIn("contents: write", workflow)
        self.assertIn("pull-requests: write", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("CEREBRO_AUTORELEASE_TOKEN", workflow)
        self.assertIn("mode=deploy_app", workflow)
        self.assertIn("mode=autorelease_token", workflow)
        self.assertIn("- name: Create deploy GitHub App token", workflow)
        self.assertIn("steps.release-auth.outputs.mode == 'deploy_app'", workflow)
        self.assertIn("uses: ./.github/actions/deploy-app-token", workflow)
        self.assertIn("client-id: ${{ vars.CEREBRO_DEPLOY_APP_CLIENT_ID }}", workflow)
        self.assertIn("private-key: ${{ secrets.CEREBRO_DEPLOY_APP_PRIVATE_KEY }}", workflow)
        self.assertIn("GH_TOKEN: ${{ steps.deploy-app-token.outputs.token || secrets.CEREBRO_AUTORELEASE_TOKEN }}", apply_step)
        self.assertIn("DEPLOY_AUTH_MODE: ${{ steps.release-auth.outputs.mode }}", apply_step)
        self.assertIn('git config user.name "${DEPLOY_APP_SLUG}[bot]"', apply_step)
        self.assertIn('git config user.name "github-actions[bot]"', apply_step)
        self.assertIn('git remote set-url origin "https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"', apply_step)
        self.assertIn('git push --force-with-lease origin "HEAD:${branch}"', apply_step)
        self.assertNotIn('git push --force-with-lease "https://x-access-token:${GH_TOKEN}', apply_step)
        self.assertIn("actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1", action)
        self.assertIn("Preflight deploy GitHub App token", action)
        self.assertIn("gh api /installation/repositories", action)
        self.assertIn("permission-contents: write", action)
        self.assertIn("permission-pull-requests: write", action)
        self.assertNotIn("permission-checks: read", action)
        self.assertNotIn("permission-actions: write", action)

    def test_repository_dispatch_superseded_releases_skip_promotion(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("- name: Resolve latest stable release", workflow)
        self.assertIn("superseded=true", workflow)
        self.assertIn("if: steps.latest.outputs.superseded != 'true'", workflow)
        self.assertIn("- name: Report superseded release", workflow)

    def test_public_release_reads_use_unauthenticated_rest_api(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for step_name in (
            "Verify release metadata",
            "Resolve latest stable release",
            "Download and verify runtime deploy contract",
        ):
            with self.subTest(step_name=step_name):
                step = workflow.split(f"- name: {step_name}", 1)[1].split("\n      - name:", 1)[0]
                self.assertNotIn("GH_TOKEN: ${{ github.token }}", step)
                self.assertNotIn("gh release", step)
                self.assertIn("https://api.github.com/repos/writer/cerebro/releases", step)

        apply_step = self._apply_step()
        self.assertIn("https://api.github.com/repos/writer/cerebro/releases?per_page=100", apply_step)

    def test_release_pr_body_surfaces_runtime_contract_evidence(self) -> None:
        apply_step = self._apply_step()

        self.assertIn("contract_sources=", apply_step)
        self.assertIn("contract_runtimes=", apply_step)
        self.assertIn("contract_receipts=", apply_step)
        self.assertIn("source_health_receipt", apply_step)
        self.assertIn("Runtime contract:", apply_step)

    def test_image_tag_proposal_builds_deploy_preflight_receipt_after_contract_verification(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("infra/scripts/build_deploy_preflight_receipt.py", workflow)
        self.assertLess(
            workflow.index("infra/scripts/verify_runtime_contract.py"),
            workflow.index("infra/scripts/build_deploy_preflight_receipt.py"),
        )
        self.assertIn('--output "deploy-preflight-${STACK_NAME}.json"', workflow)
        self.assertIn('--output "deploy-preflight-sec-dev.json"', workflow)

    def test_go_prod_auto_merge_rechecks_latest_and_sec_dev_success(self) -> None:
        apply_step = self._apply_step()
        auto_merge_block = apply_step.split("auto_merge_trusted_pr() {", 1)[1].split(
            'gh pr merge "${pr_url}" --merge --delete-branch',
            1,
        )[0]

        self.assertIn('release_is_still_latest "${pr_url}"', auto_merge_block)
        self.assertIn("wait_for_sec_dev_release", auto_merge_block)
        self.assertIn("--event push", apply_step)
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

    def test_main_aws_deploy_jobs_refresh_before_pulumi_up(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        for job_marker, stack in (("  deploy-sec-dev-main:", "sec-dev"), ("  deploy-go-prod:", "go-prod")):
            with self.subTest(stack=stack):
                job_block = workflow.split(job_marker, 1)[1].split("\n  # ", 1)[0]
                pulumi_up = job_block.split(f"Pulumi Up ({stack})", 1)[1].split("\n      - name:", 1)[0]
                self.assertIn("command: up", pulumi_up)
                self.assertIn(f"stack-name: {stack}", pulumi_up)
                self.assertIn("refresh: true", pulumi_up)

    def test_sec_dev_autorelease_uses_normal_push_deploys(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        deploy_block = workflow.split("  deploy-sec-dev-main:", 1)[1].split("  # Main merge: Pulumi up for go-prod stack", 1)[0]

        self.assertNotIn("chore: deploy sec-dev Cerebro", deploy_block)

    def test_aws_deploy_jobs_create_github_deployment_records(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        script = DEPLOYMENT_SCRIPT.read_text(encoding="utf-8")

        self.assertIn('gh api -X POST "repos/${GITHUB_REPOSITORY}/deployments"', script)
        self.assertIn('gh api -X POST "repos/${GITHUB_REPOSITORY}/deployments/${deployment_id}/statuses"', script)
        for job_marker, stack in (("  deploy-sec-dev-main:", "sec-dev"), ("  deploy-go-prod:", "go-prod")):
            with self.subTest(stack=stack):
                job_block = workflow.split(job_marker, 1)[1].split("\n  # ", 1)[0]
                self.assertIn("deployments: write", job_block)
                self.assertIn(f"Create GitHub deployment record ({stack})", job_block)
                self.assertIn(f"Mark GitHub deployment in progress ({stack})", job_block)
                self.assertIn(f"Complete GitHub deployment record ({stack})", job_block)
                self.assertIn(".github/scripts/github-deployment-status.sh create", job_block)
                self.assertIn(".github/scripts/github-deployment-status.sh status", job_block)

    def test_go_prod_deploy_skips_cosmo_canary_while_runtime_is_disabled(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        deploy_block = workflow.split("name: Deploy go-prod", 1)[1]
        self.assertNotIn("Verify Cosmo source canary (go-prod)", deploy_block)

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

    def test_go_prod_deploy_runs_bedrock_guard_after_pulumi_up(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        deploy_block = workflow.split("name: Deploy go-prod", 1)[1]
        self.assertLess(deploy_block.index("Pulumi Up (go-prod)"), deploy_block.index("Verify AWS Bedrock task role (go-prod)"))
        self.assertIn("scripts/verify_aws_bedrock_task_role.py --stack-file aws/Pulumi.go-prod.yaml", deploy_block)

    def test_manual_aws_deploy_runs_guards_before_pulumi_up(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        deploy_block = workflow.split("  deploy-manual:", 1)[1]
        self.assertLess(deploy_block.index("Verify AWS scan-role trust (AWS)"), deploy_block.index("Pulumi Up (AWS)"))
        self.assertLess(deploy_block.index("Verify AWS secret imports (AWS)"), deploy_block.index("Pulumi Up (AWS)"))
        self.assertLess(deploy_block.index("Pulumi Up (AWS)"), deploy_block.index("Verify AWS Bedrock task role (AWS)"))
        self.assertNotIn("Verify Cosmo source canary (AWS)", deploy_block)


if __name__ == "__main__":
    unittest.main()
