from __future__ import annotations

import re
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
        self.assertIn('gh pr merge "${PR_URL}" --merge --delete-branch', apply_step)

    def test_release_automation_requires_deploy_app_token(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        action = DEPLOY_APP_ACTION.read_text(encoding="utf-8")
        apply_step = self._apply_step()

        self.assertIn("- name: Resolve release automation auth", workflow)
        self.assertIn("actions: write", workflow)
        self.assertIn("checks: read", workflow)
        self.assertIn("contents: write", workflow)
        self.assertIn("pull-requests: write", workflow)
        self.assertIn("statuses: read", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertNotIn("CEREBRO_AUTORELEASE_TOKEN", workflow)
        self.assertIn("mode=deploy_app", workflow)
        self.assertNotIn("mode=autorelease_token", workflow)
        self.assertNotIn("falling back", workflow)
        self.assertIn("- name: Create deploy GitHub App token", workflow)
        self.assertNotIn("steps.release-auth.outputs.mode == 'deploy_app'", workflow)
        self.assertIn("uses: ./.github/actions/deploy-app-token", workflow)
        self.assertIn("client-id: ${{ vars.CEREBRO_DEPLOY_APP_CLIENT_ID }}", workflow)
        self.assertIn("private-key: ${{ secrets.CEREBRO_DEPLOY_APP_PRIVATE_KEY }}", workflow)
        self.assertIn("GH_TOKEN: ${{ steps.deploy-app-token.outputs.token }}", apply_step)
        self.assertNotIn("DEPLOY_AUTH_MODE", apply_step)
        self.assertIn('git config user.name "${DEPLOY_APP_SLUG}[bot]"', apply_step)
        self.assertNotIn('git config user.name "github-actions[bot]"', apply_step)
        self.assertIn('git remote set-url origin "https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"', apply_step)
        self.assertIn('git fetch origin "${branch}:refs/remotes/origin/${branch}" || true', apply_step)
        self.assertIn('git push --force-with-lease origin "HEAD:${branch}"', apply_step)
        self.assertNotIn('git push --force-with-lease "https://x-access-token:${GH_TOKEN}', apply_step)
        self.assertIn("actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1", action)
        self.assertIn("Preflight deploy GitHub App token", action)
        self.assertIn("gh api /installation/repositories", action)
        self.assertIn("Deploy App token is scoped to ${GITHUB_REPOSITORY}.", action)
        self.assertIn("permission-contents: write", action)
        self.assertIn("permission-pull-requests: write", action)
        self.assertNotIn("permission-checks: read", action)
        self.assertNotIn("check_permission", action)
        self.assertNotIn("permission-actions: write", action)

    def test_repository_dispatch_superseded_releases_skip_promotion(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("- name: Resolve latest stable release", workflow)
        self.assertIn("superseded=true", workflow)
        self.assertIn("if: steps.latest.outputs.superseded != 'true'", workflow)
        self.assertIn("- name: Report superseded release", workflow)

    def test_scheduled_release_scan_uses_canonical_latest_release(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        resolve_step = workflow.split("- name: Resolve image tag", 1)[1].split("\n      - name:", 1)[0]
        latest_step = workflow.split("- name: Resolve latest stable release", 1)[1].split("\n      - name:", 1)[0]

        self.assertIn("GH_TOKEN: ${{ github.token }}", resolve_step)
        self.assertIn('gh api "repos/writer/cerebro/releases/latest"', resolve_step)
        self.assertNotIn("ghcr.io/v2/writer/cerebro/tags/list", resolve_step)
        self.assertNotIn("tags/list?n=1000", resolve_step)
        self.assertIn('gh api "repos/writer/cerebro/releases/latest"', latest_step)
        self.assertIn('[ "${EVENT_NAME}" = "schedule" ]', latest_step)
        self.assertIn("Scheduled release scan resolved", latest_step)

    def test_release_reads_use_authenticated_github_api(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for step_name in (
            "Verify release metadata",
            "Resolve latest stable release",
            "Download and verify runtime deploy contract",
        ):
            with self.subTest(step_name=step_name):
                step = workflow.split(f"- name: {step_name}", 1)[1].split("\n      - name:", 1)[0]
                self.assertIn("GH_TOKEN: ${{ github.token }}", step)
                self.assertNotIn("gh release", step)
                self.assertIn('gh api "repos/writer/cerebro/releases', step)

        apply_step = self._apply_step()
        self.assertIn('gh api "repos/writer/cerebro/releases/latest"', apply_step)
        self.assertNotIn('gh api "repos/writer/cerebro/releases?per_page=100"', apply_step)

    def test_automated_image_promotions_do_not_downgrade_stacks(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        update_step = workflow.split("- name: Update stack config", 1)[1].split("\n      - name:", 1)[0]
        apply_step = self._apply_step()

        for step in (update_step, apply_step):
            with self.subTest(step=step[:40]):
                self.assertIn('EVENT_NAME: ${{ github.event_name }}', step)
                self.assertIn('[ "${EVENT_NAME}" != "workflow_dispatch" ]', step)
                self.assertIn("target_tag_args+=(--ensure-at-least)", step)

    def test_auto_merge_reads_checks_with_workflow_token_and_surfaces_errors(self) -> None:
        apply_step = self._apply_step()

        self.assertIn("CHECKS_TOKEN: ${{ github.token }}", apply_step)
        self.assertIn('GH_TOKEN="${CHECKS_TOKEN}" gh pr view', apply_step)
        self.assertIn("Could not read the PR check rollup", apply_step)
        self.assertNotIn("2>/dev/null || echo '[]'", apply_step)

    def test_auto_merge_refreshes_deploy_app_token_after_long_wait(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        apply_step = workflow.split("      - name: Apply stack config update", 1)[1].split(
            "      - name: Refresh deploy GitHub App token for merge",
            1,
        )[0]
        refresh_step = workflow.split("      - name: Refresh deploy GitHub App token for merge", 1)[1].split(
            "      - name: Merge trusted promotion PR",
            1,
        )[0]
        merge_step = workflow.split("      - name: Merge trusted promotion PR", 1)[1].split(
            "      - name: Report superseded release",
            1,
        )[0]

        self.assertIn("id: apply", apply_step)
        self.assertIn('echo "auto_merge_pr=${pr_url}" >> "${GITHUB_OUTPUT}"', apply_step)
        self.assertNotIn("gh pr merge", apply_step)
        self.assertIn("if: steps.apply.outputs.auto_merge_pr != ''", refresh_step)
        self.assertIn("id: merge-app-token", refresh_step)
        self.assertIn("uses: ./.github/actions/deploy-app-token", refresh_step)
        self.assertIn("GH_TOKEN: ${{ steps.merge-app-token.outputs.token }}", merge_step)
        self.assertIn("CHECKS_TOKEN: ${{ github.token }}", merge_step)
        self.assertIn('GH_TOKEN="${CHECKS_TOKEN}" gh pr view', merge_step)
        self.assertIn('[ "${pr_state}" = "MERGED" ]', merge_step)
        self.assertIn('gh pr merge "${PR_URL}" --merge --delete-branch', merge_step)

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

    def test_static_infra_validation_checks_latest_release_promotion_compatibility(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        static_checks = workflow.split("- name: Run static checks", 1)[1].split("\n  #", 1)[0]

        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", static_checks)
        self.assertIn("scripts/verify_latest_runtime_contracts.py", static_checks)
        self.assertLess(
            static_checks.index("scripts/validate_stack_config.py"),
            static_checks.index("scripts/verify_latest_runtime_contracts.py"),
        )
        self.assertLess(
            static_checks.index("scripts/verify_latest_runtime_contracts.py"),
            static_checks.index("python -m unittest discover -s tests"),
        )

    def test_runtime_contract_download_uses_stack_specific_assets(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        contract_step = workflow.split("- name: Download and verify runtime deploy contract", 1)[1].split(
            "\n      - name:",
            1,
        )[0]

        self.assertIn('contract_base="cerebro-runtime-contract-${STACK_NAME}"', contract_step)
        self.assertIn('contract_base="cerebro-runtime-contract"', contract_step)
        self.assertIn('destination="runtime-contract/cerebro-runtime-contract.${suffix}"', contract_step)
        self.assertIn("Using runtime deploy contract assets ${contract_base}.* for ${STACK_NAME}.", contract_step)
        self.assertIn("--certificate runtime-contract/cerebro-runtime-contract.json.pem", contract_step)
        self.assertIn("--signature runtime-contract/cerebro-runtime-contract.json.sig", contract_step)
        self.assertIn("runtime-contract/cerebro-runtime-contract.json", contract_step)

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

    def test_go_prod_waits_for_exact_sec_dev_promotion_deploy(self) -> None:
        apply_step = self._apply_step()
        wait_block = apply_step.split("wait_for_sec_dev_release() {", 1)[1].split(
            "refresh_from_main_and_apply_update",
            1,
        )[0]

        self.assertIn('local deadline=$((SECONDS + 5400))', wait_block)
        self.assertIn('local sec_dev_branch="automation/cerebro-image-sec-dev-${safe_tag}"', wait_block)
        self.assertIn('--state merged', wait_block)
        self.assertIn('--head "${sec_dev_branch}"', wait_block)
        self.assertIn('--json mergeCommit,url', wait_block)
        self.assertIn('GH_TOKEN="${CHECKS_TOKEN}" gh pr list', wait_block)
        self.assertIn('GH_TOKEN="${CHECKS_TOKEN}" gh run list', wait_block)
        self.assertIn('select(.headSha == \\"${sec_dev_sha}\\")', wait_block)
        self.assertIn('sec-dev deploy for ${IMAGE_TAG} succeeded', wait_block)
        self.assertNotIn('git rev-parse origin/main', wait_block)
        self.assertNotIn('sec-dev is still on', wait_block)

    def test_pulumi_preview_jobs_have_timeout(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        for job_name in ("Preview sec-dev", "Preview go-prod", "Preview gcp-dev", "Preview gcp-prod"):
            with self.subTest(job_name=job_name):
                job_block = workflow.split(f"name: {job_name}", 1)[1].split("    steps:", 1)[0]
                self.assertIn("timeout-minutes: 20", job_block)

    def test_pulumi_preview_jobs_do_not_share_deploy_concurrency_groups(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        preview_jobs = (
            ("  deploy-sec-dev:", "infra-preview-sec-dev"),
            ("  preview-go-prod:", "infra-preview-go-prod"),
            ("  deploy-gcp-dev:", "infra-preview-gcp-dev"),
            ("  preview-gcp-prod:", "infra-preview-gcp-prod"),
        )
        for job_marker, group in preview_jobs:
            with self.subTest(job_marker=job_marker):
                job_block = workflow.split(job_marker, 1)[1].split("    steps:", 1)[0]
                self.assertIn(f"group: {group}", job_block)
                self.assertNotIn("group: infra-stack-", job_block)
                self.assertIn("cancel-in-progress: false", job_block)

        deploy_jobs = (
            ("  deploy-sec-dev-main:", "infra-stack-sec-dev"),
            ("  deploy-go-prod:", "infra-stack-go-prod"),
            ("  deploy-gcp-prod:", "infra-stack-gcp-prod"),
            ("  deploy-manual:", "infra-stack-${{ github.event.inputs.environment }}"),
        )
        for job_marker, group in deploy_jobs:
            with self.subTest(job_marker=job_marker):
                job_block = workflow.split(job_marker, 1)[1].split("    steps:", 1)[0]
                self.assertIn(f"group: {group}", job_block)

    def test_main_aws_deploy_jobs_have_timeout(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        for job_name in ("Deploy sec-dev", "Deploy go-prod"):
            with self.subTest(job_name=job_name):
                job_block = workflow.split(f"name: {job_name}", 1)[1].split("    steps:", 1)[0]
                self.assertIn("timeout-minutes: 75", job_block)

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

        manual_block = workflow.split("  deploy-manual:", 1)[1]
        self.assertIn("deployments: write", manual_block)
        self.assertIn("Create GitHub deployment record (manual)", manual_block)
        self.assertIn("Mark GitHub deployment in progress (manual)", manual_block)
        self.assertIn("Complete GitHub deployment record (manual)", manual_block)
        self.assertIn(".github/scripts/github-deployment-status.sh create", manual_block)
        self.assertIn(".github/scripts/github-deployment-status.sh status", manual_block)

    def test_aws_deploy_jobs_require_promotion_receipts_before_pulumi_up(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")

        self.assertNotIn("wait-for-ecr-image.sh", workflow)
        for job_marker, stack in (("  deploy-sec-dev-main:", "sec-dev"), ("  deploy-go-prod:", "go-prod")):
            with self.subTest(stack=stack):
                job_block = workflow.split(job_marker, 1)[1].split("\n  # ", 1)[0]
                self.assertIn(f"Ensure ECR promotion ({stack})", job_block)
                self.assertIn("scripts/ensure_ecr_promotion.py", job_block)
                self.assertIn("--dispatch-if-missing", job_block)
                self.assertIn(f"promotion-receipt-{stack}.json", job_block)
                self.assertLess(job_block.index(f"Ensure ECR promotion ({stack})"), job_block.index(f"Pulumi Up ({stack})"))

        manual_block = workflow.split("  deploy-manual:", 1)[1]
        self.assertIn("Ensure ECR promotion (AWS)", manual_block)
        self.assertIn("scripts/ensure_ecr_promotion.py", manual_block)
        self.assertIn("--dispatch-if-missing", manual_block)
        self.assertIn("promotion-receipt-${STACK_NAME}.json", manual_block)
        self.assertLess(manual_block.index("Ensure ECR promotion (AWS)"), manual_block.index("Pulumi Up (AWS)"))

    def test_github_deployment_status_describes_degraded_post_deploy_health(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")

        for job_marker, complete_step in (
            ("  deploy-sec-dev-main:", "Complete GitHub deployment record (sec-dev)"),
            ("  deploy-go-prod:", "Complete GitHub deployment record (go-prod)"),
            ("  deploy-manual:", "Complete GitHub deployment record (manual)"),
        ):
            with self.subTest(job_marker=job_marker):
                job_block = workflow.split(job_marker, 1)[1].split("\n  # ", 1)[0]
                complete_block = job_block.split(complete_step, 1)[1].split("\n      - name:", 1)[0]
                self.assertIn("GRAPH_HEALTH_DEGRADED", complete_block)
                self.assertIn("SOURCE_RUNTIME_DEGRADED", complete_block)
                self.assertIn("graph health degraded", complete_block)
                self.assertIn("source runtime degraded", complete_block)

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
        self.assertLess(deploy_block.index("Ensure ECR promotion (AWS)"), deploy_block.index("Pulumi Up (AWS)"))
        self.assertLess(deploy_block.index("Verify AWS scan-role trust (AWS)"), deploy_block.index("Pulumi Up (AWS)"))
        self.assertLess(deploy_block.index("Verify AWS secret imports (AWS)"), deploy_block.index("Pulumi Up (AWS)"))
        self.assertLess(deploy_block.index("Pulumi Up (AWS)"), deploy_block.index("Verify AWS Bedrock task role (AWS)"))
        self.assertNotIn("Verify Cosmo source canary (AWS)", deploy_block)

    def test_otel_runtime_config_validator_changes_are_static_only(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        filter_block = workflow.split("- name: Filter changed paths", 1)[1].split("\n      - name:", 1)[0]
        static_only_pattern = next(
            (
                match
                for match in re.finditer(r"grep -Ev '([^']+)' changed\.txt", filter_block)
                if "validate_otel_collector_config_runtime" in match.group(1)
            ),
            None,
        )

        self.assertIsNotNone(static_only_pattern)
        assert static_only_pattern is not None
        static_only_paths = re.compile(static_only_pattern.group(1))
        self.assertRegex("infra/scripts/validate_otel_collector_config_runtime.py", static_only_paths)
        self.assertRegex("infra/tests/test_validate_otel_collector_config_runtime.py", static_only_paths)
        self.assertRegex("infra/tests/test_propose_image_tag_workflow.py", static_only_paths)
        self.assertNotRegex("infra/scripts/provision_otel_collector_config.py", static_only_paths)


if __name__ == "__main__":
    unittest.main()
