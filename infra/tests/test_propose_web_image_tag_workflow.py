from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "propose-web-image-tag.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
INFRA_DEPLOY_WORKFLOW = ROOT / ".github" / "workflows" / "infra-deploy.yml"
VERIFY_SCRIPT = ROOT / ".github" / "scripts" / "verify-ghcr-image.sh"
DEPLOY_APP_ACTION = ROOT / ".github" / "actions" / "deploy-app-token" / "action.yml"


class ProposeWebImageTagWorkflowTest(unittest.TestCase):
    def test_public_web_image_is_the_trusted_source(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("WEB_GHCR_IMAGE: ghcr.io/writer/cerebro-web", workflow)
        self.assertIn('DISPATCH_SOURCE_REPOSITORY}" != "writer/cerebro-web"', workflow)
        self.assertIn('DISPATCH_WEB_IMAGE}" != "${WEB_GHCR_IMAGE}"', workflow)
        self.assertIn('DISPATCH_SOURCE_REF}" =~ ^[0-9a-f]{40}$', workflow)
        self.assertIn('Repository dispatch must include web_image_digest', workflow)
        self.assertIn('"sha-${DISPATCH_SOURCE_REF:0:12}"', workflow)
        self.assertIn("steps.resolved.outputs.expected_digest", workflow)

    def test_web_image_signature_uses_public_release_workflow_identity(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        verify_block = workflow.split("bash .github/scripts/verify-ghcr-image.sh \\", 1)[1].split(
            "\n\n      - name:",
            1,
        )[0]

        self.assertIn("bash .github/scripts/install-cosign.sh", workflow)
        self.assertIn(
            r"^https://github\.com/writer/cerebro-web/\.github/workflows/release\.yml@refs/heads/main$",
            verify_block,
        )
        self.assertIn('"signature-only"', verify_block)
        self.assertNotIn('"true"', verify_block)

    def test_web_image_attestations_use_buildx_index_metadata(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        attest_block = workflow.split("- name: Verify web GHCR build attestations", 1)[1].split(
            "\n\n      - name:",
            1,
        )[0]

        self.assertIn('IMAGE_DIGEST: ${{ steps.verify.outputs.digest }}', attest_block)
        self.assertIn('docker buildx imagetools inspect "${WEB_GHCR_IMAGE}@${IMAGE_DIGEST}" --raw', attest_block)
        self.assertIn('annotations["vnd.docker.reference.type"] == "attestation-manifest"', attest_block)

    def test_trusted_sec_dev_release_uses_pr_auto_merge_not_main_push(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("apply_mode=direct_push is deprecated", workflow)
        self.assertIn('mode="trusted_sec_dev_release"', workflow)
        self.assertIn("auto_merge_trusted_sec_dev_pr", workflow)
        self.assertIn("Trusted release promotion:", workflow)
        self.assertIn('gh pr merge "${pr_url}" --merge --delete-branch', workflow)
        self.assertNotIn('"HEAD:main"', workflow)
        self.assertNotIn("dispatch_and_require_run", workflow)

    def test_release_automation_requires_deploy_app_token(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        action = DEPLOY_APP_ACTION.read_text(encoding="utf-8")

        self.assertIn("- name: Resolve release automation auth", workflow)
        self.assertIn("actions: write", workflow)
        self.assertIn("contents: write", workflow)
        self.assertIn("pull-requests: write", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertNotIn("CEREBRO_AUTORELEASE_TOKEN", workflow)
        self.assertIn("mode=deploy_app", workflow)
        self.assertNotIn("mode=autorelease_token", workflow)
        self.assertNotIn("falling back", workflow)
        self.assertIn("- name: Create deploy GitHub App token", workflow)
        self.assertNotIn("if: steps.release-auth.outputs.mode == 'deploy_app'", workflow)
        self.assertIn("uses: ./.github/actions/deploy-app-token", workflow)
        self.assertIn("client-id: ${{ vars.CEREBRO_DEPLOY_APP_CLIENT_ID }}", workflow)
        self.assertIn("private-key: ${{ secrets.CEREBRO_DEPLOY_APP_PRIVATE_KEY }}", workflow)
        self.assertIn("GH_TOKEN: ${{ steps.deploy-app-token.outputs.token }}", workflow)
        self.assertNotIn("DEPLOY_AUTH_MODE", workflow)
        self.assertIn('git config user.name "${DEPLOY_APP_SLUG}[bot]"', workflow)
        self.assertNotIn('git config user.name "github-actions[bot]"', workflow)
        self.assertIn('git remote set-url origin "https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}.git"', workflow)
        self.assertIn('git fetch origin "${branch}:refs/remotes/origin/${branch}" || true', workflow)
        self.assertIn('git push --force-with-lease origin "HEAD:${branch}"', workflow)
        self.assertNotIn('git push --force-with-lease "https://x-access-token:${GH_TOKEN}', workflow)
        self.assertIn("password: ${{ secrets.GITHUB_TOKEN }}", workflow)
        self.assertIn("actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1", action)
        self.assertIn("Preflight deploy GitHub App token", action)
        self.assertIn("gh api /installation/repositories", action)
        self.assertIn("Deploy App token is scoped to ${GITHUB_REPOSITORY}.", action)
        self.assertIn("permission-contents: write", action)
        self.assertIn("permission-pull-requests: write", action)
        self.assertNotIn("permission-checks: read", action)
        self.assertNotIn("check_permission", action)
        self.assertNotIn("permission-actions: write", action)

    def test_ci_mirrors_public_web_image(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("WEB_GHCR_IMAGE: ghcr.io/writer/cerebro-web", workflow)
        self.assertIn(
            r"^https://github\.com/writer/cerebro-web/\.github/workflows/release\.yml@refs/heads/main$",
            workflow,
        )
        self.assertIn('"signature-only"', workflow)
        self.assertIn('IMAGE_DIGEST: ${{ steps.verify-web-ghcr-image.outputs.digest }}', workflow)
        self.assertIn('docker buildx imagetools inspect "${WEB_GHCR_IMAGE}@${IMAGE_DIGEST}" --raw', workflow)

    def test_ghcr_verifier_supports_signature_only_mode(self) -> None:
        script = VERIFY_SCRIPT.read_text(encoding="utf-8")

        self.assertIn("attestation_mode=", script)
        self.assertIn("signature-only)", script)
        self.assertIn("Unknown attestation mode", script)

    def test_workflow_contract_test_changes_do_not_trigger_deploys(self) -> None:
        workflow = INFRA_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        filter_block = workflow.split("- name: Filter changed paths", 1)[1].split("\n      - name:", 1)[0]
        static_only_pattern = next(
            (
                match
                for match in re.finditer(r"grep -Ev '([^']+)' changed\.txt", filter_block)
                if "propose_" in match.group(1)
            ),
            None,
        )

        self.assertIsNotNone(static_only_pattern)
        assert static_only_pattern is not None
        static_only_paths = re.compile(static_only_pattern.group(1))
        self.assertRegex("infra/tests/test_propose_web_image_tag_workflow.py", static_only_paths)


if __name__ == "__main__":
    unittest.main()
