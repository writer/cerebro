from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "propose-web-image-tag.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
INFRA_DEPLOY_WORKFLOW = ROOT / ".github" / "workflows" / "infra-deploy.yml"
VERIFY_SCRIPT = ROOT / ".github" / "scripts" / "verify-ghcr-image.sh"


class ProposeWebImageTagWorkflowTest(unittest.TestCase):
    def test_public_web_image_is_the_trusted_source(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("WEB_GHCR_IMAGE: ghcr.io/writer/cerebro-web", workflow)
        self.assertIn('DISPATCH_SOURCE_REPOSITORY}" != "writer/cerebro-web"', workflow)
        self.assertIn('DISPATCH_WEB_IMAGE}" != "${WEB_GHCR_IMAGE}"', workflow)
        self.assertIn('DISPATCH_SOURCE_REF}" =~ ^[0-9a-f]{40}$', workflow)
        self.assertIn('Repository dispatch must include web_image_digest', workflow)
        self.assertIn('"sha-${DISPATCH_SOURCE_REF:0:12}"', workflow)
        self.assertIn("steps.inputs.outputs.expected_digest", workflow)

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

    def test_direct_push_matches_backend_sec_dev_promotion_shape(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        direct_push_block = workflow.split('if [ "${APPLY_MODE}" = "direct_push" ]; then', 1)[1].split(
            'if [ "${APPLY_MODE}" != "pull_request" ]; then',
            1,
        )[0]

        self.assertIn('STACK_NAME}" != "sec-dev"', direct_push_block)
        self.assertIn('EVENT_NAME}" != "repository_dispatch"', direct_push_block)
        self.assertIn("CEREBRO_AUTORELEASE_TOKEN is required for direct_push", direct_push_block)
        self.assertIn('"HEAD:main"', direct_push_block)
        self.assertIn("dispatch_and_require_run ci.yml", direct_push_block)
        self.assertIn("dispatch_and_require_run infra-deploy.yml -f environment=", direct_push_block)
        self.assertIn('conclusion}" != "success"', workflow)
        self.assertIn("completed successfully", workflow)

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

        self.assertIn("propose_web_image_tag_workflow", workflow)


if __name__ == "__main__":
    unittest.main()
