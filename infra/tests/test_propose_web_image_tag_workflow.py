from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "propose-web-image-tag.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


class ProposeWebImageTagWorkflowTest(unittest.TestCase):
    def test_public_web_image_is_the_trusted_source(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("WEB_GHCR_IMAGE: ghcr.io/writer/cerebro-web", workflow)
        self.assertIn('DISPATCH_SOURCE_REPOSITORY}" != "writer/cerebro-web"', workflow)
        self.assertIn('DISPATCH_WEB_IMAGE}" != "${WEB_GHCR_IMAGE}"', workflow)
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

    def test_ci_mirrors_public_web_image(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("WEB_GHCR_IMAGE: ghcr.io/writer/cerebro-web", workflow)
        self.assertIn(
            r"^https://github\.com/writer/cerebro-web/\.github/workflows/release\.yml@refs/heads/main$",
            workflow,
        )
        self.assertIn('IMAGE_DIGEST: ${{ steps.verify-web-ghcr-image.outputs.digest }}', workflow)
        self.assertIn('docker buildx imagetools inspect "${WEB_GHCR_IMAGE}@${IMAGE_DIGEST}" --raw', workflow)


if __name__ == "__main__":
    unittest.main()
