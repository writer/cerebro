import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "web-release.yml"
DOCKERFILE = ROOT / "apps" / "web" / "Dockerfile"


class WebReleaseWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.dockerfile = DOCKERFILE.read_text(encoding="utf-8")

    def test_validates_the_owned_web_workspace(self) -> None:
        self.assertIn("npm run check --workspace @writer/cerebro-web", self.workflow)
        self.assertIn("npm run build --workspace @writer/cerebro-web", self.workflow)
        self.assertIn("npm run smoke:standalone --workspace @writer/cerebro-web -- --skip-build", self.workflow)
        self.assertIn("npm audit --omit=dev --audit-level=moderate", self.workflow)
        self.assertIn("make oss-audit", self.workflow)
        self.assertIn('./scripts/leak_check.sh range "${range}"', self.workflow)

    def test_preserves_the_public_image_identity_and_immutable_main_tag(self) -> None:
        self.assertIn("WEB_IMAGE: ghcr.io/writer/cerebro-web", self.workflow)
        self.assertIn('tag="sha-${short_sha}"', self.workflow)
        self.assertIn('echo "${WEB_IMAGE}:latest"', self.workflow)
        self.assertNotIn("ghcr.io/${GITHUB_REPOSITORY", self.workflow)

    def test_builds_the_monorepo_dockerfile_for_both_platforms(self) -> None:
        self.assertIn("context: .", self.workflow)
        self.assertIn("file: apps/web/Dockerfile", self.workflow)
        self.assertIn("platform: linux/amd64", self.workflow)
        self.assertIn("platform: linux/arm64", self.workflow)
        self.assertIn("SOURCE_REVISION=${{ github.sha }}", self.workflow)
        self.assertIn('LABEL org.opencontainers.image.source="https://github.com/writer/cerebro"', self.dockerfile)

    def test_release_triggers_cover_every_workspace_manifest_in_the_image_context(self) -> None:
        self.assertEqual(self.workflow.count('- "apps/web/**"'), 2)
        for manifest in (
            "apps/slack-companion/package.json",
            "sdk/typescript/package.json",
            "package.json",
            "package-lock.json",
        ):
            with self.subTest(manifest=manifest):
                self.assertEqual(self.workflow.count(f'- "{manifest}"'), 2)

    def test_attaches_sbom_and_provenance_to_immutable_digests(self) -> None:
        self.assertIn("provenance: mode=max", self.workflow)
        self.assertIn("sbom: true", self.workflow)
        self.assertIn("push-by-digest=true", self.workflow)
        self.assertIn("actions/attest-build-provenance@", self.workflow)
        self.assertIn("subject-digest: ${{ steps.manifest.outputs.digest }}", self.workflow)
        self.assertRegex(
            self.workflow,
            r'aquasec/trivy:[^\s"]+@sha256:[0-9a-f]{64}',
        )
        self.assertIn('cosign sign --yes "${IMAGE}@${DIGEST}"', self.workflow)

    def test_every_action_is_pinned_to_a_commit(self) -> None:
        actions = re.findall(r"^\s*-?\s*uses:\s*([^\s]+)", self.workflow, flags=re.MULTILINE)
        self.assertGreater(len(actions), 0)
        for action in actions:
            with self.subTest(action=action):
                self.assertRegex(action, r"@[0-9a-f]{40}$")

    def test_workflow_uses_narrow_permissions(self) -> None:
        self.assertNotIn("contents: write", self.workflow)
        self.assertNotIn("actions: write", self.workflow)
        self.assertNotIn("pull-requests: write", self.workflow)
        self.assertEqual(self.workflow.count("packages: write"), 2)
        self.assertEqual(self.workflow.count("attestations: write"), 1)
        self.assertEqual(self.workflow.count("timeout-minutes:"), 4)

    def test_release_consumer_contract_is_topology_neutral(self) -> None:
        self.assertIn("RELEASE_CONSUMER_TOKEN", self.workflow)
        self.assertIn("RELEASE_CONSUMER_REPOSITORY", self.workflow)
        self.assertIn('event_type: "application-release-published"', self.workflow)
        payload = re.search(
            r"client_payload:\s*\{(?P<body>.*?)^\s*\}",
            self.workflow,
            flags=re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(payload)
        fields = re.findall(r"^\s+([a-z_]+):", payload.group("body"), flags=re.MULTILINE)
        self.assertEqual(
            fields,
            ["schema_version", "application_id", "image", "tag", "digest", "source_commit"],
        )
        for deployment_detail in (
            "target_environment",
            "apply_mode",
            "wait_for_promotion",
            "promotion_run_id",
            "gh run view",
            "contents/.github/workflows",
        ):
            with self.subTest(deployment_detail=deployment_detail):
                self.assertNotIn(deployment_detail, self.workflow)


if __name__ == "__main__":
    unittest.main()
