from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "candidate-runtime-smoke.yml"


class CandidateRuntimeSmokeWorkflowTest(unittest.TestCase):
    def test_uses_github_attestation_verifier(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertIn("attestations: read", workflow)
        self.assertIn("GH_TOKEN: ${{ github.token }}", workflow)
        self.assertIn(
            'gh attestation verify "oci://${source_image}" --repo writer/cerebro',
            workflow,
        )
        self.assertNotIn("cosign tree", workflow)


if __name__ == "__main__":
    unittest.main()
