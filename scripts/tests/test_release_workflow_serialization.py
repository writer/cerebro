from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
CUT_RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "cut-release.yml"
RUST_ONLY_CANDIDATE_WORKFLOW = (
    ROOT / ".github" / "workflows" / "rust-only-candidate.yml"
)
EPHEMERAL_CEREBRO_WORKFLOW = ROOT / ".github" / "workflows" / "ephemeral-cerebro.yml"
RUST_GRAPH_QUALIFICATION = ROOT / "scripts" / "qualify-rust-graph.sh"
SMOKE_RECEIPT_RENDERER = ROOT / "scripts" / "release" / "render_smoke_receipt.sh"
MINIMUM_CANDIDATE_CI_GATE_SECONDS = 90 * 60


class ReleaseWorkflowSerializationTest(unittest.TestCase):
    def test_release_publication_is_serialized_across_tags(self) -> None:
        workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("group: stable-release-publication", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertNotIn("group: release-${{ inputs.release_tag }}", workflow)

    def test_stable_release_verifies_and_publishes_smoke_evidence(self) -> None:
        workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("scripts/release/verify_smoke_receipt.sh", workflow)
        self.assertIn(
            'grep -Fq "${SMOKE_RECEIPT_URL}" release-notes.md',
            workflow,
        )
        self.assertIn("SMOKE_RECEIPT_ALLOWED_ORIGINS", workflow)
        self.assertIn("stable-release-smoke-evidence-", workflow)
        self.assertIn("-o -name 'smoke-evidence.json'", workflow)
        self.assertIn("${{ runner.temp }}/smoke-receipt.json.sig", workflow)
        self.assertIn("-o -name 'smoke-receipt.json*'", workflow)
        self.assertIn("CANDIDATE_RUNTIME_DIGEST", workflow)

    def test_portable_smoke_receipt_signing_is_isolated_from_pr_job(self) -> None:
        workflow = EPHEMERAL_CEREBRO_WORKFLOW.read_text(encoding="utf-8")
        topology = workflow.split("  topology:\n", 1)[1].split(
            "\n  sign-receipt:\n", 1
        )[0]
        signer = workflow.split("  sign-receipt:\n", 1)[1]
        qualification = RUST_GRAPH_QUALIFICATION.read_text(encoding="utf-8")
        renderer = SMOKE_RECEIPT_RENDERER.read_text(encoding="utf-8")

        self.assertNotIn("id-token: write", topology)
        self.assertIn("id-token: write", signer)
        self.assertIn(
            "github.event_name == 'workflow_dispatch' && inputs.image_source == 'published'",
            signer,
        )
        self.assertIn("signed-pr-rust-graph-", signer)
        self.assertIn("cosign sign-blob --yes", signer)
        self.assertIn("CANDIDATE_SHA: ${{ inputs.candidate_sha }}", signer)
        self.assertNotIn('"${{ inputs.candidate_sha }}"', signer)
        self.assertIn("scripts/release/render_smoke_receipt.sh", qualification)
        self.assertIn('"cerebro.smoke-receipt/v1"', renderer)
        self.assertIn("runtime_image_digest", renderer)

    def test_candidate_build_does_not_claim_stable_release_reservation(self) -> None:
        workflow = CUT_RELEASE_WORKFLOW.read_text(encoding="utf-8")

        concurrency = workflow.split("concurrency:\n", 1)[1].split("\njobs:\n", 1)[0]
        self.assertNotIn("group: stable-release-tag-reservation", concurrency)

    def test_candidate_attestations_are_queued_instead_of_cancelled(self) -> None:
        workflow = CUT_RELEASE_WORKFLOW.read_text(encoding="utf-8")

        concurrency = workflow.split("concurrency:\n", 1)[1].split("\njobs:\n", 1)[0]
        self.assertIn("group: candidate-build-main", concurrency)
        self.assertIn("cancel-in-progress: false", concurrency)
        self.assertNotIn("cancel-in-progress: true", concurrency)

    def test_candidate_ci_gate_covers_a_queued_full_ci_run(self) -> None:
        workflow = CUT_RELEASE_WORKFLOW.read_text(encoding="utf-8")
        ci_gate = workflow.split("  ci-gate:\n", 1)[1].split("\n  binary:\n", 1)[0]

        budget = re.search(r'CI_GATE_DEADLINE_SECONDS: "(\d+)"', ci_gate)
        self.assertIsNotNone(budget, "ci-gate must declare a named deadline budget")
        self.assertGreaterEqual(
            int(budget.group(1)),
            MINIMUM_CANDIDATE_CI_GATE_SECONDS,
        )
        self.assertIn(
            "deadline=$((SECONDS + CI_GATE_DEADLINE_SECONDS))",
            ci_gate,
        )
        self.assertNotIn("deadline=$((SECONDS + 1800))", ci_gate)
        self.assertIn("needs: resolve", ci_gate)
        self.assertIn("Require successful CI for candidate commit", ci_gate)

    def test_candidate_web_images_use_native_architecture_runners(self) -> None:
        workflow = CUT_RELEASE_WORKFLOW.read_text(encoding="utf-8")
        web_image = workflow.split("  web-image:\n", 1)[1].split(
            "\n  web-manifest:", 1
        )[0]

        self.assertIn("runs-on: ${{ matrix.runner }}", web_image)
        self.assertIn("timeout-minutes: 30", web_image)
        self.assertIn("runner: ubuntu-24.04", web_image)
        self.assertIn("runner: ubuntu-24.04-arm", web_image)
        self.assertNotIn("docker/setup-qemu-action", web_image)

    def test_candidate_image_attestations_can_index_artifact_metadata(self) -> None:
        workflow = CUT_RELEASE_WORKFLOW.read_text(encoding="utf-8")
        manifest = workflow.split("  manifest:\n", 1)[1].split(
            "\n  rust-organizational-e2e:", 1
        )[0]
        web_manifest = workflow.split("  web-manifest:\n", 1)[1].split(
            "\n  scan-images:", 1
        )[0]

        for job in (manifest, web_manifest):
            self.assertIn("artifact-metadata: write", job)

    def test_rust_only_candidate_attestation_can_index_artifact_metadata(self) -> None:
        workflow = RUST_ONLY_CANDIDATE_WORKFLOW.read_text(encoding="utf-8")
        manifest = workflow.split("  manifest:\n", 1)[1].split("\n  e2e:", 1)[0]

        self.assertIn("artifact-metadata: write", manifest)


if __name__ == "__main__":
    unittest.main()
