from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
AUTO_WORKFLOW = ROOT / ".github" / "workflows" / "auto-stable-release.yml"
CANDIDATE_WORKFLOW = ROOT / ".github" / "workflows" / "cut-release.yml"


class AutoStableReleaseWorkflowTest(unittest.TestCase):
    def test_candidate_dispatches_input_bound_orchestrator_after_receipt(self) -> None:
        workflow = CANDIDATE_WORKFLOW.read_text(encoding="utf-8")
        job = workflow.split("  dispatch-automatic-stable-release:\n", 1)[1]

        self.assertIn("if: github.event_name == 'push'", job)
        self.assertIn("needs: [resolve, receipt]", job)
        self.assertIn("actions: write", job)
        self.assertIn("gh workflow run auto-stable-release.yml", job)
        self.assertIn('-f candidate_run_id="${CANDIDATE_RUN_ID}"', job)
        self.assertIn('-f candidate_sha="${CANDIDATE_SHA}"', job)

    def test_orchestrator_uses_manual_inputs_not_workflow_run(self) -> None:
        workflow = AUTO_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("workflow_run:", workflow)
        self.assertIn("CANDIDATE_RUN_ID: ${{ inputs.candidate_run_id }}", workflow)
        self.assertIn("CANDIDATE_SHA: ${{ inputs.candidate_sha }}", workflow)
        self.assertIn(".github/workflows/cut-release.yml", workflow)
        self.assertIn('test "$(jq -r .event <<< "${candidate_run}")" = push', workflow)
        self.assertIn(
            'test "$(jq -r .head_branch <<< "${candidate_run}")" = main', workflow
        )
        self.assertIn("cerebro-candidate-${CANDIDATE_SHA}", workflow)

    def test_orchestrator_fails_closed_on_stale_or_incomplete_evidence(self) -> None:
        workflow = AUTO_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("is superseded by main", workflow)
        self.assertIn("Main advanced to", workflow)
        self.assertIn("rust-only-candidate.yml", workflow)
        self.assertIn("signed-pr-rust-graph-${CANDIDATE_SHA}", workflow)
        self.assertIn("scripts/release/validate_release_notes.sh", workflow)
        self.assertIn("-f require_current_main=true", workflow)
        self.assertIn('test "$(gh api', workflow)

    def test_orchestrator_dispatches_missing_rust_graph_proof_once(self) -> None:
        workflow = AUTO_WORKFLOW.read_text(encoding="utf-8")
        proof = workflow.split("      - name: Require exact-head main proofs\n", 1)[1]
        proof = proof.split(
            "      - name: Resolve or dispatch published-image smoke\n", 1
        )[0]

        self.assertIn('if [[ "${graph_runs}" == 0 ]]', proof)
        self.assertIn("gh workflow run rust-graph-replacement.yml", proof)
        self.assertNotIn("|| echo 0", proof)
        self.assertIn("--ref main", proof)
        self.assertIn('if [[ "${current_main}" != "${CANDIDATE_SHA}" ]]', proof)
        self.assertLess(
            proof.index('if [[ "${graph_runs}" == 0 ]]'),
            proof.index("gh workflow run rust-graph-replacement.yml"),
        )


if __name__ == "__main__":
    unittest.main()
