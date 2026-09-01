from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
AUTO_WORKFLOW = ROOT / ".github" / "workflows" / "auto-stable-release.yml"
CANDIDATE_WORKFLOW = ROOT / ".github" / "workflows" / "cut-release.yml"
RUST_GRAPH_WORKFLOW = ROOT / ".github" / "workflows" / "rust-graph-replacement.yml"
EPHEMERAL_WORKFLOW = ROOT / ".github" / "workflows" / "ephemeral-cerebro.yml"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


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

    def test_superseded_candidate_is_skipped_rather_than_failed(self) -> None:
        workflow = AUTO_WORKFLOW.read_text(encoding="utf-8")
        proof = workflow.split("      - name: Require exact-head main proofs\n", 1)[1]
        proof = proof.split(
            "      - name: Resolve or dispatch published-image smoke\n", 1
        )[0]

        # A candidate that main has already moved past cannot publish, so the
        # orchestrator records it and exits clean instead of reddening main.
        self.assertIn("id: proofs", proof)
        self.assertIn('echo "superseded=true" >> "${GITHUB_OUTPUT}"', proof)
        self.assertNotIn("ERROR: main advanced", proof)

        # Supersession is checked before any qualification work is started.
        self.assertLess(
            proof.index("mark_superseded"),
            proof.index('if [[ "${graph_runs}" == 0 ]]'),
        )

    def test_cancelled_proof_only_counts_as_superseded_when_main_moved(self) -> None:
        workflow = AUTO_WORKFLOW.read_text(encoding="utf-8")
        proof = workflow.split("      - name: Require exact-head main proofs\n", 1)[1]
        proof = proof.split(
            "      - name: Resolve or dispatch published-image smoke\n", 1
        )[0]
        terminal = proof.split('if [[ "${status}" == completed ]]; then', 1)[1]

        # Rust Graph Replacement is keyed on github.ref with cancel-in-progress,
        # so a newer candidate's dispatch cancels this one's proof run.
        self.assertIn('if [[ "${conclusion}" == cancelled ]]', terminal)
        self.assertLess(
            terminal.index('if [[ "${conclusion}" == cancelled ]]'),
            terminal.index("ERROR: ${workflow} completed with"),
        )

        # Any other terminal conclusion, and a cancellation on unmoved main,
        # still fail closed.
        self.assertIn("ERROR: ${workflow} completed with ${conclusion}", terminal)
        self.assertIn("exit 1", terminal)

    def test_publication_steps_are_gated_on_a_live_candidate(self) -> None:
        workflow = AUTO_WORKFLOW.read_text(encoding="utf-8")
        gate = "steps.proofs.outputs.superseded != 'true'"

        for step in (
            "      - name: Resolve or dispatch published-image smoke\n",
            "      - name: Reserve next stable tag and render notes\n",
            "      - name: Dispatch stable publication\n",
        ):
            guard = workflow.split(step, 1)[1].split("\n", 2)[0]
            self.assertIn("steps.candidate.outputs.eligible == 'true'", guard, step)
            self.assertIn(gate, guard, step)

    def test_smoke_runs_are_matched_by_run_name_not_head_sha(self) -> None:
        workflow = AUTO_WORKFLOW.read_text(encoding="utf-8")
        smoke = workflow.split(
            "      - name: Resolve or dispatch published-image smoke\n", 1
        )[1]
        smoke = smoke.split(
            "      - name: Reserve next stable tag and render notes\n", 1
        )[0]

        # Ephemeral Cerebro is dispatched with --ref main, so its headSha is
        # whatever main was at dispatch time, not the candidate input. Matching
        # on headSha loses the run whenever main advances between the candidate
        # build and the release run.
        self.assertNotIn(".headSha ==", smoke)
        self.assertNotIn(",headSha,", smoke)
        self.assertIn('smoke_title="${CANDIDATE_SHA} (published)"', smoke)
        self.assertEqual(smoke.count("--workflow \"Ephemeral Cerebro\""), 2)
        self.assertEqual(smoke.count("--json databaseId,displayTitle,"), 2)
        self.assertEqual(
            smoke.count('.displayTitle | contains(\\"${smoke_title}\\")'), 2
        )
        self.assertIn("--event workflow_dispatch --branch main", smoke)
        self.assertIn('.createdAt >= \\"${requested_at}\\"', smoke)

        # The run name the orchestrator matches on is the one Ephemeral Cerebro
        # actually renders for a published-image dispatch.
        ephemeral = EPHEMERAL_WORKFLOW.read_text(encoding="utf-8")
        run_name = [
            line for line in ephemeral.splitlines() if line.startswith("run-name:")
        ]
        self.assertEqual(len(run_name), 1)
        self.assertIn("${{ inputs.candidate_sha ||", run_name[0])
        self.assertIn("github.event.pull_request.head.sha", run_name[0])
        self.assertIn("(${{ inputs.image_source || 'source' }})", run_name[0])

    def test_publication_runs_are_matched_by_run_name_not_head_sha(self) -> None:
        workflow = AUTO_WORKFLOW.read_text(encoding="utf-8")
        publication = workflow.split(
            "      - name: Dispatch stable publication\n", 1
        )[1]

        # Stable Release is dispatched with --ref main too, so the same headSha
        # mismatch applies whenever main moves in the gap after the final
        # current-main check. release.yml has no candidate_sha input, so the
        # match keys on the reserved tag and candidate run this step passes.
        self.assertNotIn(".headSha ==", publication)
        self.assertNotIn(",headSha,", publication)
        self.assertIn(
            'publication_title="${RELEASE_TAG} (candidate run ${CANDIDATE_RUN_ID})"',
            publication,
        )
        self.assertIn("--workflow \"Stable Release\"", publication)
        self.assertIn("--json databaseId,displayTitle,", publication)
        self.assertIn(
            '.displayTitle | contains(\\"${publication_title}\\")', publication
        )
        self.assertIn("--event workflow_dispatch --branch main", publication)
        self.assertIn('.createdAt >= \\"${requested_at}\\"', publication)

        release = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        run_name = [
            line for line in release.splitlines() if line.startswith("run-name:")
        ]
        self.assertEqual(len(run_name), 1)
        self.assertIn("${{ inputs.release_tag ||", run_name[0])
        self.assertIn(
            "(candidate run ${{ inputs.candidate_run_id ||", run_name[0]
        )

    def test_rust_graph_proof_has_a_cold_build_budget(self) -> None:
        workflow = RUST_GRAPH_WORKFLOW.read_text(encoding="utf-8")
        replacement = workflow.split("  replacement:\n", 1)[1]

        self.assertIn("timeout-minutes: 30", replacement)


if __name__ == "__main__":
    unittest.main()
