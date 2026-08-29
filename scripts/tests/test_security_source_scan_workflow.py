from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCAN_WORKFLOW = ROOT / ".github" / "workflows" / "security-source-scan.yml"


def _gosec_shard_step() -> str:
    workflow = SCAN_WORKFLOW.read_text(encoding="utf-8")
    step = workflow.split("      - name: Run gosec shard (JSON report)\n", 1)[1]
    return step.split("      - name: Fail on HIGH findings\n", 1)[0]


class SecuritySourceScanWorkflowTest(unittest.TestCase):
    def test_gosec_scans_each_shard_in_bounded_batches(self) -> None:
        step = _gosec_shard_step()

        # One gosec process over a whole shard grows until the hosted runner is
        # killed mid-scan (exit 143), so the shard is scanned in fixed batches.
        self.assertIn("GOSEC_BATCH_SIZE:", step)
        self.assertIn("start += GOSEC_BATCH_SIZE", step)
        self.assertIn('batch=("${selected[@]:start:GOSEC_BATCH_SIZE}")', step)
        self.assertIn('-out "${batch_report}" "${batch[@]}"', step)

        # The whole shard must never be handed to gosec in one invocation again.
        self.assertNotIn('-out "${report_path}" "${selected[@]}"', step)

    def test_unscanned_batch_fails_instead_of_reporting_clean(self) -> None:
        step = _gosec_shard_step()

        # gosec exits non-zero merely for having findings, so a missing report is
        # the only reliable signal that a batch did not actually run.
        self.assertIn('if [ ! -s "${batch_report}" ]; then', step)
        self.assertIn("went unscanned", step)
        self.assertIn("exit 1", step)

    def test_batch_reports_are_merged_into_the_shard_report(self) -> None:
        step = _gosec_shard_step()

        self.assertIn('python3 - "${report_path}" gosec-batches/*.json', step)
        self.assertIn('issues.extend(json.load(handle).get("Issues") or [])', step)

    def test_shard_maths_reads_env_not_interpolated_matrix_context(self) -> None:
        step = _gosec_shard_step()

        self.assertIn("SHARD_INDEX: ${{ matrix.shard_index }}", step)
        self.assertIn("SHARD_TOTAL: ${{ matrix.shard_total }}", step)
        self.assertIn("if (( i % SHARD_TOTAL == SHARD_INDEX )); then", step)

        script = step.split("        run: |\n", 1)[1]
        self.assertNotIn("${{", script)

    def test_high_findings_still_fail_the_scan(self) -> None:
        workflow = SCAN_WORKFLOW.read_text(encoding="utf-8")
        gate = workflow.split("      - name: Fail on HIGH findings\n", 1)[1]
        gate = gate.split("      - name: Upload gosec report artifact\n", 1)[0]

        self.assertIn("SHARD_INDEX: ${{ matrix.shard_index }}", gate)
        self.assertIn("str(i.get('severity', '')).upper() == 'HIGH'", gate)
        self.assertIn("sys.exit(1)", gate)
        self.assertNotIn("${{", gate.split("        run: |\n", 1)[1])


if __name__ == "__main__":
    unittest.main()
