import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.plan_graph_backfill import BackfillTarget, _missing_runtime_ids_from_diagnostics, _verify_command, _write_commands, plan_backfill


class PlanGraphBackfillTest(unittest.TestCase):
    def test_plan_backfill_classifies_declared_scheduled_runtime(self) -> None:
        config = {
            "sourceRuntimes": [
                {"id": "runtime-a", "sourceId": "gcp", "config": {"family": "asset_metadata"}},
            ],
            "orchestratorSchedules": [
                {
                    "name": "runtime-a-schedule",
                    "scheduleExpression": "rate(6 hours)",
                    "command": ["orchestrator", "run", "runtime_id=runtime-a"],
                }
            ],
        }

        targets = plan_backfill(config, ["runtime-a", "runtime-missing"])

        self.assertEqual(targets[0].state, "backfillable")
        self.assertEqual(targets[0].source_id, "gcp")
        self.assertEqual(targets[1].state, "not_declared")

    def test_extract_missing_runtime_ids_from_diagnostics(self) -> None:
        diagnostics = "ERROR: missing graph ingest run history for 2 declared runtime(s): runtime-a, runtime-b; latest graph ingest run failed"

        self.assertEqual(_missing_runtime_ids_from_diagnostics(diagnostics), ["runtime-a", "runtime-b"])

    def test_verify_command_groups_runtime_ids(self) -> None:
        args = SimpleNamespace(
            stack_file=Path("aws/Pulumi.sec-dev.yaml"),
            target_concurrency=4,
            mode="run",
            run_page_limit=10,
            run_graph_page_limit=20,
            run_event_limit=30,
            stop_running_before_run=True,
        )

        command = _verify_command(args, "gcp", ["runtime-a", "runtime-b"])

        self.assertIn("--run", command)
        self.assertIn("--succeed-after-graph-ingest", command)
        self.assertEqual(command.count("--runtime-id"), 2)

    def test_write_commands_runs_all_commands_and_preserves_failure(self) -> None:
        args = SimpleNamespace(
            stack_file=Path("aws/Pulumi.sec-dev.yaml"),
            target_concurrency=4,
            mode="run",
            run_page_limit=0,
            run_graph_page_limit=0,
            run_event_limit=0,
            stop_running_before_run=False,
        )
        targets = [
            BackfillTarget("runtime-a", "gcp", "asset_metadata", "", "", "backfillable", ""),
            BackfillTarget("runtime-b", "gcp", "asset_metadata", "", "", "backfillable", ""),
            BackfillTarget("runtime-c", "okta", "audit", "", "", "manual_backfill", ""),
        ]

        output = StringIO()
        with redirect_stdout(output):
            _write_commands(args, targets)

        script = output.getvalue()
        self.assertIn("set -uo pipefail", script)
        self.assertIn("status=0", script)
        self.assertEqual(script.count(" || status=$?"), 2)
        self.assertTrue(script.rstrip().endswith('exit "${status}"'))

    def test_write_commands_splits_runtime_ids_when_concurrency_is_one(self) -> None:
        args = SimpleNamespace(
            stack_file=Path("aws/Pulumi.sec-dev.yaml"),
            target_concurrency=1,
            mode="dry-run",
            run_page_limit=0,
            run_graph_page_limit=0,
            run_event_limit=0,
            stop_running_before_run=False,
        )
        targets = [
            BackfillTarget("runtime-a", "gcp", "asset_metadata", "", "", "backfillable", ""),
            BackfillTarget("runtime-b", "gcp", "asset_metadata", "", "", "backfillable", ""),
        ]

        output = StringIO()
        with redirect_stdout(output):
            _write_commands(args, targets)

        command_lines = [line for line in output.getvalue().splitlines() if line.startswith("uv run")]
        self.assertEqual(len(command_lines), 2)
        self.assertIn("--runtime-id runtime-a", command_lines[0])
        self.assertNotIn("--runtime-id runtime-b", command_lines[0])
        self.assertIn("--runtime-id runtime-b", command_lines[1])


if __name__ == "__main__":
    unittest.main()
