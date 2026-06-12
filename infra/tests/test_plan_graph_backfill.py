import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.plan_graph_backfill import _missing_runtime_ids_from_diagnostics, _verify_command, plan_backfill


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


if __name__ == "__main__":
    unittest.main()
