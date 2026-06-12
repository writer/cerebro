import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.reconcile_orchestrator_schedules import reconcile_schedules


class ReconcileOrchestratorSchedulesTest(unittest.TestCase):
    def test_reconcile_reports_missing_and_orphan_schedules(self) -> None:
        config = {
            "sourceRuntimes": [
                {"id": "runtime-a", "sourceId": "aws", "config": {"family": "s3_bucket"}},
                {"id": "runtime-b", "sourceId": "aws", "config": {"family": "kms_key"}},
            ],
            "orchestratorSchedules": [
                {"name": "a", "scheduleExpression": "rate(6 hours)", "command": ["orchestrator", "run", "runtime_id=runtime-a"]},
                {"name": "orphan", "scheduleExpression": "rate(6 hours)", "command": ["orchestrator", "run", "runtime_id=runtime-z"]},
            ],
        }

        rows = reconcile_schedules(config)
        states = {row.runtime_id: row.state for row in rows}

        self.assertEqual(states["runtime-a"], "ok")
        self.assertEqual(states["runtime-b"], "missing_schedule")
        self.assertEqual(states["runtime-z"], "orphan_schedule")

    def test_reconcile_filters_by_source(self) -> None:
        config = {
            "sourceRuntimes": [
                {"id": "runtime-a", "sourceId": "aws", "config": {"family": "s3_bucket"}},
                {"id": "runtime-b", "sourceId": "gcp", "config": {"family": "gcs_bucket"}},
            ],
            "orchestratorSchedules": [],
        }

        rows = reconcile_schedules(config, source_id="gcp")

        self.assertEqual([row.runtime_id for row in rows], ["runtime-b"])


if __name__ == "__main__":
    unittest.main()
