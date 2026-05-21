from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.verify_source_runtime_ecs import RuntimeTarget, _declared_runtime_ids, _runtime_id_from_command, _schedule_suffix, _task_family, _verify_task


class VerifySourceRuntimeEcsTest(unittest.TestCase):
    def test_declared_runtime_ids_filter_by_source_and_request(self) -> None:
        config = {
            "sourceRuntimes": [
                {"id": "writer-cosmo-session", "sourceId": "cosmo"},
                {"id": "writer-cosmo-message", "source_id": "cosmo"},
                {"id": "writer-okta-audit", "sourceId": "okta"},
            ]
        }

        self.assertEqual(_declared_runtime_ids(config, "cosmo", {"writer-cosmo-message"}), ["writer-cosmo-message"])

    def test_runtime_id_from_command(self) -> None:
        self.assertEqual(_runtime_id_from_command(["orchestrator", "run", "runtime_id=writer-cosmo-session"]), "writer-cosmo-session")

    def test_schedule_suffix_matches_pulumi_names(self) -> None:
        self.assertEqual(_schedule_suffix("Cosmo Survey Feedback"), "cosmo-survey-feedback")

    def test_task_family_from_arn(self) -> None:
        self.assertEqual(
            _task_family("arn:aws:ecs:us-east-1:123456789012:task-definition/cerebro-sec-dev-orchestrator-cosmo-session:3"),
            "cerebro-sec-dev-orchestrator-cosmo-session",
        )

    def test_verify_task_accepts_skipped_runtime(self) -> None:
        target = RuntimeTarget(
            runtime_id="writer-cosmo-fact",
            schedule_name="cosmo-fact",
            rule_name="cerebro-sec-dev-orchestrator-cosmo-fact",
            target={"Arn": "arn:aws:ecs:us-east-1:123:cluster/cerebro-sec-dev-cluster"},
        )
        task = {"containers": [{"name": "cerebro", "exitCode": 0}]}
        messages = [{"kind": "span_end", "name": "orchestrator.runtime", "status": "skipped"}]

        with patch("scripts.verify_source_runtime_ecs._describe_tasks", return_value=[task]), patch(
            "scripts.verify_source_runtime_ecs._task_logs", return_value=messages
        ):
            result = _verify_task(target, "arn:aws:ecs:us-east-1:123:task/task-1", "us-east-1")

        self.assertEqual(result.runtime_status, "skipped")
        self.assertEqual(result.sync_status, "skipped")
        self.assertEqual(result.graph_ingest_status, "skipped")


if __name__ == "__main__":
    unittest.main()
