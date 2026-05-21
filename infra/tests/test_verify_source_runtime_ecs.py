from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.verify_source_runtime_ecs import (
    _declared_runtime_ids,
    _runtime_id_from_command,
    _runtime_skip_reason,
    _runtime_skip_retryable,
    _schedule_suffix,
    _task_family,
)


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

    def test_runtime_skip_reason_is_retryable_for_lease_contention(self) -> None:
        span = {"status": "skipped", "reason": "lease_not_acquired"}

        self.assertEqual(_runtime_skip_reason(span), "lease_not_acquired")
        self.assertTrue(_runtime_skip_retryable(_runtime_skip_reason(span)))

    def test_runtime_skip_reason_is_not_retryable_for_unknown_skip(self) -> None:
        span = {"status": "skipped", "reason": "disabled"}

        self.assertEqual(_runtime_skip_reason(span), "disabled")
        self.assertFalse(_runtime_skip_retryable(_runtime_skip_reason(span)))


if __name__ == "__main__":
    unittest.main()
