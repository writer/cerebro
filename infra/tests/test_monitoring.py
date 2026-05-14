from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


spec = importlib.util.spec_from_file_location("monitoring", Path(__file__).resolve().parents[1] / "aws" / "monitoring.py")
monitoring = importlib.util.module_from_spec(spec)
spec.loader.exec_module(monitoring)


class MonitoringRuntimeTest(unittest.TestCase):
    def test_source_runtime_ids_are_limited_to_scheduled_runtimes(self) -> None:
        runtimes = [
            {"id": "writer-cosmo-session", "sourceId": "cosmo"},
            {"id": "writer-okta-audit", "sourceId": "okta"},
            {"id": "writer-unscheduled", "sourceId": "aws"},
        ]

        self.assertEqual(
            monitoring._scheduled_source_runtime_ids(
                runtimes,
                {"writer-cosmo-session", "writer-okta-audit"},
            ),
            ["writer-cosmo-session", "writer-okta-audit"],
        )

    def test_source_runtime_ids_ignore_unscheduled_runtimes(self) -> None:
        runtimes = [
            {"id": "writer-cosmo-session", "sourceId": "cosmo"},
            {"id": "writer-okta-audit", "sourceId": "okta"},
        ]

        self.assertEqual(
            monitoring._scheduled_source_runtime_ids(runtimes, set()),
            [],
        )

    def test_runtime_heartbeat_period_follows_rate_schedule(self) -> None:
        schedule = {"scheduleExpression": "rate(30 minutes)"}
        self.assertEqual(monitoring._runtime_heartbeat_period_seconds(schedule, 28800), 5400)

    def test_runtime_heartbeat_period_follows_cron_hour_step(self) -> None:
        schedule = {"scheduleExpression": "cron(3 0/6 * * ? *)"}
        self.assertEqual(monitoring._runtime_heartbeat_period_seconds(schedule, 28800), 64800)


if __name__ == "__main__":
    unittest.main()
