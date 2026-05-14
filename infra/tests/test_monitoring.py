from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


spec = importlib.util.spec_from_file_location("monitoring", Path(__file__).resolve().parents[1] / "aws" / "monitoring.py")
monitoring = importlib.util.module_from_spec(spec)
spec.loader.exec_module(monitoring)


class MonitoringRuntimeTest(unittest.TestCase):
    def test_cosmo_runtime_ids_are_limited_to_scheduled_cosmo_runtimes(self) -> None:
        runtimes = [
            {"id": "writer-cosmo-session", "sourceId": "cosmo"},
            {"id": "writer-cosmo-fact", "source_id": "cosmo"},
            {"id": "writer-okta-audit", "sourceId": "okta"},
        ]

        self.assertEqual(
            monitoring._cosmo_runtime_ids(runtimes, {"writer-cosmo-fact", "writer-okta-audit"}),
            ["writer-cosmo-fact"],
        )

    def test_cosmo_runtime_ids_include_all_cosmo_runtimes_without_schedule_filter(self) -> None:
        runtimes = [
            {"id": "writer-cosmo-session", "sourceId": "cosmo"},
            {"id": "writer-cosmo-fact", "sourceId": "cosmo"},
            {"id": "writer-okta-audit", "sourceId": "okta"},
        ]

        self.assertEqual(
            monitoring._cosmo_runtime_ids(runtimes, set()),
            ["writer-cosmo-fact", "writer-cosmo-session"],
        )


if __name__ == "__main__":
    unittest.main()
