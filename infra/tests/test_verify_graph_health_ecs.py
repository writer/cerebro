from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.verify_graph_health_ecs import (
    _extract_json_payload,
    _resource_prefix,
    _verify_counts,
    _verify_current_ingest_runs,
    _verify_integrity,
)


class VerifyGraphHealthEcsTest(unittest.TestCase):
    def test_resource_prefix_uses_cerebro_environment(self) -> None:
        self.assertEqual(_resource_prefix({"environment": "go-production"}, "go-prod"), "cerebro-go-production")

    def test_resource_prefix_falls_back_to_stack_name(self) -> None:
        self.assertEqual(_resource_prefix({}, "sec-dev"), "cerebro-sec-dev")

    def test_extract_json_payload_from_pretty_logs(self) -> None:
        payload = _extract_json_payload(['{"nodes": 2,', ' "relations": 3}'])

        self.assertEqual(payload, {"nodes": 2, "relations": 3})

    def test_verify_counts_rejects_empty_graph(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "node count"):
            _verify_counts({"nodes": 0, "relations": 1})
        with self.assertRaisesRegex(RuntimeError, "relation count"):
            _verify_counts({"nodes": 1, "relations": 0})

    def test_verify_integrity_reports_failed_checks(self) -> None:
        payload = {
            "failed": 1,
            "checks": [
                {"name": "self_referential_relations", "actual": 528, "passed": False},
                {"name": "blank_entity_labels", "actual": 0, "passed": True},
            ],
        }

        with self.assertRaisesRegex(RuntimeError, "self_referential_relations=528"):
            _verify_integrity(payload)

    def test_verify_current_ingest_runs_uses_latest_per_runtime(self) -> None:
        payload = {
            "runs": [
                {"id": "run-new", "runtime_id": "runtime-a", "status": "completed"},
                {"id": "run-old", "runtime_id": "runtime-a", "status": "failed"},
                {"id": "run-b", "runtime_id": "runtime-b", "status": "completed"},
            ]
        }

        self.assertEqual(_verify_current_ingest_runs(payload), 2)

    def test_verify_current_ingest_runs_rejects_latest_failures(self) -> None:
        payload = {
            "runs": [
                {"id": "run-new", "runtime_id": "runtime-a", "status": "failed"},
                {"id": "run-old", "runtime_id": "runtime-a", "status": "completed"},
            ]
        }

        with self.assertRaisesRegex(RuntimeError, "runtime-a:run-new"):
            _verify_current_ingest_runs(payload)


if __name__ == "__main__":
    unittest.main()
