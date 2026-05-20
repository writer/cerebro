from __future__ import annotations

import sys
import unittest
from datetime import UTC, datetime
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.verify_graph_health_ecs import (
    _declared_aws_families,
    _extract_json_payload,
    _declared_runtime_ids,
    _graph_path_relations,
    _ingest_run_limit,
    _resource_prefix,
    _verify_counts,
    _verify_current_ingest_runs,
    _verify_integrity,
    _verify_required_graph_relations,
)


class VerifyGraphHealthEcsTest(unittest.TestCase):
    def test_resource_prefix_uses_cerebro_environment(self) -> None:
        self.assertEqual(_resource_prefix({"environment": "go-production"}, "go-prod"), "cerebro-go-production")

    def test_resource_prefix_falls_back_to_stack_name(self) -> None:
        self.assertEqual(_resource_prefix({}, "sec-dev"), "cerebro-sec-dev")

    def test_declared_runtime_ids_reads_source_runtimes(self) -> None:
        self.assertEqual(
            _declared_runtime_ids({"sourceRuntimes": [{"id": "runtime-a"}, {"id": "runtime-b"}, {"sourceId": "missing-id"}]}),
            {"runtime-a", "runtime-b"},
        )

    def test_declared_aws_families_reads_aws_runtime_configs(self) -> None:
        self.assertEqual(
            _declared_aws_families(
                {
                    "sourceRuntimes": [
                        {"id": "aws-a", "sourceId": "aws", "config": {"family": "effective_permission"}},
                        {"id": "okta-a", "sourceId": "okta", "config": {"family": "user"}},
                        {"id": "aws-b", "sourceId": "aws", "config": {"family": "public_endpoint"}},
                    ]
                }
            ),
            {"effective_permission", "public_endpoint"},
        )

    def test_ingest_run_limit_scales_with_declared_runtimes(self) -> None:
        self.assertEqual(_ingest_run_limit({"a", "b"}), 100)
        self.assertEqual(_ingest_run_limit({str(index) for index in range(40)}), 120)

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

    def test_verify_current_ingest_runs_rejects_missing_declared_runtime(self) -> None:
        payload = {"runs": [{"id": "run-a", "runtime_id": "runtime-a", "status": "completed"}]}

        with self.assertRaisesRegex(RuntimeError, "runtime-b"):
            _verify_current_ingest_runs(payload, declared_runtime_ids={"runtime-a", "runtime-b"})

    def test_verify_current_ingest_runs_allows_recent_running_runs(self) -> None:
        payload = {"runs": [{"id": "run-a", "runtime_id": "runtime-a", "status": "running", "started_at": "2026-05-20T00:30:00Z"}]}

        self.assertEqual(_verify_current_ingest_runs(payload, now=datetime(2026, 5, 20, 1, 0, tzinfo=UTC)), 1)

    def test_verify_current_ingest_runs_rejects_stale_running_runs(self) -> None:
        payload = {"runs": [{"id": "run-a", "runtime_id": "runtime-a", "status": "running", "started_at": "2026-05-20T00:00:00Z"}]}

        with self.assertRaisesRegex(RuntimeError, "stale-running"):
            _verify_current_ingest_runs(payload, max_running_minutes=30, now=datetime(2026, 5, 20, 1, 0, tzinfo=UTC))

    def test_verify_current_ingest_runs_rejects_completed_zero_projection(self) -> None:
        payload = {
            "runs": [
                {
                    "id": "run-a",
                    "runtime_id": "runtime-a",
                    "status": "completed",
                    "events_read": 10,
                    "entities_projected": 0,
                    "links_projected": 0,
                }
            ]
        }

        with self.assertRaisesRegex(RuntimeError, "projected no graph records"):
            _verify_current_ingest_runs(payload)

    def test_graph_path_relations_reads_patterns_and_traversals(self) -> None:
        payload = {
            "patterns": [{"first_relation": "can_reach", "second_relation": "belongs_to"}],
            "traversals": [{"first_relation": "represents", "second_relation": "can_perform"}],
        }
        self.assertEqual(_graph_path_relations(payload), {"belongs_to", "can_perform", "can_reach", "represents"})

    def test_verify_required_graph_relations_requires_attack_path_edges_for_aws(self) -> None:
        payload = {
            "patterns": [
                {"first_relation": "can_reach", "second_relation": "belongs_to"},
                {"first_relation": "represents", "second_relation": "can_perform"},
                {"first_relation": "can_assume", "second_relation": "belongs_to"},
            ]
        }
        self.assertIn("can_perform", _verify_required_graph_relations(payload, {"effective_permission", "iam_role_trust"}))

    def test_verify_required_graph_relations_rejects_missing_edges(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "can_reach"):
            _verify_required_graph_relations({"patterns": [{"first_relation": "belongs_to", "second_relation": "represents"}]})


if __name__ == "__main__":
    unittest.main()
