from __future__ import annotations

import sys
import unittest
from datetime import UTC, datetime
from pathlib import Path
import subprocess


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import scripts.verify_graph_health_ecs as verify_graph_health_ecs
from scripts.verify_graph_health_ecs import (
    _declared_aws_families,
    _extract_json_payload,
    _declared_runtime_ids,
    _graph_command_overrides,
    _graph_path_relations,
    _graph_relation_counts,
    _image_tag_version,
    _ingest_run_limit,
    _is_graph_paths_timeout,
    _latest_active_task_definition,
    _resource_prefix,
    _supports_attack_path_relations,
    _supports_relation_counts,
    _verify_counts,
    _verify_current_ingest_runs,
    _verify_integrity,
    _verify_required_graph_relation_counts,
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
        self.assertEqual(_ingest_run_limit({str(index) for index in range(40)}), 500)

    def test_image_tag_version_parses_release_tags(self) -> None:
        self.assertEqual(_image_tag_version("v2.1.46"), (2, 1, 46))
        self.assertEqual(_image_tag_version("2.1.47-rc.1"), (2, 1, 47))
        self.assertIsNone(_image_tag_version("sha-abcdef"))

    def test_supports_attack_path_relations_uses_minimum_image_tag(self) -> None:
        self.assertFalse(_supports_attack_path_relations({"imageTag": "v2.1.45"}))
        self.assertTrue(_supports_attack_path_relations({"imageTag": "v2.1.46"}))

    def test_supports_relation_counts_requires_min_image_tag(self) -> None:
        self.assertFalse(_supports_relation_counts({"imageTag": "v2.1.49"}))
        self.assertTrue(_supports_relation_counts({"imageTag": "v2.1.50"}))

    def test_is_graph_paths_timeout_matches_neo4j_deadline(self) -> None:
        self.assertTrue(_is_graph_paths_timeout(RuntimeError("query graph path patterns: ConnectivityError: context deadline exceeded")))
        self.assertFalse(_is_graph_paths_timeout(RuntimeError("graph paths missing required relation(s): can_reach")))

    def test_aws_error_includes_stderr(self) -> None:
        original_run = verify_graph_health_ecs.subprocess.run

        def fake_run(*_args, **_kwargs):
            raise subprocess.CalledProcessError(254, ["aws"], stderr="TaskDefinition is inactive")

        verify_graph_health_ecs.subprocess.run = fake_run
        try:
            with self.assertRaisesRegex(RuntimeError, "TaskDefinition is inactive"):
                verify_graph_health_ecs._aws(["ecs", "run-task"], "us-east-1")
        finally:
            verify_graph_health_ecs.subprocess.run = original_run

    def test_latest_active_task_definition_keeps_active_service_definition(self) -> None:
        original_aws = verify_graph_health_ecs._aws

        def fake_aws(args, _region):
            self.assertIn("describe-task-definition", args)
            return {
                "taskDefinition": {
                    "status": "ACTIVE",
                    "taskDefinitionArn": "arn:aws:ecs:us-east-1:123:task-definition/cerebro-go-production:44",
                }
            }

        verify_graph_health_ecs._aws = fake_aws
        try:
            self.assertEqual(
                _latest_active_task_definition("arn:aws:ecs:us-east-1:123:task-definition/cerebro-go-production:44", "us-east-1"),
                "arn:aws:ecs:us-east-1:123:task-definition/cerebro-go-production:44",
            )
        finally:
            verify_graph_health_ecs._aws = original_aws

    def test_latest_active_task_definition_falls_back_from_inactive_service_definition(self) -> None:
        original_aws = verify_graph_health_ecs._aws

        def fake_aws(args, _region):
            if "describe-task-definition" in args:
                return {"taskDefinition": {"status": "INACTIVE", "family": "cerebro-go-production"}}
            if "list-task-definitions" in args:
                self.assertIn("--status", args)
                self.assertIn("ACTIVE", args)
                self.assertIn("--sort", args)
                self.assertIn("DESC", args)
                return {"taskDefinitionArns": ["arn:aws:ecs:us-east-1:123:task-definition/cerebro-go-production:45"]}
            raise AssertionError(f"unexpected args: {args}")

        verify_graph_health_ecs._aws = fake_aws
        try:
            self.assertEqual(
                _latest_active_task_definition("arn:aws:ecs:us-east-1:123:task-definition/cerebro-go-production:44", "us-east-1"),
                "arn:aws:ecs:us-east-1:123:task-definition/cerebro-go-production:45",
            )
        finally:
            verify_graph_health_ecs._aws = original_aws

    def test_graph_command_overrides_disables_source_runtime_bootstrap_dependency(self) -> None:
        original_aws = verify_graph_health_ecs._aws

        def fake_aws(args, _region):
            self.assertIn("describe-task-definition", args)
            return {
                "taskDefinition": {
                    "containerDefinitions": [
                        {"name": "source-runtime-bootstrap"},
                        {"name": "cerebro"},
                    ]
                }
            }

        verify_graph_health_ecs._aws = fake_aws
        try:
            self.assertEqual(
                _graph_command_overrides("arn:aws:ecs:us-east-1:123:task-definition/cerebro-sec-dev:72", ["graph", "counts"], "us-east-1"),
                {
                    "containerOverrides": [
                        {"name": "cerebro", "command": ["graph", "counts"]},
                        {"name": "source-runtime-bootstrap", "command": ["graph", "counts"]},
                    ]
                },
            )
        finally:
            verify_graph_health_ecs._aws = original_aws

    def test_graph_command_overrides_preserves_tasks_without_bootstrap_container(self) -> None:
        original_aws = verify_graph_health_ecs._aws

        def fake_aws(args, _region):
            self.assertIn("describe-task-definition", args)
            return {"taskDefinition": {"containerDefinitions": [{"name": "cerebro"}]}}

        verify_graph_health_ecs._aws = fake_aws
        try:
            self.assertEqual(
                _graph_command_overrides("arn:aws:ecs:us-east-1:123:task-definition/cerebro-sec-dev:72", ["graph", "integrity"], "us-east-1"),
                {"containerOverrides": [{"name": "cerebro", "command": ["graph", "integrity"]}]},
            )
        finally:
            verify_graph_health_ecs._aws = original_aws

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

    def test_graph_relation_counts_reads_relation_count_payload(self) -> None:
        self.assertEqual(
            _graph_relation_counts({"relations": {"belongs_to": 4, "represents": "2", "missing": 0}}),
            {"belongs_to": 4, "represents": 2, "missing": 0},
        )

    def test_verify_required_graph_relation_counts_requires_positive_counts(self) -> None:
        payload = {"relations": {"belongs_to": 4, "represents": 2, "can_reach": 0}}

        with self.assertRaisesRegex(RuntimeError, "can_reach"):
            _verify_required_graph_relation_counts(payload, {"resource_exposure"})

    def test_verify_required_graph_relation_counts_accepts_required_relations(self) -> None:
        payload = {"relations": {"belongs_to": 4, "represents": 2, "can_reach": 1, "can_perform": 0}}

        self.assertEqual(
            _verify_required_graph_relation_counts(payload, {"resource_exposure"}),
            {"belongs_to", "represents", "can_reach"},
        )

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
            _verify_required_graph_relations(
                {"patterns": [{"first_relation": "belongs_to", "second_relation": "represents"}]},
                {"resource_exposure"},
            )

    def test_verify_required_graph_relations_allows_public_endpoint_without_reachability_edge(self) -> None:
        payload = {"patterns": [{"first_relation": "belongs_to", "second_relation": "represents"}]}

        self.assertEqual(
            _verify_required_graph_relations(payload, {"public_endpoint"}),
            {"belongs_to", "represents"},
        )

    def test_verify_required_graph_relations_allows_legacy_image_without_attack_path_edges(self) -> None:
        payload = {"patterns": [{"first_relation": "belongs_to", "second_relation": "represents"}]}

        self.assertEqual(
            _verify_required_graph_relations(
                payload,
                {"effective_permission", "public_endpoint"},
                attack_path_relations_supported=False,
            ),
            {"belongs_to", "represents"},
        )


if __name__ == "__main__":
    unittest.main()
