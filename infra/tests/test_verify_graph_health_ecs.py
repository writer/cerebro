from __future__ import annotations

import contextlib
import io
import json
import sys
import unittest
from datetime import UTC, datetime
from pathlib import Path
import subprocess
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import scripts.verify_graph_health_ecs as verify_graph_health_ecs
from scripts.verify_graph_health_ecs import (
    GRAPH_RELATIONS_TO_OBSERVE,
    GraphCommandContext,
    _count_health_errors,
    _declared_aws_families,
    _extract_graph_payload_with_retries,
    _extract_json_payload,
    _failed_integrity_checks,
    _declared_runtime_ids,
    _graph_command_overrides,
    _graph_path_relations,
    _graph_health_command,
    _graph_health_errors,
    _graph_relation_counts,
    _ingest_run_commands,
    _run_graph_command_with_retries,
    _summary_markdown,
    _image_tag_version,
    _ingest_run_limit,
    _is_graph_paths_timeout,
    _latest_active_task_definition,
    _missing_declared_ingest_runtime_ids,
    _missing_required_graph_relation_counts,
    _resource_prefix,
    _run_graph_command,
    _run_graph_health_command_with_retries,
    _supports_attack_path_relations,
    _supports_graph_health_command,
    _supports_relation_counts,
    _task_definition_without_bootstrap_from_definition,
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

    def test_ingest_run_commands_scope_runtime_ids_and_batch_when_needed(self) -> None:
        runtime_ids = {f"runtime-{index:04d}-with-a-very-long-name" for index in range(400)}

        commands = _ingest_run_commands(runtime_ids)

        self.assertGreater(len(commands), 1)
        command_runtime_ids = set()
        for command in commands:
            self.assertEqual(command[:2], ["graph", "ingest-runs"])
            self.assertLessEqual(verify_graph_health_ecs._ecs_container_overrides_size(command), verify_graph_health_ecs.ECS_CONTAINER_OVERRIDES_SAFE_BYTES)
            runtime_arg = next(argument for argument in command if argument.startswith("runtime_ids="))
            command_runtime_ids.update(runtime_arg.removeprefix("runtime_ids=").split(","))
        self.assertEqual(command_runtime_ids, runtime_ids)

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

    def test_supports_graph_health_command_requires_min_image_tag(self) -> None:
        self.assertFalse(_supports_graph_health_command({"imageTag": "v2.1.139"}))
        self.assertTrue(_supports_graph_health_command({"imageTag": "v2.1.140"}))

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

    def test_graph_command_overrides_leave_source_runtime_bootstrap_default(self) -> None:
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
                {"containerOverrides": [{"name": "cerebro", "command": ["graph", "counts"]}]},
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

    def test_task_definition_without_bootstrap_removes_container_and_dependency(self) -> None:
        payload = _task_definition_without_bootstrap_from_definition(
            {
                "family": "cerebro-sec-dev",
                "taskRoleArn": "task-role",
                "executionRoleArn": "execution-role",
                "networkMode": "awsvpc",
                "requiresCompatibilities": ["FARGATE"],
                "cpu": "1024",
                "memory": "2048",
                "containerDefinitions": [
                    {"name": "source-runtime-bootstrap", "image": "image", "command": ["source-runtime", "bootstrap"]},
                    {"name": "sidecar", "image": "image"},
                    {
                        "name": "cerebro",
                        "image": "image",
                        "dependsOn": [
                            {"containerName": "source-runtime-bootstrap", "condition": "SUCCESS"},
                            {"containerName": "sidecar", "condition": "START"},
                        ],
                    },
                ],
            }
        )

        self.assertIsNotNone(payload)
        assert payload is not None
        self.assertEqual(payload["family"], "cerebro-sec-dev-graph-command")
        self.assertEqual(
            [container["name"] for container in payload["containerDefinitions"]],
            ["sidecar", "cerebro"],
        )
        cerebro = next(container for container in payload["containerDefinitions"] if container["name"] == "cerebro")
        self.assertEqual(cerebro["dependsOn"], [{"containerName": "sidecar", "condition": "START"}])

    def test_task_definition_without_bootstrap_returns_none_without_bootstrap(self) -> None:
        self.assertIsNone(
            _task_definition_without_bootstrap_from_definition(
                {
                    "family": "cerebro-sec-dev",
                    "containerDefinitions": [{"name": "cerebro", "image": "image"}],
                }
            )
        )

    def test_main_graph_command_runs_requested_command(self) -> None:
        context = GraphCommandContext(
            cluster="cluster",
            task_definition="task-definition",
            network_configuration={},
            log_group="log-group",
            stream_prefix="prefix",
            has_source_runtime_bootstrap=True,
        )
        with (
            patch("scripts.verify_graph_health_ecs._load_config", return_value={"environment": "sec-dev"}),
            patch("scripts.verify_graph_health_ecs._verify_account"),
            patch("scripts.verify_graph_health_ecs._describe_api_service", return_value={}),
            patch("scripts.verify_graph_health_ecs._graph_command_context", return_value=context),
            patch(
                "scripts.verify_graph_health_ecs._run_graph_command_with_retries",
                return_value=verify_graph_health_ecs.GraphCommandResult(
                    command=["graph", "repair-open-finding-primary-links"],
                    task_arn="task",
                    exit_code=0,
                    payload={"links_created": 1},
                ),
            ) as run_command,
            contextlib.redirect_stdout(io.StringIO()) as stdout,
        ):
            status = verify_graph_health_ecs.main(
                [
                    "--stack-file",
                    "aws/Pulumi.sec-dev.yaml",
                    "--graph-command",
                    "graph",
                    "repair-open-finding-primary-links",
                    "apply=true",
                ]
            )

        self.assertEqual(status, 0)
        self.assertIn('"links_created": 1', stdout.getvalue())
        self.assertEqual(run_command.call_args.args[2], ["graph", "repair-open-finding-primary-links", "apply=true"])

    def test_main_requires_bundled_graph_health_when_requested(self) -> None:
        context = GraphCommandContext(
            cluster="cluster",
            task_definition="task-definition",
            network_configuration={},
            log_group="log-group",
            stream_prefix="prefix",
            has_source_runtime_bootstrap=True,
        )
        with (
            patch("scripts.verify_graph_health_ecs._load_config", return_value={"environment": "sec-dev", "imageTag": "v2.1.139"}),
            patch("scripts.verify_graph_health_ecs._verify_account"),
            patch("scripts.verify_graph_health_ecs._describe_api_service", return_value={}),
            patch("scripts.verify_graph_health_ecs._graph_command_context", return_value=context),
        ):
            with self.assertRaisesRegex(RuntimeError, "bundled graph health"):
                verify_graph_health_ecs.main(["--stack-file", "aws/Pulumi.sec-dev.yaml", "--require-bundled-health"])

    def test_run_graph_command_with_retries_recovers_after_transient_failure(self) -> None:
        original_run_graph_command = verify_graph_health_ecs._run_graph_command
        original_time = verify_graph_health_ecs.time.time
        original_sleep = verify_graph_health_ecs.time.sleep
        calls = 0

        def fake_run_graph_command(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("graph command did not emit a JSON object")
            return verify_graph_health_ecs.GraphCommandResult(
                command=["graph", "counts"],
                task_arn="task-arn",
                exit_code=0,
                payload={"nodes": 1, "relations": 1},
            )

        verify_graph_health_ecs._run_graph_command = fake_run_graph_command
        verify_graph_health_ecs.time.time = lambda: 0
        verify_graph_health_ecs.time.sleep = lambda _seconds: None
        try:
            result = _run_graph_command_with_retries("prefix", {}, ["graph", "counts"], 10, 1, "us-east-1", 5)
        finally:
            verify_graph_health_ecs._run_graph_command = original_run_graph_command
            verify_graph_health_ecs.time.time = original_time
            verify_graph_health_ecs.time.sleep = original_sleep

        self.assertEqual(result.payload, {"nodes": 1, "relations": 1})
        self.assertEqual(calls, 2)

    def test_run_graph_command_with_retries_logs_underlying_failure(self) -> None:
        original_run_graph_command = verify_graph_health_ecs._run_graph_command
        original_time = verify_graph_health_ecs.time.time
        original_sleep = verify_graph_health_ecs.time.sleep
        times = iter([0, 0, 2])

        verify_graph_health_ecs._run_graph_command = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("specific graph boom")
        )
        verify_graph_health_ecs.time.time = lambda: next(times)
        verify_graph_health_ecs.time.sleep = lambda _seconds: None
        stderr = io.StringIO()
        try:
            with self.assertRaisesRegex(RuntimeError, "specific graph boom"):
                with contextlib.redirect_stderr(stderr):
                    _run_graph_command_with_retries("prefix", {}, ["graph", "counts"], 10, 1, "us-east-1", 1)
        finally:
            verify_graph_health_ecs._run_graph_command = original_run_graph_command
            verify_graph_health_ecs.time.time = original_time
            verify_graph_health_ecs.time.sleep = original_sleep

        self.assertIn("specific graph boom", stderr.getvalue())

    def test_run_graph_command_uses_cached_context(self) -> None:
        original_aws = verify_graph_health_ecs._aws
        original_wait_for_task = verify_graph_health_ecs._wait_for_task
        describe_definition_calls = 0
        context = GraphCommandContext(
            cluster="cluster",
            task_definition="arn:aws:ecs:us-east-1:123:task-definition/cerebro-go-production:45",
            network_configuration={
                "awsvpcConfiguration": {
                    "subnets": ["subnet-1"],
                    "securityGroups": ["sg-1"],
                    "assignPublicIp": "DISABLED",
                }
            },
            log_group="/ecs/cerebro",
            stream_prefix="runtime",
            has_source_runtime_bootstrap=True,
            task_definition_without_bootstrap={
                "family": "cerebro-go-production-graph-command",
                "containerDefinitions": [{"name": "cerebro", "image": "image"}],
            },
        )
        registered = False
        deregistered = False

        def fake_aws(args, _region):
            nonlocal describe_definition_calls, registered, deregistered
            if args[:2] == ["ecs", "describe-task-definition"]:
                describe_definition_calls += 1
                raise AssertionError("task definition metadata should come from the cached context")
            if args[:2] == ["ecs", "register-task-definition"]:
                registered = True
                payload = json.loads(args[args.index("--cli-input-json") + 1])
                self.assertEqual(payload["family"], "cerebro-go-production-graph-command")
                self.assertNotIn("source-runtime-bootstrap", json.dumps(payload))
                return {"taskDefinition": {"taskDefinitionArn": "graph-task-definition"}}
            if args[:2] == ["ecs", "deregister-task-definition"]:
                deregistered = True
                self.assertIn("graph-task-definition", args)
                return {"taskDefinition": {"taskDefinitionArn": "graph-task-definition"}}
            if args[:2] == ["ecs", "run-task"]:
                self.assertIn("--overrides", args)
                self.assertEqual(args[args.index("--task-definition") + 1], "graph-task-definition")
                override = args[args.index("--overrides") + 1]
                self.assertNotIn("source-runtime-bootstrap", override)
                return {"tasks": [{"taskArn": "task-arn"}]}
            if args[:2] == ["ecs", "describe-tasks"]:
                return {"tasks": [{"taskArn": "task-arn", "containers": [{"name": "cerebro", "exitCode": 0}]}]}
            if args[:2] == ["logs", "get-log-events"]:
                self.assertIn("/ecs/cerebro", args)
                return {"events": [{"message": '{"nodes": 1, "relations": 2}'}]}
            raise AssertionError(f"unexpected args: {args}")

        verify_graph_health_ecs._aws = fake_aws
        verify_graph_health_ecs._wait_for_task = lambda *_args, **_kwargs: None
        try:
            result = _run_graph_command("prefix", {}, ["graph", "counts"], 10, 1, "us-east-1", context)
        finally:
            verify_graph_health_ecs._aws = original_aws
            verify_graph_health_ecs._wait_for_task = original_wait_for_task

        self.assertEqual(result.payload, {"nodes": 1, "relations": 2})
        self.assertEqual(describe_definition_calls, 0)
        self.assertTrue(registered)
        self.assertTrue(deregistered)

    def test_run_graph_command_reports_exit_failure_log_tail(self) -> None:
        original_aws = verify_graph_health_ecs._aws
        original_wait_for_task = verify_graph_health_ecs._wait_for_task
        context = GraphCommandContext(
            cluster="cluster",
            task_definition="arn:aws:ecs:us-east-1:123:task-definition/cerebro-go-production:45",
            network_configuration={
                "awsvpcConfiguration": {
                    "subnets": ["subnet-1"],
                    "securityGroups": ["sg-1"],
                    "assignPublicIp": "DISABLED",
                }
            },
            log_group="/ecs/cerebro",
            stream_prefix="runtime",
            has_source_runtime_bootstrap=False,
        )

        def fake_aws(args, _region):
            if args[:2] == ["ecs", "run-task"]:
                return {"tasks": [{"taskArn": "task-arn"}]}
            if args[:2] == ["ecs", "describe-tasks"]:
                return {"tasks": [{"taskArn": "task-arn", "containers": [{"name": "cerebro", "exitCode": 1}]}]}
            if args[:2] == ["logs", "get-log-events"]:
                return {"events": [{"message": "fatal graph boom"}]}
            raise AssertionError(f"unexpected args: {args}")

        verify_graph_health_ecs._aws = fake_aws
        verify_graph_health_ecs._wait_for_task = lambda *_args, **_kwargs: None
        try:
            with self.assertRaisesRegex(RuntimeError, "exited with 1.*fatal graph boom"):
                _run_graph_command("prefix", {}, ["graph", "counts"], 10, 1, "us-east-1", context)
        finally:
            verify_graph_health_ecs._aws = original_aws
            verify_graph_health_ecs._wait_for_task = original_wait_for_task

    def test_run_graph_command_reports_ecs_stop_reason_when_logs_missing(self) -> None:
        original_aws = verify_graph_health_ecs._aws
        original_time = verify_graph_health_ecs.time.time
        original_sleep = verify_graph_health_ecs.time.sleep
        context = GraphCommandContext(
            cluster="cluster",
            task_definition="arn:aws:ecs:us-east-1:123:task-definition/cerebro-go-production:45",
            network_configuration={
                "awsvpcConfiguration": {
                    "subnets": ["subnet-1"],
                    "securityGroups": ["sg-1"],
                    "assignPublicIp": "DISABLED",
                }
            },
            log_group="/ecs/cerebro",
            stream_prefix="runtime",
            has_source_runtime_bootstrap=False,
        )

        def fake_aws(args, _region):
            if args[:2] == ["ecs", "run-task"]:
                return {"tasks": [{"taskArn": "task-arn"}]}
            if args[:2] == ["ecs", "describe-tasks"]:
                return {
                    "tasks": [
                        {
                            "taskArn": "task-arn",
                            "lastStatus": "STOPPED",
                            "stopCode": "TaskFailedToStart",
                            "stoppedReason": "ResourceInitializationError: unable to fetch secrets",
                            "containers": [
                                {
                                    "name": "cerebro",
                                    "lastStatus": "STOPPED",
                                    "exitCode": 1,
                                    "reason": "secret cerebro-go-production/MISSING was not found",
                                }
                            ],
                        }
                    ]
                }
            if args[:2] == ["logs", "get-log-events"]:
                raise RuntimeError("ResourceNotFoundException: log stream does not exist")
            raise AssertionError(f"unexpected args: {args}")

        verify_graph_health_ecs._aws = fake_aws
        times = iter([0, 91, 0, 91])
        verify_graph_health_ecs.time.time = lambda: next(times)
        verify_graph_health_ecs.time.sleep = lambda _seconds: None
        try:
            with self.assertRaisesRegex(RuntimeError, "ResourceInitializationError.*MISSING"):
                _run_graph_command("prefix", {}, ["graph", "counts"], 10, 1, "us-east-1", context)
        finally:
            verify_graph_health_ecs._aws = original_aws
            verify_graph_health_ecs.time.time = original_time
            verify_graph_health_ecs.time.sleep = original_sleep

    def test_run_graph_command_allows_nonzero_graph_health_payload(self) -> None:
        original_aws = verify_graph_health_ecs._aws
        original_wait_for_task = verify_graph_health_ecs._wait_for_task
        context = GraphCommandContext(
            cluster="cluster",
            task_definition="arn:aws:ecs:us-east-1:123:task-definition/cerebro-go-production:45",
            network_configuration={
                "awsvpcConfiguration": {
                    "subnets": ["subnet-1"],
                    "securityGroups": ["sg-1"],
                    "assignPublicIp": "DISABLED",
                }
            },
            log_group="/ecs/cerebro",
            stream_prefix="runtime",
            has_source_runtime_bootstrap=False,
        )

        def fake_aws(args, _region):
            if args[:2] == ["ecs", "run-task"]:
                return {"tasks": [{"taskArn": "task-arn"}]}
            if args[:2] == ["ecs", "describe-tasks"]:
                return {"tasks": [{"taskArn": "task-arn", "containers": [{"name": "cerebro", "exitCode": 1}]}]}
            if args[:2] == ["logs", "get-log-events"]:
                return {
                    "events": [
                        {
                            "message": '{"status":"failed","counts":{"nodes":1,"relations":1},"integrity":{"passed":1,"failed":0},"failures":["latest ingest failed"]}'
                        }
                    ]
                }
            raise AssertionError(f"unexpected args: {args}")

        verify_graph_health_ecs._aws = fake_aws
        verify_graph_health_ecs._wait_for_task = lambda *_args, **_kwargs: None
        try:
            result = _run_graph_command(
                "prefix",
                {},
                ["graph", "health"],
                10,
                1,
                "us-east-1",
                context,
                allow_nonzero=True,
            )
        finally:
            verify_graph_health_ecs._aws = original_aws
            verify_graph_health_ecs._wait_for_task = original_wait_for_task

        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.payload["status"], "failed")
        self.assertEqual(_graph_health_errors(result.payload, result.exit_code), ["latest ingest failed"])

    def test_run_graph_command_retries_delayed_logs(self) -> None:
        original_aws = verify_graph_health_ecs._aws
        original_wait_for_task = verify_graph_health_ecs._wait_for_task
        original_time = verify_graph_health_ecs.time.time
        original_sleep = verify_graph_health_ecs.time.sleep
        log_calls = 0
        context = GraphCommandContext(
            cluster="cluster",
            task_definition="arn:aws:ecs:us-east-1:123:task-definition/cerebro-go-production:45",
            network_configuration={
                "awsvpcConfiguration": {
                    "subnets": ["subnet-1"],
                    "securityGroups": ["sg-1"],
                    "assignPublicIp": "DISABLED",
                }
            },
            log_group="/ecs/cerebro",
            stream_prefix="runtime",
            has_source_runtime_bootstrap=False,
        )

        def fake_aws(args, _region):
            nonlocal log_calls
            if args[:2] == ["ecs", "run-task"]:
                return {"tasks": [{"taskArn": "task-arn"}]}
            if args[:2] == ["ecs", "describe-tasks"]:
                return {"tasks": [{"taskArn": "task-arn", "containers": [{"name": "cerebro", "exitCode": 0}]}]}
            if args[:2] == ["logs", "get-log-events"]:
                log_calls += 1
                if log_calls == 1:
                    return {"events": []}
                return {"events": [{"message": '{"nodes": 1, "relations": 2}'}]}
            raise AssertionError(f"unexpected args: {args}")

        verify_graph_health_ecs._aws = fake_aws
        verify_graph_health_ecs._wait_for_task = lambda *_args, **_kwargs: None
        verify_graph_health_ecs.time.time = lambda: 0
        verify_graph_health_ecs.time.sleep = lambda _seconds: None
        try:
            result = _run_graph_command("prefix", {}, ["graph", "counts"], 10, 1, "us-east-1", context)
        finally:
            verify_graph_health_ecs._aws = original_aws
            verify_graph_health_ecs._wait_for_task = original_wait_for_task
            verify_graph_health_ecs.time.time = original_time
            verify_graph_health_ecs.time.sleep = original_sleep

        self.assertEqual(result.payload, {"nodes": 1, "relations": 2})
        self.assertEqual(log_calls, 2)

    def test_run_graph_command_with_retries_stops_before_credential_expiry(self) -> None:
        original_run_graph_command = verify_graph_health_ecs._run_graph_command
        original_time = verify_graph_health_ecs.time.time
        calls = 0

        def fake_run_graph_command(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            return verify_graph_health_ecs.GraphCommandResult(
                command=["graph", "counts"],
                task_arn="task-arn",
                exit_code=0,
                payload={"nodes": 1, "relations": 1},
            )

        verify_graph_health_ecs._run_graph_command = fake_run_graph_command
        verify_graph_health_ecs.time.time = lambda: 100
        try:
            with self.assertRaisesRegex(TimeoutError, "credential-safe timeout"):
                _run_graph_command_with_retries(
                    "prefix",
                    {},
                    ["graph", "counts"],
                    10,
                    1,
                    "us-east-1",
                    5,
                    overall_deadline=99,
                )
        finally:
            verify_graph_health_ecs._run_graph_command = original_run_graph_command
            verify_graph_health_ecs.time.time = original_time

        self.assertEqual(calls, 0)

    def test_extract_json_payload_from_pretty_logs(self) -> None:
        payload = _extract_json_payload(['{"nodes": 2,', ' "relations": 3}'])

        self.assertEqual(payload, {"nodes": 2, "relations": 3})

    def test_extract_json_payload_ignores_telemetry_json(self) -> None:
        payload = _extract_json_payload(
            [
                '{"span":"graph.ingest_list_runs","status":"completed"}',
                "{",
                '  "runs": [',
                '    {"id": "run-1", "runtime_id": "runtime-a", "status": "completed"}',
                "  ],",
                '  "failed_count": 0',
                "}",
            ]
        )

        self.assertEqual(payload["runs"][0]["id"], "run-1")
        self.assertEqual(payload["failed_count"], 0)

    def test_extract_json_payload_filters_interleaved_span_logs(self) -> None:
        payload = _extract_json_payload(
            [
                '{"kind":"span_start","name":"graph.ingest_list_runs"}',
                "{",
                '  "runs": [',
                "    {",
                '      "id": "run-a",',
                '      "runtime_id": "runtime-a",',
                '      "status": "completed"',
                '{"kind":"span_end","name":"graph.ingest_list_runs","status":"completed"}',
                "    }",
                "  ],",
                '  "failed_count": 0',
                "}",
            ]
        )

        self.assertEqual(
            payload,
            {"runs": [{"id": "run-a", "runtime_id": "runtime-a", "status": "completed"}], "failed_count": 0},
        )

    def test_extract_json_payload_selects_graph_health_payload(self) -> None:
        payload = _extract_json_payload(
            [
                '{"span":"graph.health","status":"completed"}',
                '{"status":"passed","counts":{"nodes":2,"relations":3},"integrity":{"passed":5,"failed":0},"ingest":{"current_runtime_count":2}}',
            ]
        )

        self.assertEqual(payload["status"], "passed")
        self.assertEqual(payload["counts"], {"nodes": 2, "relations": 3})

    def test_extract_graph_payload_retries_missing_log_stream(self) -> None:
        original_time = verify_graph_health_ecs.time.time
        original_sleep = verify_graph_health_ecs.time.sleep
        calls = 0

        def fake_fetch_messages() -> list[str]:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("ResourceNotFoundException: specified log stream does not exist")
            return ['{"status":"passed","counts":{"nodes":1},"integrity":{"checks":[]}}']

        times = iter([0, 1])
        verify_graph_health_ecs.time.time = lambda: next(times)
        verify_graph_health_ecs.time.sleep = lambda _seconds: None
        try:
            messages, payload = _extract_graph_payload_with_retries(["graph", "health"], "task-arn", fake_fetch_messages)
        finally:
            verify_graph_health_ecs.time.time = original_time
            verify_graph_health_ecs.time.sleep = original_sleep

        self.assertEqual(calls, 2)
        self.assertEqual(messages, ['{"status":"passed","counts":{"nodes":1},"integrity":{"checks":[]}}'])
        self.assertEqual(payload["status"], "passed")

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
                {"id": "run-new", "runtime_id": "runtime-a", "status": "failed", "error": "source read failed"},
                {"id": "run-old", "runtime_id": "runtime-a", "status": "completed"},
            ]
        }

        with self.assertRaisesRegex(RuntimeError, "runtime-a:run-new.*source read failed"):
            _verify_current_ingest_runs(payload)

    def test_verify_current_ingest_runs_ignores_undeclared_latest_failures_when_scoped(self) -> None:
        payload = {
            "runs": [
                {"id": "run-a", "runtime_id": "runtime-a", "status": "completed"},
                {"id": "run-disabled", "runtime_id": "runtime-disabled", "status": "failed", "error": "disabled source"},
            ]
        }

        self.assertEqual(_verify_current_ingest_runs(payload, declared_runtime_ids={"runtime-a"}), 1)

    def test_verify_current_ingest_runs_allows_transient_source_failure_with_prior_success(self) -> None:
        payload = {
            "runs": [
                {
                    "id": "run-new",
                    "runtime_id": "runtime-a",
                    "status": "failed",
                    "error": 'request /web/api/v2.1/threats: Get "https://example.invalid": net/http: request canceled (Client.Timeout exceeded while awaiting headers)',
                },
                {"id": "run-old", "runtime_id": "runtime-a", "status": "completed"},
            ]
        }

        self.assertEqual(_verify_current_ingest_runs(payload, allow_transient_source_failures=True), 1)

    def test_verify_current_ingest_runs_rejects_transient_source_failure_without_prior_success(self) -> None:
        payload = {
            "runs": [
                {
                    "id": "run-new",
                    "runtime_id": "runtime-a",
                    "status": "failed",
                    "error": "Client.Timeout exceeded while awaiting headers",
                },
            ]
        }

        with self.assertRaisesRegex(RuntimeError, "runtime-a:run-new"):
            _verify_current_ingest_runs(payload, allow_transient_source_failures=True)

    def test_verify_current_ingest_runs_rejects_non_transient_failure_even_with_prior_success(self) -> None:
        payload = {
            "runs": [
                {"id": "run-new", "runtime_id": "runtime-a", "status": "failed", "error": "graph projection failed"},
                {"id": "run-old", "runtime_id": "runtime-a", "status": "completed"},
            ]
        }

        with self.assertRaisesRegex(RuntimeError, "graph projection failed"):
            _verify_current_ingest_runs(payload, allow_transient_source_failures=True)

    def test_verify_current_ingest_runs_with_retries_recovers_after_failed_latest_run(self) -> None:
        original_run_graph_command_with_retries = verify_graph_health_ecs._run_graph_command_with_retries
        original_time = verify_graph_health_ecs.time.time
        original_sleep = verify_graph_health_ecs.time.sleep
        calls = 0

        def fake_run_graph_command_with_retries(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            status = "failed" if calls == 1 else "completed"
            return verify_graph_health_ecs.GraphCommandResult(
                command=["graph", "ingest-runs"],
                task_arn=f"task-{calls}",
                exit_code=0,
                payload={"runs": [{"id": f"run-{calls}", "runtime_id": "runtime-a", "status": status}]},
            )

        verify_graph_health_ecs._run_graph_command_with_retries = fake_run_graph_command_with_retries
        verify_graph_health_ecs.time.time = lambda: 0
        verify_graph_health_ecs.time.sleep = lambda _seconds: None
        try:
            ingest_runs, current_count = verify_graph_health_ecs._verify_current_ingest_runs_with_retries(
                "prefix",
                {},
                {"runtime-a"},
                10,
                1,
                "us-east-1",
                5,
                30,
                60,
                False,
            )
        finally:
            verify_graph_health_ecs._run_graph_command_with_retries = original_run_graph_command_with_retries
            verify_graph_health_ecs.time.time = original_time
            verify_graph_health_ecs.time.sleep = original_sleep

        self.assertEqual(current_count, 1)
        self.assertEqual(ingest_runs.task_arn, "task-2")
        self.assertEqual(calls, 2)

    def test_graph_health_command_builds_single_health_check(self) -> None:
        self.assertEqual(
            _graph_health_command({"runtime-a", "runtime-b"}, {"belongs_to", "represents"}, 45, True),
            [
                "graph",
                "health",
                "limit=100",
                "max_running_minutes=45",
                "relations=belongs_to,represents",
                "allow_transient_source_failures=true",
                "runtime_ids=runtime-a,runtime-b",
            ],
        )

    def test_graph_health_command_omits_runtime_ids_when_ecs_override_would_be_too_large(self) -> None:
        runtime_ids = {f"runtime-{index:04d}-with-a-very-long-name" for index in range(400)}

        command = _graph_health_command(runtime_ids, {"belongs_to"}, 45, True)

        self.assertNotIn("runtime_ids=", " ".join(command))
        self.assertIn("allow_transient_source_failures=true", command)

    def test_run_graph_health_command_checks_ingest_runs_when_runtime_ids_omitted(self) -> None:
        original_run_graph_command_with_retries = verify_graph_health_ecs._run_graph_command_with_retries
        runtime_ids = {f"runtime-{index:04d}-with-a-very-long-name" for index in range(400)}
        commands: list[list[str]] = []

        def fake_run_graph_command_with_retries(*args, **_kwargs):
            command = args[2]
            commands.append(command)
            if command[:2] == ["graph", "health"]:
                self.assertNotIn("runtime_ids=", " ".join(command))
                return verify_graph_health_ecs.GraphCommandResult(
                    command=command,
                    task_arn="task-health",
                    exit_code=0,
                    payload={
                        "status": "passed",
                        "counts": {"nodes": 1, "relations": 1},
                        "integrity": {"passed": 1, "failed": 0},
                        "ingest": {"current_runtime_count": 1},
                    },
                )
            if command[:2] == ["graph", "ingest-runs"]:
                return verify_graph_health_ecs.GraphCommandResult(
                    command=command,
                    task_arn="task-ingest-runs",
                    exit_code=0,
                    payload={"runs": [{"id": "run-a", "runtime_id": "runtime-0000-with-a-very-long-name", "status": "completed"}]},
                )
            raise AssertionError(f"unexpected command: {command}")

        verify_graph_health_ecs._run_graph_command_with_retries = fake_run_graph_command_with_retries
        try:
            result = _run_graph_health_command_with_retries(
                "prefix",
                {},
                runtime_ids,
                {"belongs_to"},
                10,
                1,
                "us-east-1",
                0,
                0,
                60,
                False,
            )
        finally:
            verify_graph_health_ecs._run_graph_command_with_retries = original_run_graph_command_with_retries

        self.assertEqual(result.exit_code, 1)
        self.assertIn("missing graph ingest run history", result.payload["failures"][0])
        self.assertEqual(commands[0][:2], ["graph", "health"])
        self.assertEqual(commands[1][:2], ["graph", "ingest-runs"])

    def test_run_graph_health_command_replaces_unscoped_ingest_failures_with_scoped_ingest_health(self) -> None:
        original_run_graph_command_with_retries = verify_graph_health_ecs._run_graph_command_with_retries
        runtime_ids = {f"runtime-{index:04d}-with-a-very-long-name" for index in range(400)}
        commands: list[list[str]] = []

        def fake_run_graph_command_with_retries(*args, **_kwargs):
            command = args[2]
            commands.append(command)
            if command[:2] == ["graph", "health"]:
                self.assertNotIn("runtime_ids=", " ".join(command))
                return verify_graph_health_ecs.GraphCommandResult(
                    command=command,
                    task_arn="task-health",
                    exit_code=1,
                    payload={
                        "status": "failed",
                        "counts": {"nodes": 1, "relations": 1},
                        "integrity": {"passed": 1, "failed": 0},
                        "ingest": {"current_runtime_count": 2},
                        "failures": [
                            "latest graph ingest run failed for 1 runtime(s): runtime-disabled:run-disabled:error=disabled source"
                        ],
                    },
                )
            if command[:2] == ["graph", "ingest-runs"]:
                return verify_graph_health_ecs.GraphCommandResult(
                    command=command,
                    task_arn="task-ingest-runs",
                    exit_code=0,
                    payload={
                        "runs": [
                            {"id": f"run-{index:04d}", "runtime_id": runtime_id, "status": "completed"}
                            for index, runtime_id in enumerate(sorted(runtime_ids))
                        ]
                        + [
                            {"id": "run-disabled", "runtime_id": "runtime-disabled", "status": "failed", "error": "disabled source"},
                        ]
                    },
                )
            raise AssertionError(f"unexpected command: {command}")

        verify_graph_health_ecs._run_graph_command_with_retries = fake_run_graph_command_with_retries
        try:
            result = _run_graph_health_command_with_retries(
                "prefix",
                {},
                runtime_ids,
                {"belongs_to"},
                10,
                1,
                "us-east-1",
                0,
                0,
                60,
                False,
            )
        finally:
            verify_graph_health_ecs._run_graph_command_with_retries = original_run_graph_command_with_retries

        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.payload["status"], "passed")
        self.assertEqual(result.payload["failures"], [])
        self.assertEqual(result.payload["ingest"]["current_runtime_count"], 400)
        self.assertEqual(commands[0][:2], ["graph", "health"])
        self.assertEqual(commands[1][:2], ["graph", "ingest-runs"])

    def test_batched_ingest_runs_falls_back_to_legacy_runtime_id_filter(self) -> None:
        original_run_graph_command_with_retries = verify_graph_health_ecs._run_graph_command_with_retries
        commands: list[list[str]] = []

        def fake_run_graph_command_with_retries(*args, **_kwargs):
            command = args[2]
            commands.append(command)
            if any(argument.startswith("runtime_ids=") for argument in command):
                raise RuntimeError('unsupported graph ingest-runs argument "runtime_ids"')
            if "runtime_id=runtime-b" in command:
                return verify_graph_health_ecs.GraphCommandResult(
                    command=command,
                    task_arn="task-runtime-b",
                    exit_code=0,
                    payload={"runs": [{"id": "run-b", "runtime_id": "runtime-b", "status": "completed"}]},
                )
            return verify_graph_health_ecs.GraphCommandResult(
                command=command,
                task_arn="task-unscoped",
                exit_code=0,
                payload={"runs": [{"id": "run-a", "runtime_id": "runtime-a", "status": "completed"}]},
            )

        verify_graph_health_ecs._run_graph_command_with_retries = fake_run_graph_command_with_retries
        try:
            result = verify_graph_health_ecs._run_batched_ingest_runs_command(
                "prefix",
                {},
                {"runtime-a", "runtime-b"},
                10,
                1,
                "us-east-1",
                0,
            )
        finally:
            verify_graph_health_ecs._run_graph_command_with_retries = original_run_graph_command_with_retries

        self.assertEqual(result.command, ["graph", "ingest-runs", "legacy_scoped=true"])
        self.assertEqual({run["runtime_id"] for run in result.payload["runs"]}, {"runtime-a", "runtime-b"})
        self.assertIn("runtime_ids=runtime-a,runtime-b", commands[0])
        self.assertNotIn("runtime_ids=", " ".join(commands[1]))
        self.assertIn("runtime_id=runtime-b", commands[2])

    def test_run_graph_health_command_with_retries_recovers_after_failed_status(self) -> None:
        original_run_graph_command_with_retries = verify_graph_health_ecs._run_graph_command_with_retries
        original_time = verify_graph_health_ecs.time.time
        original_sleep = verify_graph_health_ecs.time.sleep
        calls = 0

        def fake_run_graph_command_with_retries(*_args, **kwargs):
            nonlocal calls
            calls += 1
            self.assertTrue(kwargs.get("allow_nonzero"))
            if calls == 1:
                return verify_graph_health_ecs.GraphCommandResult(
                    command=["graph", "health"],
                    task_arn="task-1",
                    exit_code=1,
                    payload={
                        "status": "failed",
                        "counts": {"nodes": 1, "relations": 1},
                        "integrity": {"passed": 1, "failed": 0},
                        "failures": ["latest graph ingest run failed"],
                    },
                )
            return verify_graph_health_ecs.GraphCommandResult(
                command=["graph", "health"],
                task_arn="task-2",
                exit_code=0,
                payload={
                    "status": "passed",
                    "counts": {"nodes": 1, "relations": 1},
                    "integrity": {"passed": 1, "failed": 0},
                    "ingest": {"current_runtime_count": 1},
                },
            )

        verify_graph_health_ecs._run_graph_command_with_retries = fake_run_graph_command_with_retries
        verify_graph_health_ecs.time.time = lambda: 0
        verify_graph_health_ecs.time.sleep = lambda _seconds: None
        try:
            result = _run_graph_health_command_with_retries(
                "prefix",
                {},
                {"runtime-a"},
                {"belongs_to"},
                10,
                1,
                "us-east-1",
                5,
                30,
                60,
                False,
            )
        finally:
            verify_graph_health_ecs._run_graph_command_with_retries = original_run_graph_command_with_retries
            verify_graph_health_ecs.time.time = original_time
            verify_graph_health_ecs.time.sleep = original_sleep

        self.assertEqual(result.task_arn, "task-2")
        self.assertEqual(calls, 2)

    def test_verify_current_ingest_runs_with_retries_checks_declared_runtime_ids(self) -> None:
        original_run_graph_command_with_retries = verify_graph_health_ecs._run_graph_command_with_retries

        def fake_run_graph_command_with_retries(*_args, **_kwargs):
            return verify_graph_health_ecs.GraphCommandResult(
                command=["graph", "ingest-runs"],
                task_arn="task-1",
                exit_code=0,
                payload={"runs": [{"id": "run-a", "runtime_id": "runtime-a", "status": "completed"}]},
            )

        verify_graph_health_ecs._run_graph_command_with_retries = fake_run_graph_command_with_retries
        try:
            with self.assertRaisesRegex(RuntimeError, "runtime-b"):
                verify_graph_health_ecs._verify_current_ingest_runs_with_retries(
                    "prefix",
                    {},
                    {"runtime-a", "runtime-b"},
                    10,
                    1,
                    "us-east-1",
                    0,
                    0,
                    60,
                    False,
                )
        finally:
            verify_graph_health_ecs._run_graph_command_with_retries = original_run_graph_command_with_retries

    def test_verify_current_ingest_runs_rejects_missing_declared_runtime(self) -> None:
        payload = {"runs": [{"id": "run-a", "runtime_id": "runtime-a", "status": "completed"}]}

        with self.assertRaisesRegex(RuntimeError, "runtime-b"):
            _verify_current_ingest_runs(payload, declared_runtime_ids={"runtime-a", "runtime-b"})

    def test_missing_declared_ingest_runtime_ids_reports_without_failing(self) -> None:
        payload = {"runs": [{"id": "run-a", "runtime_id": "runtime-a", "status": "completed"}]}

        self.assertEqual(
            _missing_declared_ingest_runtime_ids(payload, {"runtime-a", "runtime-b"}),
            ["runtime-b"],
        )

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

    def test_count_health_errors_reports_zero_counts(self) -> None:
        self.assertEqual(
            _count_health_errors({"nodes": 0, "relations": 0}),
            [
                "graph node count must be positive, got 0",
                "graph relation count must be positive, got 0",
            ],
        )

    def test_failed_integrity_checks_lists_failed_checks(self) -> None:
        payload = {
            "failed": 1,
            "checks": [
                {"name": "has_nodes", "actual": 0, "passed": False},
                {"name": "has_relations", "actual": 12, "passed": True},
            ],
        }

        self.assertEqual(_failed_integrity_checks(payload), ["has_nodes=0"])

    def test_verify_required_graph_relation_counts_requires_positive_counts(self) -> None:
        payload = {"relations": {"belongs_to": 4, "represents": 2, "can_reach": 0}}

        with self.assertRaisesRegex(RuntimeError, "can_reach"):
            _verify_required_graph_relation_counts(payload, {"resource_exposure"})

    def test_verify_required_graph_relation_counts_accepts_required_relations(self) -> None:
        payload = {"relations": {"belongs_to": 4, "represents": 2, "can_reach": 1, "can_perform": 3, "can_assume": 5}}

        self.assertEqual(
            _verify_required_graph_relation_counts(payload, {"resource_exposure", "effective_permission", "iam_role_trust"}),
            {"belongs_to", "can_assume", "can_perform", "can_reach", "represents"},
        )

    def test_verify_required_graph_relation_counts_requires_declared_iam_edges(self) -> None:
        payload = {"relations": {"belongs_to": 4, "represents": 2, "can_perform": 0, "can_assume": 0}}

        with self.assertRaisesRegex(RuntimeError, "can_assume, can_perform"):
            _verify_required_graph_relation_counts(payload, {"effective_permission", "iam_role_trust"})

    def test_missing_required_graph_relation_counts_returns_missing_edges(self) -> None:
        counts = {"belongs_to": 4, "represents": 2, "can_perform": 0, "can_assume": 0}

        self.assertEqual(
            _missing_required_graph_relation_counts(counts, {"effective_permission", "iam_role_trust"}),
            ["can_assume", "can_perform"],
        )

    def test_graph_relation_observation_includes_optional_aws_depth_edges(self) -> None:
        self.assertIn("can_reach", GRAPH_RELATIONS_TO_OBSERVE)
        self.assertIn("runs_as", GRAPH_RELATIONS_TO_OBSERVE)

    def test_verify_required_graph_relations_reports_optional_attack_path_edges_for_aws(self) -> None:
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

    def test_summary_markdown_includes_graph_shape(self) -> None:
        summary = _summary_markdown(
            "go-prod",
            {"nodes": 36278, "relations": 85586},
            {"passed": 8, "failed": 0},
            {"belongs_to": 11437, "can_assume": 0, "can_reach": 454},
            {"belongs_to", "can_reach"},
            27,
            27,
            [],
            [],
            [],
            [],
            {"public_endpoint"},
        )

        self.assertIn("Status: **passed**", summary)
        self.assertIn("Nodes: `36278`", summary)
        self.assertIn("Relationships: `85586`", summary)
        self.assertIn("Integrity checks: `8 passed / 0 failed`", summary)
        self.assertIn("AWS source families: `public_endpoint`", summary)
        self.assertIn("| `can_assume` | 0 |", summary)
        self.assertIn("| `can_reach` | 454 |", summary)

    def test_summary_markdown_marks_missing_ingest_runtime_failed(self) -> None:
        summary = _summary_markdown(
            "sec-dev",
            {"nodes": 1, "relations": 1},
            {"passed": 7, "failed": 0},
            {},
            {"belongs_to"},
            1,
            2,
            [],
            [],
            ["runtime-b"],
            [],
            set(),
        )

        self.assertIn("Status: **failed**", summary)
        self.assertIn("| `runtime-b` |", summary)

    def test_summary_markdown_marks_missing_graph_relation_failed(self) -> None:
        summary = _summary_markdown(
            "go-prod",
            {"nodes": 1, "relations": 1},
            {"passed": 7, "failed": 0},
            {"belongs_to": 1, "represents": 1, "can_assume": 0},
            {"belongs_to", "represents"},
            2,
            2,
            [],
            [],
            [],
            ["can_assume"],
            {"iam_role_trust"},
        )

        self.assertIn("Status: **failed**", summary)
        self.assertIn("| Missing graph relation |", summary)
        self.assertIn("| `can_assume` |", summary)

    def test_summary_markdown_includes_count_and_integrity_failures(self) -> None:
        summary = _summary_markdown(
            "go-prod",
            {"nodes": 0, "relations": 0},
            {"passed": 6, "failed": 1},
            {},
            set(),
            2,
            2,
            ["graph node count must be positive, got 0"],
            ["has_nodes=0"],
            [],
            [],
            set(),
        )

        self.assertIn("Status: **failed**", summary)
        self.assertIn("| Graph health failure |", summary)
        self.assertIn("| `graph node count must be positive, got 0` |", summary)
        self.assertIn("| Failed integrity check |", summary)
        self.assertIn("| `has_nodes=0` |", summary)


if __name__ == "__main__":
    unittest.main()
