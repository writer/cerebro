from __future__ import annotations

import json
import sys
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import verify_aws_secret_imports as secret_imports
from scripts.verify_source_runtime_ecs import (
    RuntimeSkippedError,
    RuntimeTaskFailedError,
    RuntimeTarget,
    RuntimeVerificationFailedError,
    SecretImportPreflightFinding,
    VerificationOptions,
    VerificationResult,
    _bootstrap_payload_from_task_definition,
    _bootstrap_payload_runtime_ids,
    _config_for_runtime_scope,
    _bootstrap_task_diagnostics,
    _declared_runtime_ids,
    _latest_active_task_definition,
    _latest_task,
    _observability_runtime_ids,
    _run_and_verify_task_with_retries,
    _run_task,
    _runtime_id_from_command,
    _runtime_targets,
    _runtime_skip_reason,
    _runtime_skip_retryable,
    _schedule_suffix,
    _sanitize_text,
    _scoped_bootstrap_payload,
    _secret_import_preflight_findings,
    _stop_running_tasks,
    _summarize_log_messages,
    _task_family,
    _task_logs,
    _verify_bootstrap_payload_targets,
    _verify_runtime_target,
    _verify_task,
    _verification_result_from_logs,
    _verify_runtime_targets,
    _verification_command,
    main,
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

    def test_declared_runtime_ids_filter_by_family(self) -> None:
        config = {
            "sourceRuntimes": [
                {"id": "aws-public", "sourceId": "aws", "config": {"family": "public_endpoint"}},
                {"id": "aws-iam", "sourceId": "aws", "config": {"family": "iam_user"}},
                {"id": "cosmo-session", "sourceId": "cosmo", "config": {"family": "session"}},
            ]
        }

        self.assertEqual(_declared_runtime_ids(config, "aws", set(), {"public_endpoint"}), ["aws-public"])

    def test_observability_runtime_ids_use_enabled_entries_and_filters(self) -> None:
        config = {
            "sourceRuntimeObservability": [
                {
                    "sourceSystem": "evidence_cas",
                    "sourceRuntimeId": "writer-evidence-cas-cases",
                    "runtimeClass": "object",
                    "enabled": True,
                    "freshnessSlaMinutes": 90,
                },
                {
                    "sourceSystem": "panopticon",
                    "sourceRuntimeId": "writer-panopticon-alerts",
                    "runtimeClass": "alert",
                    "enabled": True,
                    "freshnessSlaMinutes": 30,
                },
                {
                    "sourceSystem": "panopticon",
                    "sourceRuntimeId": "writer-panopticon-disabled",
                    "runtimeClass": "ioc",
                    "enabled": False,
                    "freshnessSlaMinutes": 30,
                },
            ]
        }

        self.assertEqual(
            _observability_runtime_ids(config, "panopticon", set(), {"alert"}),
            ["writer-panopticon-alerts"],
        )

    def test_observability_runtime_ids_reject_duplicate_enabled_entries(self) -> None:
        config = {
            "sourceRuntimeObservability": [
                {"sourceSystem": "panopticon", "sourceRuntimeId": "writer-panopticon-alerts", "runtimeClass": "alert", "enabled": True},
                {"sourceSystem": "panopticon", "sourceRuntimeId": "writer-panopticon-alerts", "runtimeClass": "alert", "enabled": True},
            ]
        }

        with self.assertRaisesRegex(ValueError, "duplicate enabled sourceRuntimeObservability"):
            _observability_runtime_ids(config, "panopticon", set(), {"alert"})

    def test_runtime_id_from_command(self) -> None:
        self.assertEqual(_runtime_id_from_command(["orchestrator", "run", "runtime_id=writer-cosmo-session"]), "writer-cosmo-session")

    def test_schedule_suffix_matches_pulumi_names(self) -> None:
        self.assertEqual(_schedule_suffix("Cosmo Survey Feedback"), "cosmo-survey-feedback")

    def test_runtime_targets_can_skip_not_yet_deployed_rule(self) -> None:
        config = {
            "orchestratorSchedules": [
                {
                    "name": "cosmo-message",
                    "command": ["orchestrator", "run", "runtime_id=writer-cosmo-message"],
                }
            ]
        }

        with patch("scripts.verify_source_runtime_ecs._aws", return_value={"Targets": []}):
            self.assertEqual(
                _runtime_targets(
                    config,
                    ["writer-cosmo-message"],
                    "cerebro-go-production",
                    "us-east-1",
                    allow_missing_targets=True,
                ),
                [],
            )

    def test_runtime_targets_can_read_scheduler_target(self) -> None:
        config = {
            "orchestratorSchedules": [
                {
                    "name": "gcp-writer-iam-audit",
                    "backend": "scheduler",
                    "command": ["orchestrator", "run", "runtime_id=writer-gcp-prod-writer-iam-audit"],
                }
            ]
        }

        def fake_aws(args: list[str], _region: str) -> dict[str, object]:
            self.assertEqual(
                args,
                [
                    "scheduler",
                    "get-schedule",
                    "--group-name",
                    "cerebro-go-production-orchestrator",
                    "--name",
                    "cerebro-go-production-orchestrator-gcp-writer-iam-audit",
                ],
            )
            return {
                "Target": {
                    "Arn": "cluster",
                    "Input": "{\"containerOverrides\":[]}",
                    "EcsParameters": {
                        "TaskDefinitionArn": "task-definition",
                        "LaunchType": "FARGATE",
                        "NetworkConfiguration": {
                            "awsvpcConfiguration": {
                                "Subnets": ["subnet-1"],
                                "SecurityGroups": ["sg-1"],
                                "AssignPublicIp": "DISABLED",
                            }
                        },
                    },
                }
            }

        with patch("scripts.verify_source_runtime_ecs._aws", side_effect=fake_aws):
            targets = _runtime_targets(
                config,
                ["writer-gcp-prod-writer-iam-audit"],
                "cerebro-go-production",
                "us-east-1",
            )

        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].target["Arn"], "cluster")

    def test_runtime_targets_skip_disabled_schedule(self) -> None:
        config = {
            "orchestratorSchedules": [
                {
                    "name": "gcp-writer-iam-audit",
                    "backend": "scheduler",
                    "state": "DISABLED",
                    "command": ["orchestrator", "run", "runtime_id=writer-gcp-prod-writer-iam-audit"],
                }
            ]
        }

        with patch("scripts.verify_source_runtime_ecs._aws") as aws_call:
            targets = _runtime_targets(
                config,
                ["writer-gcp-prod-writer-iam-audit"],
                "cerebro-go-production",
                "us-east-1",
            )

        self.assertEqual(targets, [])
        aws_call.assert_not_called()

    def test_task_family_from_arn(self) -> None:
        self.assertEqual(
            _task_family("arn:aws:ecs:us-east-1:123456789012:task-definition/cerebro-sec-dev-orchestrator-cosmo-session:3"),
            "cerebro-sec-dev-orchestrator-cosmo-session",
        )

    def test_latest_active_task_definition_keeps_active_definition(self) -> None:
        task_definition = "arn:aws:ecs:us-east-1:123456789012:task-definition/runtime:3"
        with patch(
            "scripts.verify_source_runtime_ecs._aws",
            return_value={"taskDefinition": {"status": "ACTIVE", "taskDefinitionArn": task_definition}},
        ):
            self.assertEqual(_latest_active_task_definition(task_definition, "us-east-1"), task_definition)

    def test_latest_active_task_definition_replaces_inactive_definition(self) -> None:
        inactive = "arn:aws:ecs:us-east-1:123456789012:task-definition/runtime:3"
        active = "arn:aws:ecs:us-east-1:123456789012:task-definition/runtime:4"

        def fake_aws(args: list[str], _region: str) -> dict[str, object]:
            if args[:2] == ["ecs", "describe-task-definition"]:
                return {"taskDefinition": {"status": "INACTIVE", "family": "runtime"}}
            if args[:2] == ["ecs", "list-task-definitions"]:
                return {"taskDefinitionArns": [active]}
            raise AssertionError(f"unexpected args: {args}")

        with patch("scripts.verify_source_runtime_ecs._aws", side_effect=fake_aws):
            stderr = StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(_latest_active_task_definition(inactive, "us-east-1"), active)
            self.assertNotIn("123456789012", stderr.getvalue())
            self.assertNotIn("arn:aws", stderr.getvalue())

    def test_verification_command_overrides_runtime_limits(self) -> None:
        self.assertEqual(
            _verification_command("writer-cosmo-fact", 1, 2, 3),
            [
                "orchestrator",
                "run",
                "runtime_id=writer-cosmo-fact",
                "page_limit=1",
                "graph_page_limit=2",
                "event_limit=3",
            ],
        )

    def test_verification_command_is_empty_without_overrides(self) -> None:
        self.assertIsNone(_verification_command("writer-cosmo-fact", None, None, None))

    def test_run_task_applies_command_override(self) -> None:
        target = RuntimeTarget(
            runtime_id="writer-cosmo-fact",
            schedule_name="cosmo-fact",
            rule_name="cerebro-sec-dev-orchestrator-cosmo-fact",
            target={
                "Arn": "cluster",
                "EcsParameters": {
                    "TaskDefinitionArn": "arn:aws:ecs:us-east-1:123456789012:task-definition/runtime:3",
                    "LaunchType": "FARGATE",
                    "NetworkConfiguration": {
                        "awsvpcConfiguration": {
                            "Subnets": ["subnet-1"],
                            "SecurityGroups": ["sg-1"],
                            "AssignPublicIp": "DISABLED",
                        }
                    },
                },
            },
        )
        command = _verification_command("writer-cosmo-fact", 1, 1, 100) or []

        def fake_aws(args: list[str], _region: str) -> dict[str, object]:
            if args[:2] == ["ecs", "describe-task-definition"]:
                return {"taskDefinition": {"status": "ACTIVE", "taskDefinitionArn": target.target["EcsParameters"]["TaskDefinitionArn"]}}
            if args[:2] == ["ecs", "run-task"]:
                self.assertIn("--overrides", args)
                override = args[args.index("--overrides") + 1]
                self.assertIn('"command": ["orchestrator", "run", "runtime_id=writer-cosmo-fact", "page_limit=1", "graph_page_limit=1", "event_limit=100"]', override)
                return {"tasks": [{"taskArn": "task-arn"}]}
            raise AssertionError(f"unexpected args: {args}")

        with patch("scripts.verify_source_runtime_ecs._aws", side_effect=fake_aws):
            self.assertEqual(_run_task(target, "us-east-1", command), "task-arn")

    def test_run_task_can_scope_bootstrap_payload_to_observability_runtimes(self) -> None:
        target = RuntimeTarget(
            runtime_id="writer-panopticon-alerts",
            schedule_name="panopticon-alerts-live",
            rule_name="cerebro-sec-dev-orchestrator-panopticon-alerts-live",
            target={
                "Arn": "cluster",
                "EcsParameters": {
                    "TaskDefinitionArn": "arn:aws:ecs:us-east-1:123456789012:task-definition/runtime:3",
                    "LaunchType": "FARGATE",
                    "NetworkConfiguration": {
                        "awsvpcConfiguration": {
                            "Subnets": ["subnet-1"],
                            "SecurityGroups": ["sg-1"],
                            "AssignPublicIp": "DISABLED",
                        }
                    },
                },
            },
        )
        full_payload = json.dumps(
            {
                "runtimes": [
                    {"id": "writer-panopticon-alerts", "source_id": "panopticon", "config": {"token": "env:PANOPTICON_TOKEN"}},
                    {"id": "writer-cosmo-session", "source_id": "cosmo", "config": {"token": "env:COSMO_TOKEN"}},
                ]
            }
        )
        target.target["Input"] = json.dumps(
            {
                "containerOverrides": [
                    {"name": "cerebro", "command": ["orchestrator", "run", "runtime_id=writer-panopticon-alerts"]},
                    {
                        "name": "source-runtime-bootstrap",
                        "environment": [{"name": "CEREBRO_SOURCE_RUNTIME_BOOTSTRAP_JSON", "value": full_payload}],
                    },
                ]
            }
        )

        def fake_aws(args: list[str], _region: str) -> dict[str, object]:
            if args[:2] == ["ecs", "describe-task-definition"]:
                return {
                    "taskDefinition": {
                        "status": "ACTIVE",
                        "taskDefinitionArn": target.target["EcsParameters"]["TaskDefinitionArn"],
                        "containerDefinitions": [{"name": "source-runtime-bootstrap"}],
                    }
                }
            if args[:2] == ["ecs", "run-task"]:
                override = json.loads(args[args.index("--overrides") + 1])
                bootstrap_override = next(item for item in override["containerOverrides"] if item["name"] == "source-runtime-bootstrap")
                self.assertEqual(bootstrap_override["environmentFiles"], [])
                scoped_payload = json.loads(bootstrap_override["environment"][0]["value"])
                self.assertEqual([runtime["id"] for runtime in scoped_payload["runtimes"]], ["writer-panopticon-alerts"])
                self.assertNotIn("COSMO_TOKEN", json.dumps(scoped_payload))
                return {"tasks": [{"taskArn": "task-arn"}]}
            raise AssertionError(f"unexpected args: {args}")

        with patch("scripts.verify_source_runtime_ecs._aws", side_effect=fake_aws):
            self.assertEqual(
                _run_task(target, "us-east-1", bootstrap_runtime_ids=("writer-panopticon-alerts",)),
                "task-arn",
            )

    def test_run_task_uses_task_definition_payload_when_schedule_payload_is_too_narrow(self) -> None:
        target = RuntimeTarget(
            runtime_id="writer-aws-sec-dev-organizations-account",
            schedule_name="aws-sec-dev-organizati-178491",
            rule_name="cerebro-sec-dev-orchestrator-aws-sec-dev-organizati-178491",
            target={
                "Arn": "cluster",
                "EcsParameters": {
                    "TaskDefinitionArn": "arn:aws:ecs:us-east-1:123456789012:task-definition/runtime:3",
                    "LaunchType": "FARGATE",
                    "NetworkConfiguration": {
                        "awsvpcConfiguration": {
                            "Subnets": ["subnet-1"],
                            "SecurityGroups": ["sg-1"],
                            "AssignPublicIp": "DISABLED",
                        }
                    },
                },
            },
        )
        target.target["Input"] = json.dumps(
            {
                "containerOverrides": [
                    {
                        "name": "source-runtime-bootstrap",
                        "environment": [
                            {
                                "name": "CEREBRO_SOURCE_RUNTIME_BOOTSTRAP_JSON",
                                "value": json.dumps(
                                    {
                                        "runtimes": [
                                            {
                                                "id": "writer-aws-sec-dev-organizations-account",
                                                "source_id": "aws",
                                            }
                                        ]
                                    }
                                ),
                            }
                        ],
                    }
                ]
            }
        )
        task_definition_payload = json.dumps(
            {
                "runtimes": [
                    {"id": "writer-aws-sec-dev-organizations-account", "source_id": "aws"},
                    {"id": "writer-aws-sec-dev-organizations-policy", "source_id": "aws"},
                    {"id": "writer-aws-sec-dev-us1-cloudfront-distribution", "source_id": "aws"},
                ]
            }
        )

        def fake_aws(args: list[str], _region: str) -> dict[str, object]:
            if args[:2] == ["ecs", "describe-task-definition"]:
                return {
                    "taskDefinition": {
                        "status": "ACTIVE",
                        "taskDefinitionArn": target.target["EcsParameters"]["TaskDefinitionArn"],
                        "containerDefinitions": [
                            {
                                "name": "source-runtime-bootstrap",
                                "environment": [
                                    {
                                        "name": "CEREBRO_SOURCE_RUNTIME_BOOTSTRAP_JSON",
                                        "value": task_definition_payload,
                                    }
                                ],
                            }
                        ],
                    }
                }
            if args[:2] == ["ecs", "run-task"]:
                override = json.loads(args[args.index("--overrides") + 1])
                bootstrap_override = next(item for item in override["containerOverrides"] if item["name"] == "source-runtime-bootstrap")
                scoped_payload = json.loads(bootstrap_override["environment"][0]["value"])
                self.assertEqual(
                    [runtime["id"] for runtime in scoped_payload["runtimes"]],
                    [
                        "writer-aws-sec-dev-organizations-account",
                        "writer-aws-sec-dev-organizations-policy",
                    ],
                )
                return {"tasks": [{"taskArn": "task-arn"}]}
            raise AssertionError(f"unexpected args: {args}")

        with patch("scripts.verify_source_runtime_ecs._aws", side_effect=fake_aws):
            self.assertEqual(
                _run_task(
                    target,
                    "us-east-1",
                    bootstrap_runtime_ids=(
                        "writer-aws-sec-dev-organizations-account",
                        "writer-aws-sec-dev-organizations-policy",
                    ),
                ),
                "task-arn",
            )

    def test_stop_running_tasks_stops_and_waits_for_runtime_family(self) -> None:
        target = RuntimeTarget(
            runtime_id="writer-cosmo-fact",
            schedule_name="cosmo-fact",
            rule_name="cerebro-sec-dev-orchestrator-cosmo-fact",
            target={
                "Arn": "cluster",
                "EcsParameters": {
                    "TaskDefinitionArn": "arn:aws:ecs:us-east-1:123456789012:task-definition/runtime:3",
                    "NetworkConfiguration": {
                        "awsvpcConfiguration": {
                            "Subnets": ["subnet-1"],
                            "SecurityGroups": ["sg-1"],
                        }
                    },
                },
            },
        )
        calls = []

        def fake_aws(args: list[str], _region: str) -> dict[str, object]:
            calls.append(args)
            if args[:2] == ["ecs", "list-tasks"]:
                self.assertIn("--desired-status", args)
                self.assertIn("RUNNING", args)
                self.assertIn("--family", args)
                self.assertIn("runtime", args)
                return {"taskArns": ["task-1"]}
            if args[:2] == ["ecs", "stop-task"]:
                self.assertIn("--reason", args)
                return {"task": {"taskArn": "task-1"}}
            if args[:2] == ["ecs", "describe-tasks"]:
                return {
                    "tasks": [
                        {
                            "taskArn": "task-1",
                            "taskDefinitionArn": "arn:aws:ecs:us-east-1:123456789012:task-definition/runtime:3",
                            "lastStatus": "STOPPED",
                        }
                    ]
                }
            raise AssertionError(f"unexpected args: {args}")

        with patch("scripts.verify_source_runtime_ecs._aws", side_effect=fake_aws):
            _stop_running_tasks(target, "us-east-1", "test cleanup", 10, 1)

        self.assertEqual(
            [call[:2] for call in calls],
            [["ecs", "list-tasks"], ["ecs", "describe-tasks"], ["ecs", "stop-task"], ["ecs", "describe-tasks"]],
        )

    def test_shared_orchestrator_target_filters_tasks_by_command_override(self) -> None:
        target = RuntimeTarget(
            runtime_id="writer-cosmo-fact",
            schedule_name="cosmo-fact",
            rule_name="cerebro-sec-dev-orchestrator-cosmo-fact",
            target={
                "Arn": "cluster",
                "Input": '{"containerOverrides":[{"name":"cerebro","command":["orchestrator","run","runtime_id=writer-cosmo-fact"]}]}',
                "EcsParameters": {
                    "TaskDefinitionArn": "arn:aws:ecs:us-east-1:123456789012:task-definition/cerebro-sec-dev-orchestrator:3"
                },
            },
        )
        now = time.time()
        matching_task = {
            "taskArn": "task-match",
            "taskDefinitionArn": "arn:aws:ecs:us-east-1:123456789012:task-definition/cerebro-sec-dev-orchestrator:3",
            "lastStatus": "STOPPED",
            "stoppedAt": now,
            "overrides": {"containerOverrides": [{"name": "cerebro", "command": ["orchestrator", "run", "runtime_id=writer-cosmo-fact"]}]},
        }
        other_task = {
            "taskArn": "task-other",
            "taskDefinitionArn": "arn:aws:ecs:us-east-1:123456789012:task-definition/cerebro-sec-dev-orchestrator:3",
            "lastStatus": "STOPPED",
            "stoppedAt": now,
            "overrides": {"containerOverrides": [{"name": "cerebro", "command": ["orchestrator", "run", "runtime_id=writer-cosmo-session"]}]},
        }

        def fake_aws(args: list[str], _region: str) -> dict[str, object]:
            if args[:2] == ["ecs", "list-tasks"]:
                self.assertEqual(args[args.index("--max-results") + 1], "100")
                return {"taskArns": ["task-other", "task-match"]}
            if args[:2] == ["ecs", "describe-tasks"]:
                return {"tasks": [other_task, matching_task]}
            raise AssertionError(f"unexpected args: {args}")

        with patch("scripts.verify_source_runtime_ecs._aws", side_effect=fake_aws):
            self.assertEqual(_latest_task(target, 60, "us-east-1"), "task-match")

    def test_runtime_skip_reason_is_retryable_for_lease_contention(self) -> None:
        span = {"status": "skipped", "reason": "lease_not_acquired"}

        self.assertEqual(_runtime_skip_reason(span), "lease_not_acquired")
        self.assertTrue(_runtime_skip_retryable(_runtime_skip_reason(span)))

    def test_runtime_skip_reason_is_not_retryable_for_unknown_skip(self) -> None:
        span = {"status": "skipped", "reason": "disabled"}

        self.assertEqual(_runtime_skip_reason(span), "disabled")
        self.assertFalse(_runtime_skip_retryable(_runtime_skip_reason(span)))

    def test_run_verify_allows_lease_contention_skip(self) -> None:
        target = RuntimeTarget(
            runtime_id="writer-cosmo-fact",
            schedule_name="cosmo-fact",
            rule_name="cerebro-sec-dev-orchestrator-cosmo-fact",
            target={"Arn": "cluster"},
        )

        with (
            patch("scripts.verify_source_runtime_ecs._run_task", return_value="task-arn"),
            patch("scripts.verify_source_runtime_ecs._wait_for_task"),
            patch(
                "scripts.verify_source_runtime_ecs._verify_task",
                side_effect=RuntimeSkippedError("writer-cosmo-fact", "task-arn", "lease_not_acquired"),
            ),
        ):
            result = _run_and_verify_task_with_retries(
                target,
                wait_timeout_seconds=60,
                poll_seconds=10,
                region="us-east-1",
                allow_lease_contention_skip=True,
            )

        self.assertEqual(result.runtime_id, "writer-cosmo-fact")
        self.assertEqual(result.runtime_status, "skipped")
        self.assertEqual(result.sync_status, "skipped")
        self.assertEqual(result.graph_ingest_status, "skipped")

    def test_run_verify_retries_failed_task_within_budget(self) -> None:
        target = RuntimeTarget(
            runtime_id="writer-cosmo-fact",
            schedule_name="cosmo-fact",
            rule_name="cerebro-sec-dev-orchestrator-cosmo-fact",
            target={"Arn": "cluster"},
        )
        verified = VerificationResult(
            runtime_id="writer-cosmo-fact",
            task_arn="task-2",
            exit_code=0,
            runtime_status="completed",
            sync_status="completed",
            graph_ingest_status="completed",
            events_appended=1,
            pages_read=1,
        )

        with (
            patch("scripts.verify_source_runtime_ecs.time.time", return_value=0),
            patch("scripts.verify_source_runtime_ecs.time.sleep"),
            patch("scripts.verify_source_runtime_ecs._run_task", side_effect=["task-1", "task-2"]) as run_task,
            patch("scripts.verify_source_runtime_ecs._wait_for_task"),
            patch(
                "scripts.verify_source_runtime_ecs._verify_task",
                side_effect=[RuntimeTaskFailedError("writer-cosmo-fact", "task-1", 1, "timeout"), verified],
            ),
        ):
            result = _run_and_verify_task_with_retries(
                target,
                wait_timeout_seconds=100,
                poll_seconds=10,
                region="us-east-1",
                failed_run_retry_seconds=60,
            )

        self.assertEqual(result, verified)
        self.assertEqual(run_task.call_count, 2)

    def test_run_verify_retries_runtime_verification_failure_within_budget(self) -> None:
        target = RuntimeTarget(
            runtime_id="writer-cosmo-session",
            schedule_name="cosmo-session",
            rule_name="cerebro-sec-dev-orchestrator-cosmo-session",
            target={"Arn": "cluster"},
        )
        verified = VerificationResult(
            runtime_id="writer-cosmo-session",
            task_arn="task-2",
            exit_code=0,
            runtime_status="completed",
            sync_status="completed",
            graph_ingest_status="completed",
            events_appended=1,
            pages_read=1,
        )

        with (
            patch("scripts.verify_source_runtime_ecs.time.time", return_value=0),
            patch("scripts.verify_source_runtime_ecs.time.sleep"),
            patch("scripts.verify_source_runtime_ecs._run_task", side_effect=["task-1", "task-2"]) as run_task,
            patch(
                "scripts.verify_source_runtime_ecs._verify_task_until_graph_ingested",
                side_effect=[RuntimeVerificationFailedError("writer-cosmo-session", "task-1", "source sync", "failed"), verified],
            ),
        ):
            result = _run_and_verify_task_with_retries(
                target,
                wait_timeout_seconds=100,
                poll_seconds=10,
                region="us-east-1",
                failed_run_retry_seconds=60,
                succeed_after_graph_ingest=True,
            )

        self.assertEqual(result, verified)
        self.assertEqual(run_task.call_count, 2)

    def test_run_verify_can_succeed_after_graph_ingest_before_task_stops(self) -> None:
        target = RuntimeTarget(
            runtime_id="writer-aws-devops-iam-role-trust",
            schedule_name="aws-devops-iam-role-trust",
            rule_name="cerebro-go-production-orchestrator-aws-devops-iam-role-trust",
            target={"Arn": "cluster"},
        )
        messages = [
            {
                "kind": "span_end",
                "name": "source_runtime.sync",
                "status": "completed",
                "events_appended": 12,
                "pages_read": 1,
            },
            {
                "kind": "span_end",
                "name": "graph.ingest_runtime",
                "status": "completed",
                "entities_projected": 367,
                "links_projected": 474,
            },
            {
                "kind": "span_end",
                "name": "orchestrator.graph_ingest",
                "status": "completed",
            },
        ]

        with (
            patch("scripts.verify_source_runtime_ecs._run_task", return_value="task-arn"),
            patch(
                "scripts.verify_source_runtime_ecs._describe_tasks",
                return_value=[{"taskArn": "task-arn", "lastStatus": "RUNNING", "containers": [{"name": "cerebro"}]}],
            ),
            patch("scripts.verify_source_runtime_ecs._task_logs", return_value=messages),
            patch("scripts.verify_source_runtime_ecs._wait_for_task") as wait_for_task,
        ):
            result = _run_and_verify_task_with_retries(
                target,
                wait_timeout_seconds=100,
                poll_seconds=10,
                region="us-east-1",
                succeed_after_graph_ingest=True,
            )

        self.assertEqual(result.runtime_status, "running")
        self.assertEqual(result.sync_status, "completed")
        self.assertEqual(result.graph_ingest_status, "completed")
        self.assertEqual(result.events_appended, 12)
        self.assertEqual(result.pages_read, 1)
        self.assertEqual(result.entities_projected, 367)
        self.assertEqual(result.links_projected, 474)
        wait_for_task.assert_not_called()

    def test_run_verify_can_succeed_after_graph_ingest_when_task_stopped_without_runtime_span(self) -> None:
        target = RuntimeTarget(
            runtime_id="writer-panopticon-alerts",
            schedule_name="panopticon-alerts-live",
            rule_name="cerebro-sec-dev-orchestrator-panopticon-alerts-live",
            target={"Arn": "cluster"},
        )
        messages = [
            {
                "kind": "span_end",
                "name": "source_runtime.sync",
                "status": "completed",
                "events_appended": 2,
                "pages_read": 1,
            },
            {
                "kind": "span_end",
                "name": "orchestrator.graph_ingest",
                "status": "completed",
                "entities_projected": 2,
                "links_projected": 1,
            },
        ]

        with (
            patch("scripts.verify_source_runtime_ecs._run_task", return_value="task-arn"),
            patch(
                "scripts.verify_source_runtime_ecs._describe_tasks",
                return_value=[{"taskArn": "task-arn", "lastStatus": "STOPPED", "containers": [{"name": "cerebro", "exitCode": 0}]}],
            ),
            patch("scripts.verify_source_runtime_ecs._task_logs", return_value=messages),
            patch("scripts.verify_source_runtime_ecs._verify_task") as verify_task,
        ):
            result = _run_and_verify_task_with_retries(
                target,
                wait_timeout_seconds=100,
                poll_seconds=10,
                region="us-east-1",
                succeed_after_graph_ingest=True,
            )

        self.assertEqual(result.runtime_status, "running")
        self.assertEqual(result.sync_status, "completed")
        self.assertEqual(result.graph_ingest_status, "completed")
        verify_task.assert_not_called()

    def test_verify_runtime_targets_parallel_preserves_result_order(self) -> None:
        targets = [
            RuntimeTarget(runtime_id=f"runtime-{index}", schedule_name=f"runtime-{index}", rule_name=f"rule-{index}", target={"Arn": "cluster"})
            for index in range(3)
        ]
        active = 0
        max_active = 0
        lock = threading.Lock()

        def fake_verify(target: RuntimeTarget, _options: VerificationOptions) -> VerificationResult:
            nonlocal active, max_active
            with lock:
                active += 1
                max_active = max(max_active, active)
            try:
                time.sleep(0.02)
                return VerificationResult(
                    runtime_id=target.runtime_id,
                    task_arn=f"{target.runtime_id}-task",
                    exit_code=0,
                    runtime_status="completed",
                    sync_status="completed",
                    graph_ingest_status="completed",
                    events_appended=1,
                    pages_read=1,
                )
            finally:
                with lock:
                    active -= 1

        with patch("scripts.verify_source_runtime_ecs._verify_runtime_target", side_effect=fake_verify):
            results = _verify_runtime_targets(targets, VerificationOptions(), target_concurrency=2)

        self.assertEqual([result.runtime_id for result in results], ["runtime-0", "runtime-1", "runtime-2"])
        self.assertEqual(max_active, 2)

    def test_verify_runtime_target_scopes_bootstrap_to_current_runtime(self) -> None:
        target = RuntimeTarget(
            runtime_id="runtime-1",
            schedule_name="runtime-1",
            rule_name="runtime-1",
            target={"Arn": "cluster"},
        )
        verified = VerificationResult(
            runtime_id="runtime-1",
            task_arn="task-1",
            exit_code=0,
            runtime_status="completed",
            sync_status="completed",
            graph_ingest_status="completed",
            events_appended=1,
            pages_read=1,
        )

        def fake_run_and_verify(*args):
            self.assertEqual(args[-1], ("runtime-1",))
            return verified

        options = VerificationOptions(run=True, bootstrap_runtime_ids=("runtime-1", "runtime-2"))
        with patch("scripts.verify_source_runtime_ecs._run_and_verify_task_with_retries", side_effect=fake_run_and_verify):
            self.assertEqual(_verify_runtime_target(target, options), verified)

    def test_run_verify_stops_and_retries_timed_out_attempt(self) -> None:
        target = RuntimeTarget(
            runtime_id="writer-cosmo-fact",
            schedule_name="cosmo-fact",
            rule_name="cerebro-sec-dev-orchestrator-cosmo-fact",
            target={"Arn": "cluster"},
        )
        verified = VerificationResult(
            runtime_id="writer-cosmo-fact",
            task_arn="task-2",
            exit_code=0,
            runtime_status="completed",
            sync_status="completed",
            graph_ingest_status="completed",
            events_appended=1,
            pages_read=1,
        )

        with (
            patch("scripts.verify_source_runtime_ecs.time.time", return_value=0),
            patch("scripts.verify_source_runtime_ecs.time.sleep"),
            patch("scripts.verify_source_runtime_ecs._run_task", side_effect=["task-1", "task-2"]) as run_task,
            patch("scripts.verify_source_runtime_ecs._wait_for_task", side_effect=[TimeoutError("attempt timed out"), None]) as wait_for_task,
            patch("scripts.verify_source_runtime_ecs._stop_task") as stop_task,
            patch("scripts.verify_source_runtime_ecs._verify_task", return_value=verified),
        ):
            result = _run_and_verify_task_with_retries(
                target,
                wait_timeout_seconds=100,
                poll_seconds=10,
                region="us-east-1",
                failed_run_retry_seconds=60,
                run_attempt_timeout_seconds=30,
            )

        self.assertEqual(result, verified)
        self.assertEqual(run_task.call_count, 2)
        wait_for_task.assert_any_call("cluster", "task-1", 30, 10, "us-east-1")
        stop_task.assert_called_once()

    def test_verify_task_reports_graph_projection_counts(self) -> None:
        target = RuntimeTarget(
            runtime_id="writer-aws-public",
            schedule_name="aws-public",
            rule_name="cerebro-sec-dev-orchestrator-aws-public",
            target={"Arn": "cluster"},
        )
        task = {
            "taskArn": "task-arn",
            "taskDefinitionArn": "task-def",
            "containers": [{"name": "cerebro", "exitCode": 0}],
        }
        messages = [
            {"kind": "span_end", "name": "orchestrator.runtime", "status": "completed"},
            {"kind": "span_end", "name": "source_runtime.sync", "status": "completed", "events_appended": 7, "pages_read": 2},
            {
                "kind": "span_end",
                "name": "orchestrator.graph_ingest",
                "status": "completed",
                "entities_projected": 5,
                "links_projected": 3,
            },
        ]

        with (
            patch("scripts.verify_source_runtime_ecs._describe_tasks", return_value=[task]),
            patch("scripts.verify_source_runtime_ecs._task_logs", return_value=messages),
        ):
            result = _verify_task(target, "task-arn", "us-east-1")

        self.assertEqual(result.events_appended, 7)
        self.assertEqual(result.pages_read, 2)
        self.assertEqual(result.entities_projected, 5)
        self.assertEqual(result.links_projected, 3)

    def test_verify_task_fails_closed_for_contract_probe_failure(self) -> None:
        target = RuntimeTarget(
            runtime_id="writer-evidence-cas-cases",
            schedule_name="evidence-cas-cases",
            rule_name="cerebro-sec-dev-orchestrator-evidence-cas-cases",
            target={"Arn": "cluster"},
        )
        messages = [
            {"kind": "span_end", "name": "orchestrator.runtime", "status": "completed"},
            {"kind": "span_end", "name": "source_runtime.sync", "status": "completed", "events_appended": 1, "pages_read": 1},
            {"kind": "event", "name": "source_runtime.contract_probe", "contract_probe_status": "failure"},
            {"kind": "span_end", "name": "orchestrator.graph_ingest", "status": "completed"},
        ]

        with self.assertRaisesRegex(RuntimeVerificationFailedError, "contract probe status is failure"):
            _verification_result_from_logs(target, "arn:aws:ecs:us-east-1:123456789012:task/cluster/task-1", 0, messages, True)

    def test_verify_task_fails_closed_for_orphan_missing_link_state(self) -> None:
        target = RuntimeTarget(
            runtime_id="writer-evidence-cas-cases",
            schedule_name="evidence-cas-cases",
            rule_name="cerebro-sec-dev-orchestrator-evidence-cas-cases",
            target={"Arn": "cluster"},
        )
        messages = [
            {"kind": "span_end", "name": "orchestrator.runtime", "status": "completed"},
            {"kind": "span_end", "name": "source_runtime.sync", "status": "completed", "events_appended": 1, "pages_read": 1},
            {"kind": "event", "name": "runtime.evidence.link_status", "link_status": "missing_resource"},
            {"kind": "span_end", "name": "orchestrator.graph_ingest", "status": "completed"},
        ]

        with self.assertRaisesRegex(RuntimeVerificationFailedError, "link status is missing_resource"):
            _verification_result_from_logs(target, "arn:aws:ecs:us-east-1:123456789012:task/cluster/task-1", 0, messages, True)

    def test_verify_task_fails_closed_for_zero_discovered_runtimes(self) -> None:
        target = RuntimeTarget(
            runtime_id="writer-panopticon-alerts",
            schedule_name="panopticon-alerts-live",
            rule_name="cerebro-sec-dev-orchestrator-panopticon-alerts-live",
            target={"Arn": "cluster"},
        )
        messages = [
            {"kind": "span_start", "name": "orchestrator.run", "runtime_id": "writer-panopticon-alerts"},
            {"kind": "event", "name": "orchestrator.runtimes_listed", "runtime_count": 0},
            {"kind": "span_end", "name": "orchestrator.iteration", "status": "completed", "runtimes_attempted": 0},
            {"kind": "span_end", "name": "orchestrator.run", "status": "completed"},
        ]

        with self.assertRaisesRegex(RuntimeVerificationFailedError, "runtime discovery status is missing"):
            _verification_result_from_logs(target, "arn:aws:ecs:us-east-1:123456789012:task/cluster/task-1", 0, messages, True)

    def test_verify_task_includes_ecs_stop_reason_when_logs_missing(self) -> None:
        target = RuntimeTarget(
            runtime_id="writer-cosmo-session",
            schedule_name="cosmo-session",
            rule_name="cerebro-go-production-orchestrator-cosmo-session",
            target={"Arn": "cluster"},
        )
        task = {
            "taskArn": "task-arn",
            "taskDefinitionArn": "task-def",
            "stopCode": "TaskFailedToStart",
            "stoppedReason": "ResourceInitializationError: unable to pull secrets",
            "containers": [
                {
                    "name": "cerebro",
                    "lastStatus": "STOPPED",
                    "exitCode": 1,
                    "reason": "secret cerebro-go-production/MISSING was not found",
                }
            ],
        }

        with (
            patch("scripts.verify_source_runtime_ecs._describe_tasks", return_value=[task]),
            patch("scripts.verify_source_runtime_ecs._task_logs", side_effect=RuntimeError("log stream missing")),
        ):
            with self.assertRaises(RuntimeTaskFailedError) as context:
                _verify_task(target, "arn:aws:ecs:us-east-1:123456789012:task/cluster/task-arn", "us-east-1")

        message = str(context.exception)
        self.assertIn("ResourceInitializationError", message)
        self.assertNotIn("123456789012", message)
        self.assertNotIn("arn:aws", message)
        self.assertNotIn("cerebro-go-production/MISSING", message)

    def test_verify_task_includes_ecs_stop_reason_when_logs_empty(self) -> None:
        target = RuntimeTarget(
            runtime_id="writer-panopticon-cases",
            schedule_name="panopticon-cases-live",
            rule_name="cerebro-sec-dev-orchestrator-panopticon-cases-live",
            target={"Arn": "cluster"},
        )
        task = {
            "taskArn": "arn:aws:ecs:us-east-1:123456789012:task/cluster/task-arn",
            "taskDefinitionArn": "task-def",
            "stopCode": "TaskFailedToStart",
            "stoppedReason": "CannotStartContainerError: bootstrap dependency did not complete",
            "containers": [
                {"name": "source-runtime-bootstrap", "lastStatus": "STOPPED", "exitCode": 1},
                {"name": "cerebro", "lastStatus": "STOPPED"},
            ],
        }

        with (
            patch("scripts.verify_source_runtime_ecs._describe_tasks", return_value=[task]),
            patch("scripts.verify_source_runtime_ecs._task_logs", return_value=[]),
        ):
            with self.assertRaises(RuntimeTaskFailedError) as context:
                _verify_task(target, "arn:aws:ecs:us-east-1:123456789012:task/cluster/task-arn", "us-east-1")

        message = str(context.exception)
        self.assertIn("CannotStartContainerError", message)
        self.assertIn("source-runtime-bootstrap", message)
        self.assertNotIn("123456789012", message)
        self.assertNotIn("arn:aws", message)

    def test_verify_task_includes_bootstrap_logs_when_bootstrap_fails(self) -> None:
        target = RuntimeTarget(
            runtime_id="writer-panopticon-alerts",
            schedule_name="panopticon-alerts-live",
            rule_name="cerebro-sec-dev-orchestrator-panopticon-alerts-live",
            target={"Arn": "cluster"},
        )
        task = {
            "taskArn": "arn:aws:ecs:us-east-1:123456789012:task/cluster/task-arn",
            "taskDefinitionArn": "task-def",
            "stopCode": "TaskFailedToStart",
            "stoppedReason": "Task failed to start",
            "containers": [
                {"name": "source-runtime-bootstrap", "lastStatus": "STOPPED", "exitCode": 1},
                {"name": "cerebro", "lastStatus": "STOPPED"},
            ],
        }

        def fake_task_logs(_task, _region, cache=None, container_name="cerebro"):
            if container_name == "source-runtime-bootstrap":
                return [
                    {
                        "kind": "event",
                        "name": "source_runtime.bootstrap",
                        "status": "failed",
                        "reason": "runtime state bootstrap failed",
                        "secret": "do-not-print",
                    }
                ]
            return []

        with (
            patch("scripts.verify_source_runtime_ecs._describe_tasks", return_value=[task]),
            patch("scripts.verify_source_runtime_ecs._task_logs", side_effect=fake_task_logs),
        ):
            with self.assertRaises(RuntimeTaskFailedError) as context:
                _verify_task(target, "arn:aws:ecs:us-east-1:123456789012:task/cluster/task-arn", "us-east-1")

        message = str(context.exception)
        self.assertIn("source-runtime-bootstrap logs", message)
        self.assertIn("source_runtime.bootstrap", message)
        self.assertIn("runtime state bootstrap failed", message)
        self.assertNotIn("do-not-print", message)
        self.assertNotIn("123456789012", message)
        self.assertNotIn("arn:aws", message)

    def test_verify_task_includes_raw_bootstrap_logs_when_structured_logs_empty(self) -> None:
        target = RuntimeTarget(
            runtime_id="writer-panopticon-alerts",
            schedule_name="panopticon-alerts-live",
            rule_name="cerebro-sec-dev-orchestrator-panopticon-alerts-live",
            target={"Arn": "cluster"},
        )
        task = {
            "taskArn": "arn:aws:ecs:us-east-1:123456789012:task/cluster/task-arn",
            "taskDefinitionArn": "task-def",
            "stopCode": "TaskFailedToStart",
            "stoppedReason": "Task failed to start",
            "containers": [
                {"name": "source-runtime-bootstrap", "lastStatus": "STOPPED", "exitCode": 1},
                {"name": "cerebro", "lastStatus": "STOPPED"},
            ],
        }

        def fake_raw_task_logs(_task, _region, cache=None, container_name="cerebro"):
            if container_name == "source-runtime-bootstrap":
                return ["bootstrap failed for arn:aws:ecs:us-east-1:123456789012:task/cluster/task-arn secret=do-not-print"]
            return []

        with (
            patch("scripts.verify_source_runtime_ecs._describe_tasks", return_value=[task]),
            patch("scripts.verify_source_runtime_ecs._task_logs", return_value=[]),
            patch("scripts.verify_source_runtime_ecs._raw_task_log_messages", side_effect=fake_raw_task_logs),
        ):
            with self.assertRaises(RuntimeTaskFailedError) as context:
                _verify_task(target, "arn:aws:ecs:us-east-1:123456789012:task/cluster/task-arn", "us-east-1")

        message = str(context.exception)
        self.assertIn("source-runtime-bootstrap raw logs", message)
        self.assertIn("bootstrap failed", message)
        self.assertNotIn("do-not-print", message)
        self.assertNotIn("123456789012", message)
        self.assertNotIn("arn:aws", message)

    def test_task_logs_caches_log_options_by_task_definition(self) -> None:
        task = {
            "taskArn": "arn:aws:ecs:us-east-1:123:task/cluster/task-1",
            "taskDefinitionArn": "arn:aws:ecs:us-east-1:123:task-definition/runtime:4",
        }
        describe_calls = 0

        def fake_aws(args: list[str], _region: str) -> dict[str, object]:
            nonlocal describe_calls
            if args[:2] == ["ecs", "describe-task-definition"]:
                describe_calls += 1
                return {
                    "taskDefinition": {
                        "containerDefinitions": [
                            {
                                "name": "cerebro",
                                "logConfiguration": {
                                    "options": {
                                        "awslogs-group": "/ecs/cerebro",
                                        "awslogs-stream-prefix": "runtime",
                                    }
                                },
                            }
                        ]
                    }
                }
            if args[:2] == ["logs", "get-log-events"]:
                return {"events": [{"message": '{"kind":"span_end","name":"source_runtime.sync"}'}]}
            raise AssertionError(f"unexpected args: {args}")

        cache = {}
        with patch("scripts.verify_source_runtime_ecs._aws", side_effect=fake_aws):
            self.assertEqual(len(_task_logs(task, "us-east-1", cache)), 1)
            self.assertEqual(len(_task_logs(task, "us-east-1", cache)), 1)

        self.assertEqual(describe_calls, 1)

    def test_summarize_log_messages_limits_fields_and_length(self) -> None:
        summary = _summarize_log_messages(
            [
                {"message": "old"},
                {"level": "error", "message": "x" * 2500, "entities_projected": 0, "links_projected": 0, "secret": "not included"},
            ],
            limit=1,
        )

        self.assertIn('"level": "error"', summary)
        self.assertIn('"entities_projected": 0', summary)
        self.assertIn('"links_projected": 0', summary)
        self.assertIn('"message": "', summary)
        self.assertNotIn("secret", summary)
        self.assertLessEqual(len(summary), 2000)

    def test_sanitize_text_redacts_sensitive_cloud_identifiers(self) -> None:
        sanitized = _sanitize_text(
            "arn:aws:ecs:us-east-1:123456789012:task/cluster/task-1 https://internal.example.com secret CEREBRO_TOKEN was not found RequestID: 2481eecc-b737-4f24-ac03-e450485270a4"
        )

        self.assertNotIn("arn:aws", sanitized)
        self.assertNotIn("123456789012", sanitized)
        self.assertNotIn("internal.example.com", sanitized)
        self.assertNotIn("CEREBRO_TOKEN", sanitized)
        self.assertNotIn("2481eecc", sanitized)
        self.assertIn("[redacted-arn]", sanitized)

    def test_dry_run_reports_planned_observability_checks_without_running_tasks(self) -> None:
        stack_file = Path("aws/Pulumi.sec-dev.yaml")
        config = {
            "environment": "sec-dev",
            "sourceRuntimeObservability": [
                {
                    "sourceSystem": "panopticon",
                    "sourceRuntimeId": "writer-panopticon-alerts",
                    "runtimeClass": "alert",
                    "enabled": True,
                    "freshnessSlaMinutes": 30,
                }
            ],
            "orchestratorSchedules": [
                {
                    "name": "panopticon-alerts-live",
                    "command": ["orchestrator", "run", "runtime_id=writer-panopticon-alerts"],
                }
            ],
        }
        targets = [
            RuntimeTarget(
                runtime_id="writer-panopticon-alerts",
                schedule_name="panopticon-alerts-live",
                rule_name="cerebro-sec-dev-orchestrator-panopticon-alerts-live",
                target={"Arn": "cluster", "EcsParameters": {"TaskDefinitionArn": "task-def"}},
            )
        ]

        stdout = StringIO()
        stderr = StringIO()
        with (
            patch("scripts.verify_source_runtime_ecs._load_config", return_value=config),
            patch("scripts.verify_source_runtime_ecs._verify_account") as verify_account,
            patch("scripts.verify_source_runtime_ecs._runtime_targets", return_value=targets),
            patch("scripts.verify_source_runtime_ecs._run_task") as run_task,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            status = main(
                [
                    "--stack-file",
                    str(stack_file),
                    "--source-id",
                    "panopticon",
                    "--family",
                    "alert",
                    "--observability-targets",
                    "--dry-run",
                    "--run-page-limit",
                    "1",
                    "--run-graph-page-limit",
                    "2",
                    "--run-event-limit",
                    "3",
                    "--wait-timeout-seconds",
                    "300",
                    "--poll-seconds",
                    "5",
                    "--target-concurrency",
                    "2",
                ]
            )

        self.assertEqual(status, 0)
        verify_account.assert_called_once()
        run_task.assert_not_called()
        output = stdout.getvalue()
        self.assertIn("mode\tread_only_dry_run", output)
        self.assertIn("mutations\tnone", output)
        self.assertIn("writer-panopticon-alerts", output)
        self.assertIn("wait_timeout_seconds\t300", output)
        self.assertIn("run_page_limit\t1", output)
        self.assertIn("run_graph_page_limit\t2", output)
        self.assertIn("run_event_limit\t3", output)
        self.assertIn("allow_missing_targets\tfalse", output)

    def test_go_prod_panopticon_observability_can_run_live_api_tasks(self) -> None:
        stack_file = Path("aws/Pulumi.go-prod.yaml")
        config = {
            "environment": "go-production",
            "sourceRuntimeObservability": [
                {
                    "sourceSystem": "panopticon",
                    "sourceRuntimeId": "writer-panopticon-alerts",
                    "runtimeClass": "alert",
                    "enabled": True,
                    "freshnessSlaMinutes": 30,
                }
            ],
            "sourceRuntimes": [
                {
                    "id": "writer-panopticon-alerts",
                    "sourceId": "panopticon",
                    "config": {
                        "base_url": "env:CEREBRO_SOURCE_PANOPTICON_BASE_URL",
                        "family": "alert",
                        "mode": "api",
                        "token": "env:CEREBRO_SOURCE_PANOPTICON_TOKEN",
                    },
                }
            ],
        }
        target = RuntimeTarget(
            runtime_id="writer-panopticon-alerts",
            schedule_name="panopticon-alerts-live",
            rule_name="cerebro-go-production-orchestrator-panopticon-alerts-live",
            target={"Arn": "arn:aws:ecs:us-east-1:123456789012:cluster/cerebro"},
        )
        result = VerificationResult(
            runtime_id="writer-panopticon-alerts",
            task_arn="task-arn",
            exit_code=0,
            runtime_status="completed",
            sync_status="completed",
            graph_ingest_status="completed",
            events_appended=1,
            pages_read=1,
            entities_projected=1,
            links_projected=1,
        )

        with (
            patch("scripts.verify_source_runtime_ecs._load_config", return_value=config),
            patch("scripts.verify_source_runtime_ecs._verify_account") as verify_account,
            patch("scripts.verify_source_runtime_ecs._runtime_targets", return_value=[target]) as runtime_targets,
            patch("scripts.verify_source_runtime_ecs._verify_bootstrap_payload_targets") as verify_bootstrap,
            patch("scripts.verify_source_runtime_ecs._verify_secret_import_preflight") as verify_secrets,
            patch("scripts.verify_source_runtime_ecs._verify_runtime_targets", return_value=[result]) as verify_targets,
        ):
            status = main(
                [
                    "--stack-file",
                    str(stack_file),
                    "--source-id",
                    "panopticon",
                    "--observability-targets",
                    "--run",
                ]
            )

        self.assertEqual(status, 0)
        verify_account.assert_called_once()
        runtime_targets.assert_called_once()
        verify_bootstrap.assert_called_once_with([target], "us-east-1")
        verify_secrets.assert_called_once()
        verify_targets.assert_called_once()
        self.assertTrue(verify_targets.call_args.args[1].run)

    def test_run_fails_secret_import_preflight_before_starting_tasks(self) -> None:
        stack_file = Path("aws/Pulumi.sec-dev.yaml")
        config = {
            "environment": "sec-dev",
            "sourceRuntimes": [
                {
                    "id": "aws-public",
                    "sourceId": "aws",
                    "config": {
                        "family": "public_endpoint",
                        "base_url": "env:EVIDENCE_CAS_BASE_URL",
                        "token": "env:EVIDENCE_CAS_TOKEN",
                    },
                }
            ],
        }
        targets = [
            RuntimeTarget(
                runtime_id="aws-public",
                schedule_name="aws-public-live",
                rule_name="cerebro-sec-dev-orchestrator-aws-public-live",
                target={"Arn": "cluster", "EcsParameters": {"TaskDefinitionArn": "task-def"}},
            )
        ]
        findings = [
            SecretImportPreflightFinding(
                env_name="EVIDENCE_CAS_BASE_URL",
                key_path="cerebro-sec-dev/EVIDENCE_CAS_BASE_URL",
                category="runtime-import",
                reason="missing",
            ),
            SecretImportPreflightFinding(
                env_name="EVIDENCE_CAS_TOKEN",
                key_path="cerebro-sec-dev/EVIDENCE_CAS_TOKEN",
                category="runtime-import",
                reason="missing",
            ),
        ]

        stderr = StringIO()
        with (
            patch("scripts.verify_source_runtime_ecs._load_config", return_value=config),
            patch("scripts.verify_source_runtime_ecs._verify_account"),
            patch("scripts.verify_source_runtime_ecs._runtime_targets", return_value=targets),
            patch("scripts.verify_source_runtime_ecs._verify_bootstrap_payload_targets"),
            patch("scripts.verify_source_runtime_ecs._secret_import_preflight_findings", return_value=findings),
            patch("scripts.verify_source_runtime_ecs._run_task") as run_task,
            redirect_stderr(stderr),
        ):
            with self.assertRaisesRegex(RuntimeError, "ECS run-task was not started"):
                main(
                    [
                        "--stack-file",
                        str(stack_file),
                        "--source-id",
                        "aws",
                        "--family",
                        "public_endpoint",
                        "--run",
                    ]
                )

        run_task.assert_not_called()
        output = stderr.getvalue()
        self.assertIn("AWS secret import preflight failed", output)
        self.assertIn("cerebro-sec-dev/EVIDENCE_CAS_BASE_URL", output)
        self.assertIn("cerebro-sec-dev/EVIDENCE_CAS_TOKEN", output)
        self.assertIn("Infisical", output)
        self.assertNotIn("secret-value", output)
        self.assertNotIn("arn:aws", output)

    def test_run_secret_import_preflight_success_allows_runtime_verification(self) -> None:
        stack_file = Path("aws/Pulumi.sec-dev.yaml")
        config = {
            "environment": "sec-dev",
            "sourceSecretKeys": ["AWS_TOKEN", "PANOPTICON_TOKEN"],
            "sourceRuntimes": [
                {"id": "aws-public", "sourceId": "aws", "config": {"family": "public_endpoint", "token": "env:AWS_TOKEN"}},
                {"id": "panopticon-alerts", "sourceId": "panopticon", "config": {"token": "env:PANOPTICON_TOKEN"}},
            ],
        }
        targets = [
            RuntimeTarget(
                runtime_id="aws-public",
                schedule_name="aws-public-live",
                rule_name="cerebro-sec-dev-orchestrator-aws-public-live",
                target={"Arn": "cluster", "EcsParameters": {"TaskDefinitionArn": "task-def"}},
            )
        ]
        result = VerificationResult(
            runtime_id="aws-public",
            task_arn="arn:aws:ecs:us-east-1:000000000000:task/cluster/task-1",
            exit_code=0,
            runtime_status="completed",
            sync_status="success",
            graph_ingest_status="success",
            events_appended=1,
            pages_read=1,
            entities_projected=1,
            links_projected=1,
        )
        events: list[str] = []

        def fake_preflight(config_arg, stack_arg, region_arg):
            self.assertEqual([runtime["id"] for runtime in config_arg["sourceRuntimes"]], ["aws-public"])
            self.assertEqual(config_arg["sourceSecretKeys"], ["AWS_TOKEN"])
            events.append("preflight")
            return []

        def fake_verify(targets_arg, options_arg, concurrency_arg):
            self.assertEqual(events, ["preflight"])
            self.assertEqual(options_arg.bootstrap_runtime_ids, ("aws-public",))
            events.append("verify")
            return [result]

        stdout = StringIO()
        with (
            patch("scripts.verify_source_runtime_ecs._load_config", return_value=config),
            patch("scripts.verify_source_runtime_ecs._verify_account"),
            patch("scripts.verify_source_runtime_ecs._runtime_targets", return_value=targets),
            patch("scripts.verify_source_runtime_ecs._verify_bootstrap_payload_targets"),
            patch("scripts.verify_source_runtime_ecs._secret_import_preflight_findings", side_effect=fake_preflight),
            patch("scripts.verify_source_runtime_ecs._verify_runtime_targets", side_effect=fake_verify),
            redirect_stdout(stdout),
        ):
            status = main(
                [
                    "--stack-file",
                    str(stack_file),
                    "--source-id",
                    "aws",
                    "--family",
                    "public_endpoint",
                    "--run",
                ]
            )

        self.assertEqual(status, 0)
        self.assertEqual(events, ["preflight", "verify"])
        self.assertIn("runtime_id\texit\tsync", stdout.getvalue())

    def test_recent_task_verification_skips_secret_import_preflight(self) -> None:
        stack_file = Path("aws/Pulumi.sec-dev.yaml")
        config = {
            "environment": "sec-dev",
            "sourceRuntimes": [
                {"id": "aws-public", "sourceId": "aws", "config": {"family": "public_endpoint"}}
            ],
        }
        targets = [
            RuntimeTarget(
                runtime_id="aws-public",
                schedule_name="aws-public-live",
                rule_name="cerebro-sec-dev-orchestrator-aws-public-live",
                target={"Arn": "cluster", "EcsParameters": {"TaskDefinitionArn": "task-def"}},
            )
        ]
        result = VerificationResult(
            runtime_id="aws-public",
            task_arn="task-1",
            exit_code=0,
            runtime_status="completed",
            sync_status="success",
            graph_ingest_status="success",
            events_appended=1,
            pages_read=1,
        )

        with (
            patch("scripts.verify_source_runtime_ecs._load_config", return_value=config),
            patch("scripts.verify_source_runtime_ecs._verify_account"),
            patch("scripts.verify_source_runtime_ecs._runtime_targets", return_value=targets),
            patch("scripts.verify_source_runtime_ecs._verify_bootstrap_payload_targets"),
            patch("scripts.verify_source_runtime_ecs._secret_import_preflight_findings") as preflight,
            patch("scripts.verify_source_runtime_ecs._verify_runtime_targets", return_value=[result]),
            redirect_stdout(StringIO()),
        ):
            status = main(
                [
                    "--stack-file",
                    str(stack_file),
                    "--source-id",
                    "aws",
                    "--family",
                    "public_endpoint",
                ]
            )

        self.assertEqual(status, 0)
        preflight.assert_not_called()

    def test_secret_import_preflight_maps_findings_to_key_paths(self) -> None:
        config = {
            "environment": "sec-dev",
            "infisicalSecretsPrefix": "cerebro-sec-dev",
            "sourceSecretKeys": ["EVIDENCE_CAS_BASE_URL", "EVIDENCE_CAS_TOKEN"],
            "sourceRuntimes": [
                {
                    "id": "aws-public",
                    "sourceId": "aws",
                    "config": {
                        "base_url": "env:EVIDENCE_CAS_BASE_URL",
                        "token": "env:EVIDENCE_CAS_TOKEN",
                    },
                }
            ],
        }

        def fake_verify(imports, region):
            return [
                type("Finding", (), {"index": 5, "category": "runtime-import", "fingerprint": "unused", "reason": "missing"})(),
                type("Finding", (), {"index": 6, "category": "runtime-import", "fingerprint": "unused", "reason": "missing"})(),
            ]

        with patch("scripts.verify_source_runtime_ecs.secret_imports.verify_secret_imports", side_effect=fake_verify):
            findings = _secret_import_preflight_findings(config, "sec-dev", "us-east-1")

        self.assertEqual([finding.env_name for finding in findings], ["EVIDENCE_CAS_BASE_URL", "EVIDENCE_CAS_TOKEN"])
        self.assertEqual(
            [finding.key_path for finding in findings],
            ["cerebro-sec-dev/EVIDENCE_CAS_BASE_URL", "cerebro-sec-dev/EVIDENCE_CAS_TOKEN"],
        )

    def test_bootstrap_payload_runtime_ids_parse_object_and_list_shapes(self) -> None:
        object_payload = '{"runtimes":[{"id":"writer-panopticon-alerts","source_id":"panopticon","config":{"token":"env:TOKEN"}}]}'
        list_payload = '[{"id":"writer-panopticon-cases","source_id":"panopticon"}]'

        self.assertEqual(_bootstrap_payload_runtime_ids(object_payload), {"writer-panopticon-alerts"})
        self.assertEqual(_bootstrap_payload_runtime_ids(list_payload), {"writer-panopticon-cases"})

    def test_bootstrap_payload_reads_s3_environment_file(self) -> None:
        payload = '{"runtimes":[{"id":"writer-panopticon-alerts","source_id":"panopticon"}]}'
        task_definition = {
            "containerDefinitions": [
                {
                    "name": "source-runtime-bootstrap",
                    "environmentFiles": [
                        {
                            "type": "s3",
                            "value": "arn:aws:s3:::writer-cerebro-sec-dev-source-runtime-bootstrap/source-runtime-bootstrap/orchestrator.env",
                        }
                    ],
                }
            ]
        }

        with patch("scripts.verify_source_runtime_ecs._read_s3_object", return_value=f"CEREBRO_SOURCE_RUNTIME_BOOTSTRAP_JSON={payload}\n") as read_s3:
            self.assertEqual(_bootstrap_payload_from_task_definition(task_definition, "us-east-1"), payload)

        read_s3.assert_called_once_with(
            "writer-cerebro-sec-dev-source-runtime-bootstrap",
            "source-runtime-bootstrap/orchestrator.env",
            "us-east-1",
        )

    def test_scoped_bootstrap_payload_keeps_requested_runtimes_only(self) -> None:
        payload = json.dumps(
            {
                "runtimes": [
                    {"id": "writer-panopticon-alerts", "source_id": "panopticon", "config": {"token": "env:PANOPTICON_TOKEN"}},
                    {"id": "writer-cosmo-session", "source_id": "cosmo", "config": {"token": "env:COSMO_TOKEN"}},
                ]
            }
        )

        scoped = json.loads(_scoped_bootstrap_payload(payload, {"writer-panopticon-alerts"}))

        self.assertEqual([runtime["id"] for runtime in scoped["runtimes"]], ["writer-panopticon-alerts"])
        self.assertNotIn("COSMO_TOKEN", json.dumps(scoped))

    def test_observability_scope_preflight_excludes_unrelated_source_secrets(self) -> None:
        config = {
            "environment": "sec-dev",
            "infisicalSecretsPrefix": "cerebro-sec-dev",
            "sourceSecretKeys": ["PANOPTICON_TOKEN", "COSMO_TOKEN"],
            "sourceRuntimes": [
                {
                    "id": "writer-panopticon-alerts",
                    "sourceId": "panopticon",
                    "config": {"token": "env:PANOPTICON_TOKEN"},
                },
                {
                    "id": "writer-cosmo-session",
                    "sourceId": "cosmo",
                    "config": {"token": "env:COSMO_TOKEN"},
                },
            ],
        }

        scoped = _config_for_runtime_scope(config, {"writer-panopticon-alerts"})
        imports = [item.env_name for item in secret_imports.expected_secret_imports(scoped, "sec-dev")]
        full_imports = [item.env_name for item in secret_imports.expected_secret_imports(config, "sec-dev")]

        self.assertIn("PANOPTICON_TOKEN", imports)
        self.assertNotIn("COSMO_TOKEN", imports)
        self.assertIn("COSMO_TOKEN", full_imports)

    def test_verify_bootstrap_payload_targets_fails_closed_for_missing_runtime_id(self) -> None:
        target = RuntimeTarget(
            runtime_id="writer-panopticon-alerts",
            schedule_name="panopticon-alerts-live",
            rule_name="cerebro-sec-dev-orchestrator-panopticon-alerts-live",
            target={"Arn": "cluster", "EcsParameters": {"TaskDefinitionArn": "task-def"}},
        )

        def fake_aws(args: list[str], _region: str) -> dict[str, object]:
            if args[:2] == ["ecs", "describe-task-definition"]:
                return {
                    "taskDefinition": {
                        "status": "ACTIVE",
                        "taskDefinitionArn": "task-def",
                        "containerDefinitions": [
                            {
                                "name": "source-runtime-bootstrap",
                                "environment": [
                                    {
                                        "name": "CEREBRO_SOURCE_RUNTIME_BOOTSTRAP_JSON",
                                        "value": '{"runtimes":[{"id":"writer-panopticon-cases","source_id":"panopticon"}]}',
                                    }
                                ],
                            }
                        ]
                    }
                }
            raise AssertionError(f"unexpected args: {args}")

        with patch("scripts.verify_source_runtime_ecs._aws", side_effect=fake_aws):
            with self.assertRaisesRegex(RuntimeVerificationFailedError, "bootstrap payload status is missing"):
                _verify_bootstrap_payload_targets([target], "us-east-1")

    def test_verify_bootstrap_payload_targets_reads_s3_environment_file(self) -> None:
        target = RuntimeTarget(
            runtime_id="writer-panopticon-alerts",
            schedule_name="panopticon-alerts-live",
            rule_name="cerebro-sec-dev-orchestrator-panopticon-alerts-live",
            target={"EcsParameters": {"TaskDefinitionArn": "task-def"}},
        )
        payload = '{"runtimes":[{"id":"writer-panopticon-alerts","source_id":"panopticon"}]}'

        def fake_aws(args, region):
            if args[:2] == ["ecs", "list-task-definitions"]:
                return {"taskDefinitionArns": ["task-def:2"]}
            return {
                "taskDefinition": {
                    "taskDefinitionArn": "task-def:2",
                    "containerDefinitions": [
                        {
                            "name": "source-runtime-bootstrap",
                            "environmentFiles": [
                                {
                                    "type": "s3",
                                    "value": "arn:aws:s3:::bootstrap/source-runtime-bootstrap/orchestrator.env",
                                }
                            ],
                        }
                    ],
                }
            }

        with (
            patch("scripts.verify_source_runtime_ecs._aws", side_effect=fake_aws),
            patch("scripts.verify_source_runtime_ecs._read_s3_object", return_value=f"CEREBRO_SOURCE_RUNTIME_BOOTSTRAP_JSON={payload}\n"),
        ):
            _verify_bootstrap_payload_targets([target], "us-east-1")

    def test_verify_bootstrap_payload_targets_reads_target_input_payload(self) -> None:
        payload = '{"runtimes":[{"id":"writer-panopticon-alerts","source_id":"panopticon"}]}'
        target = RuntimeTarget(
            runtime_id="writer-panopticon-alerts",
            schedule_name="panopticon-alerts-live",
            rule_name="cerebro-sec-dev-orchestrator-panopticon-alerts-live",
            target={
                "Input": json.dumps(
                    {
                        "containerOverrides": [
                            {
                                "name": "source-runtime-bootstrap",
                                "environment": [{"name": "CEREBRO_SOURCE_RUNTIME_BOOTSTRAP_JSON", "value": payload}],
                            }
                        ]
                    }
                ),
                "EcsParameters": {"TaskDefinitionArn": "task-def"},
            },
        )

        def fake_aws(args, region):
            if args[:2] == ["ecs", "list-task-definitions"]:
                return {"taskDefinitionArns": ["task-def:2"]}
            return {"taskDefinition": {"taskDefinitionArn": "task-def:2", "containerDefinitions": []}}

        with patch("scripts.verify_source_runtime_ecs._aws", side_effect=fake_aws):
            _verify_bootstrap_payload_targets([target], "us-east-1")

    def test_run_validates_bootstrap_payload_before_secret_preflight_and_run_task(self) -> None:
        stack_file = Path("aws/Pulumi.sec-dev.yaml")
        config = {
            "environment": "sec-dev",
            "sourceRuntimeObservability": [
                {
                    "sourceSystem": "panopticon",
                    "sourceRuntimeId": "writer-panopticon-alerts",
                    "runtimeClass": "alert",
                    "enabled": True,
                }
            ],
        }
        targets = [
            RuntimeTarget(
                runtime_id="writer-panopticon-alerts",
                schedule_name="panopticon-alerts-live",
                rule_name="cerebro-sec-dev-orchestrator-panopticon-alerts-live",
                target={"Arn": "cluster", "EcsParameters": {"TaskDefinitionArn": "task-def"}},
            )
        ]
        events: list[str] = []

        def fake_bootstrap(targets_arg, region_arg):
            events.append("bootstrap")
            raise RuntimeVerificationFailedError("writer-panopticon-alerts", "task-def", "bootstrap payload", "missing")

        def fake_preflight(config_arg, stack_arg, region_arg):
            events.append("preflight")
            return []

        with (
            patch("scripts.verify_source_runtime_ecs._load_config", return_value=config),
            patch("scripts.verify_source_runtime_ecs._verify_account"),
            patch("scripts.verify_source_runtime_ecs._runtime_targets", return_value=targets),
            patch("scripts.verify_source_runtime_ecs._verify_bootstrap_payload_targets", side_effect=fake_bootstrap),
            patch("scripts.verify_source_runtime_ecs._secret_import_preflight_findings", side_effect=fake_preflight),
            patch("scripts.verify_source_runtime_ecs._run_task") as run_task,
        ):
            with self.assertRaisesRegex(RuntimeVerificationFailedError, "bootstrap payload status is missing"):
                main(
                    [
                        "--stack-file",
                        str(stack_file),
                        "--source-id",
                        "panopticon",
                        "--observability-targets",
                        "--run",
                    ]
                )

        self.assertEqual(events, ["bootstrap"])
        run_task.assert_not_called()

    def test_runtime_discovery_failure_includes_redacted_bootstrap_diagnostics(self) -> None:
        target = RuntimeTarget(
            runtime_id="writer-panopticon-alerts",
            schedule_name="panopticon-alerts-live",
            rule_name="cerebro-sec-dev-orchestrator-panopticon-alerts-live",
            target={"Arn": "cluster"},
        )
        task = {
            "taskArn": "arn:aws:ecs:us-east-1:123456789012:task/cluster/task-1",
            "taskDefinitionArn": "arn:aws:ecs:us-east-1:123456789012:task-definition/runtime:4",
        }
        messages = [
            {"kind": "event", "name": "orchestrator.runtimes_listed", "runtime_count": 0},
            {"kind": "span_end", "name": "orchestrator.iteration", "status": "completed", "runtimes_attempted": 0},
        ]

        def fake_aws(args: list[str], _region: str) -> dict[str, object]:
            if args[:2] == ["ecs", "describe-task-definition"]:
                return {
                    "taskDefinition": {
                        "containerDefinitions": [
                            {
                                "name": "source-runtime-bootstrap",
                                "environment": [
                                    {
                                        "name": "CEREBRO_SOURCE_RUNTIME_BOOTSTRAP_JSON",
                                        "value": '{"runtimes":[{"id":"writer-panopticon-alerts","source_id":"panopticon","config":{"token":"env:TOKEN"}}]}',
                                    }
                                ],
                                "logConfiguration": {
                                    "options": {
                                        "awslogs-group": "/ecs/cerebro-sec-dev",
                                        "awslogs-stream-prefix": "source-runtime-bootstrap",
                                    }
                                },
                            }
                        ]
                    }
                }
            if args[:2] == ["logs", "get-log-events"]:
                return {
                    "events": [
                        {
                            "message": '{"kind":"event","name":"source_runtime.bootstrap","status":"completed","runtime_id":"writer-panopticon-alerts","secret":"do-not-print"}'
                        }
                    ]
                }
            raise AssertionError(f"unexpected args: {args}")

        with patch("scripts.verify_source_runtime_ecs._aws", side_effect=fake_aws):
            with self.assertRaises(RuntimeVerificationFailedError) as context:
                _verification_result_from_logs(target, task["taskArn"], 0, messages, True, task=task, region="us-east-1")

        output = str(context.exception)
        self.assertIn("bootstrap diagnostics", output)
        self.assertIn("writer-panopticon-alerts", output)
        self.assertNotIn("123456789012", output)
        self.assertNotIn("arn:aws", output)
        self.assertNotIn("do-not-print", output)


if __name__ == "__main__":
    unittest.main()
