from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.verify_source_runtime_ecs import (
    RuntimeSkippedError,
    RuntimeTarget,
    _declared_runtime_ids,
    _latest_active_task_definition,
    _run_and_verify_task_with_retries,
    _run_task,
    _runtime_id_from_command,
    _runtime_skip_reason,
    _runtime_skip_retryable,
    _schedule_suffix,
    _summarize_log_messages,
    _task_family,
    _verification_command,
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

    def test_runtime_id_from_command(self) -> None:
        self.assertEqual(_runtime_id_from_command(["orchestrator", "run", "runtime_id=writer-cosmo-session"]), "writer-cosmo-session")

    def test_schedule_suffix_matches_pulumi_names(self) -> None:
        self.assertEqual(_schedule_suffix("Cosmo Survey Feedback"), "cosmo-survey-feedback")

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
            self.assertEqual(_latest_active_task_definition(inactive, "us-east-1"), active)

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

    def test_summarize_log_messages_limits_fields_and_length(self) -> None:
        summary = _summarize_log_messages(
            [
                {"message": "old"},
                {"level": "error", "message": "x" * 2500, "secret": "not included"},
            ],
            limit=1,
        )

        self.assertIn('"level": "error"', summary)
        self.assertIn('"message": "', summary)
        self.assertNotIn("secret", summary)
        self.assertLessEqual(len(summary), 2000)


if __name__ == "__main__":
    unittest.main()
