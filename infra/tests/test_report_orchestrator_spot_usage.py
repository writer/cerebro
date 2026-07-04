from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import scripts.report_orchestrator_spot_usage as report


class ReportOrchestratorSpotUsageTest(unittest.TestCase):
    def _stack_file(self, body: str) -> Path:
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        path = Path(tempdir.name) / "Pulumi.go-prod.yaml"
        path.write_text(body, encoding="utf-8")
        return path

    def test_load_stack_context_uses_environment_and_orchestrator_size(self) -> None:
        stack_file = self._stack_file(
            """\
config:
  cerebro:environment: go-production
  cerebro:orchestratorCpu: 16384
  cerebro:orchestratorMemory: 32768
"""
        )

        context = report.load_stack_context(stack_file)

        self.assertEqual(context.stack, "go-prod")
        self.assertEqual(context.cluster_name, "cerebro-go-production-cluster")
        self.assertEqual(context.orchestrator_family, "cerebro-go-production-orchestrator")
        self.assertEqual(context.task_stop_log_group, "/aws/events/cerebro-go-production-orchestrator-task-stops")
        self.assertEqual(context.cpu_units, 16384)
        self.assertEqual(context.memory_mib, 32768)

    def test_task_stop_classifies_spot_interruption_and_grouped_runtime_ids(self) -> None:
        task = {
            "taskArn": "arn:aws:ecs:us-east-1:123456789012:task/cerebro/abc",
            "taskDefinitionArn": "arn:aws:ecs:us-east-1:123456789012:task-definition/cerebro-go-production-orchestrator:187",
            "startedAt": "2026-07-03T01:00:00Z",
            "stoppedAt": "2026-07-03T01:30:00Z",
            "stopCode": "SpotInterruption",
            "stoppedReason": "Your Spot Task was interrupted.",
            "overrides": {
                "containerOverrides": [
                    {"name": "cerebro", "command": ["orchestrator", "run", "runtime_ids=a,b"]},
                ],
            },
            "containers": [{"name": "cerebro", "exitCode": 137}],
        }

        stop = report.task_stop_from_task(task, source="ecs")

        self.assertEqual(stop.kind, "spot_interrupted")
        self.assertTrue(stop.grouped_runtime_ids)
        self.assertEqual(stop.runtime_selector, "runtime_ids=a,b")
        self.assertEqual(stop.duration_seconds, 1800)

    def test_nonzero_exit_stays_separate_from_spot_interruption(self) -> None:
        task = {
            "taskArn": "task/abc",
            "startedAt": "2026-07-03T01:00:00+00:00",
            "stoppedAt": "2026-07-03T01:05:00+00:00",
            "stopCode": "EssentialContainerExited",
            "overrides": {"containerOverrides": [{"name": "cerebro", "command": ["orchestrator", "run", "runtime_id=writer-okta"]}]},
            "containers": [{"name": "cerebro", "exitCode": 1}],
        }

        stop = report.task_stop_from_task(task, source="cloudwatch")

        self.assertEqual(stop.kind, "nonzero_exit")
        self.assertFalse(stop.grouped_runtime_ids)
        self.assertEqual(stop.runtime_selector, "runtime_id=writer-okta")

    def test_estimate_cost_models_task_hours_at_stack_size(self) -> None:
        context = report.StackContext(
            stack="go-prod",
            environment="go-production",
            resource_name="cerebro-go-production",
            cluster_name="cerebro-go-production-cluster",
            orchestrator_family="cerebro-go-production-orchestrator",
            scheduler_group="cerebro-go-production-orchestrator",
            eventbridge_rule_prefix="cerebro-go-production-orchestrator",
            task_stop_log_group="/aws/events/cerebro-go-production-orchestrator-task-stops",
            cpu_units=2048,
            memory_mib=4096,
        )
        stop = report.TaskStop(
            task_arn="task/abc",
            task_definition_arn="task-def:1",
            stopped_at=datetime(2026, 7, 3, 1, 30, tzinfo=UTC).isoformat(),
            started_at=datetime(2026, 7, 3, 1, 0, tzinfo=UTC).isoformat(),
            duration_seconds=1800,
            stop_code="",
            stopped_reason="",
            kind="success",
            command=[],
            runtime_selector="",
            grouped_runtime_ids=False,
            exit_codes={"cerebro": 0},
            source="ecs",
        )

        estimate = report.estimate_cost([stop], context, vcpu_hour_usd=1.0, gb_hour_usd=0.5, spot_discount=0.5)

        self.assertEqual(estimate.task_hours, 0.5)
        self.assertEqual(estimate.vcpu_hours, 1.0)
        self.assertEqual(estimate.memory_gb_hours, 2.0)
        self.assertEqual(estimate.on_demand_cost_usd, 2.0)
        self.assertEqual(estimate.spot_cost_usd, 1.0)

    def test_replay_command_only_accepts_spot_interrupted_tasks(self) -> None:
        context = report.StackContext(
            stack="go-prod",
            environment="go-production",
            resource_name="cerebro-go-production",
            cluster_name="cerebro-go-production-cluster",
            orchestrator_family="cerebro-go-production-orchestrator",
            scheduler_group="cerebro-go-production-orchestrator",
            eventbridge_rule_prefix="cerebro-go-production-orchestrator",
            task_stop_log_group="/aws/events/cerebro-go-production-orchestrator-task-stops",
            cpu_units=1024,
            memory_mib=2048,
        )
        run_config = report.RunConfig(
            task_definition_arn="task-def:187",
            network_configuration={"awsvpcConfiguration": {"subnets": ["subnet-a"], "securityGroups": ["sg-a"], "assignPublicIp": "DISABLED"}},
            capacity_provider_strategy=[{"capacityProvider": "FARGATE_SPOT", "weight": 1}],
            launch_type="FARGATE",
        )
        spot_stop = report.TaskStop(
            task_arn="task/abc",
            task_definition_arn="task-def:187",
            stopped_at="2026-07-03T01:30:00Z",
            started_at="2026-07-03T01:00:00Z",
            duration_seconds=1800,
            stop_code="SpotInterruption",
            stopped_reason="interrupted",
            kind="spot_interrupted",
            command=["orchestrator", "run", "runtime_ids=a,b"],
            runtime_selector="runtime_ids=a,b",
            grouped_runtime_ids=True,
            exit_codes={"cerebro": 137},
            source="ecs",
        )

        command = report.build_replay_command(
            context,
            spot_stop,
            run_config,
            profile="writer-sec-prod-us1",
            region="us-east-1",
            replay_capacity_provider="FARGATE",
        )

        self.assertEqual(command[:5], ["aws", "--profile", "writer-sec-prod-us1", "--region", "us-east-1"])
        self.assertIn("--capacity-provider-strategy", command)
        strategy = json.loads(command[command.index("--capacity-provider-strategy") + 1])
        self.assertEqual(strategy, [{"capacityProvider": "FARGATE", "weight": 1}])
        overrides = json.loads(command[command.index("--overrides") + 1])
        self.assertEqual(overrides["containerOverrides"][0]["command"], ["orchestrator", "run", "runtime_ids=a,b"])

        non_spot_stop = report.TaskStop(**{**spot_stop.__dict__, "kind": "nonzero_exit"})
        with self.assertRaisesRegex(ValueError, "only Spot-interrupted"):
            report.build_replay_command(
                context,
                non_spot_stop,
                run_config,
                profile="writer-sec-prod-us1",
                region="us-east-1",
                replay_capacity_provider="FARGATE",
            )

    def test_aws_json_runs_argument_list_without_shell(self) -> None:
        with patch.object(report.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess(["aws"], 0, stdout="{}", stderr="")
            self.assertEqual(report._aws_json(["sts", "get-caller-identity"], profile="profile", region="us-east-1"), {})

        command, kwargs = run.call_args.args[0], run.call_args.kwargs
        self.assertIsInstance(command, list)
        self.assertNotIn("shell", kwargs)
        self.assertIn("sts", command)


if __name__ == "__main__":
    unittest.main()
