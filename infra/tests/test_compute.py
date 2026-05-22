from __future__ import annotations

import importlib.util
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from pathlib import Path


spec = importlib.util.spec_from_file_location("compute", Path(__file__).resolve().parents[1] / "aws" / "compute.py")
compute = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compute)


class SourceRuntimeEnvironmentTest(unittest.TestCase):
    def test_adds_aws_role_allowlist_from_source_runtimes(self) -> None:
        env = compute._source_runtime_environment(
            {"CEREBRO_ENVIRONMENT": "sec-dev"},
            [
                {"sourceId": "aws", "tenantId": "writer", "config": {"role_arn": "arn:aws:iam::222222222222:role/cerebro-org-scan-role"}},
                {"source_id": "aws", "tenant_id": "other", "config": {"role_arn": "arn:aws:iam::111111111111:role/cerebro-org-scan-role"}},
                {"sourceId": "github", "config": {"role_arn": "arn:aws:iam::333333333333:role/ignored"}},
            ],
        )
        self.assertEqual(
            env["CEREBRO_AWS_ASSUME_ROLE_ARNS"],
            "other=arn:aws:iam::111111111111:role/cerebro-org-scan-role,writer=arn:aws:iam::222222222222:role/cerebro-org-scan-role",
        )
        self.assertEqual(env["CEREBRO_ENVIRONMENT"], "sec-dev")

    def test_preserves_explicit_aws_role_allowlist(self) -> None:
        env = compute._source_runtime_environment(
            {"CEREBRO_AWS_ASSUME_ROLE_ARNS": "custom=arn:aws:iam::999999999999:role/custom"},
            [{"sourceId": "aws", "tenantId": "writer", "config": {"role_arn": "arn:aws:iam::111111111111:role/cerebro-org-scan-role"}}],
        )
        self.assertEqual(env["CEREBRO_AWS_ASSUME_ROLE_ARNS"], "custom=arn:aws:iam::999999999999:role/custom")


class WorkerTaskRoleTest(unittest.TestCase):
    def test_orchestrator_uses_separate_worker_task_role(self) -> None:
        task_role_names: list[str] = []
        task_definition_calls: list[dict] = []
        orchestrator_events_role_calls: list[dict] = []

        def fake_named_resource(*args, **kwargs):
            name = kwargs.get("name") or args[0]
            return SimpleNamespace(name=name, id=f"{name}-id", arn=f"arn:aws:test::{name}")

        def fake_args(**kwargs):
            return SimpleNamespace(**kwargs)

        def fake_task_role(name: str, *_args, **_kwargs):
            task_role_names.append(name)
            return SimpleNamespace(name=f"{name}-task-role", arn=f"arn:aws:iam::123456789012:role/{name}-task-role")

        def fake_task_definition(**kwargs):
            task_definition_calls.append(kwargs)
            return SimpleNamespace(arn=f"arn:aws:ecs:us-east-1:123456789012:task-definition/{kwargs['name']}:1")

        def fake_orchestrator_events_role(**kwargs):
            orchestrator_events_role_calls.append(kwargs)
            return SimpleNamespace(arn="arn:aws:iam::123456789012:role/cerebro-sec-dev-orchestrator-events-role")

        with (
            patch.object(compute, "_create_execution_role", return_value=SimpleNamespace(arn="arn:aws:iam::123456789012:role/cerebro-sec-dev-exec-role")),
            patch.object(compute, "_create_task_role", side_effect=fake_task_role),
            patch.object(compute, "_create_task_definition", side_effect=fake_task_definition),
            patch.object(compute, "_create_orchestrator_events_role", side_effect=fake_orchestrator_events_role),
            patch.object(compute.aws.ecs, "Cluster", side_effect=fake_named_resource),
            patch.object(compute.aws.ecs, "ClusterCapacityProviders", side_effect=fake_named_resource),
            patch.object(compute.aws.ecs, "ClusterCapacityProvidersDefaultCapacityProviderStrategyArgs", side_effect=fake_args),
            patch.object(compute.aws.ecs, "Service", side_effect=fake_named_resource),
            patch.object(compute.aws.ecs, "ServiceCapacityProviderStrategyArgs", side_effect=fake_args),
            patch.object(compute.aws.ecs, "ServiceNetworkConfigurationArgs", side_effect=fake_args),
            patch.object(compute.aws.ecs, "ServiceLoadBalancerArgs", side_effect=fake_args),
            patch.object(compute.aws.ecs, "ServiceDeploymentCircuitBreakerArgs", side_effect=fake_args),
            patch.object(compute.aws.cloudwatch, "LogGroup", side_effect=fake_named_resource),
            patch.object(compute.aws.cloudwatch, "EventRule", side_effect=fake_named_resource),
            patch.object(compute.aws.cloudwatch, "EventTarget", side_effect=fake_named_resource),
            patch.object(compute.aws.cloudwatch, "EventTargetEcsTargetArgs", side_effect=fake_args),
            patch.object(compute.aws.cloudwatch, "EventTargetEcsTargetNetworkConfigurationArgs", side_effect=fake_args),
            patch.object(compute.aws.appautoscaling, "Target", side_effect=fake_named_resource),
            patch.object(compute.pulumi, "ResourceOptions", side_effect=fake_args),
        ):
            result = compute.create_ecs_cluster(
                name="cerebro-sec-dev",
                vpc_id="vpc-1",
                subnet_ids=["subnet-1"],
                security_group_id="sg-1",
                kms_key_id="key-1",
                target_group_arn="tg-1",
                container_image="image",
                external_secrets_prefix="/cerebro/sec-dev",
                orchestrator_enabled=True,
                orchestrator_schedules=[
                    {
                        "name": "cosmo-fact",
                        "command": ["orchestrator", "run", "runtime_id=writer-cosmo-fact"],
                    }
                ],
            )

        self.assertEqual(task_role_names, ["cerebro-sec-dev", "cerebro-sec-dev-worker"])
        self.assertEqual(
            result["task_role"].arn,
            "arn:aws:iam::123456789012:role/cerebro-sec-dev-task-role",
        )
        self.assertEqual(
            result["worker_task_role"].arn,
            "arn:aws:iam::123456789012:role/cerebro-sec-dev-worker-task-role",
        )

        api_task_definition = next(call for call in task_definition_calls if call["name"] == "cerebro-sec-dev")
        orchestrator_task_definition = next(call for call in task_definition_calls if call["name"] == "cerebro-sec-dev-orchestrator-cosmo-fact")
        self.assertEqual(
            api_task_definition["task_role_arn"],
            "arn:aws:iam::123456789012:role/cerebro-sec-dev-task-role",
        )
        self.assertEqual(
            orchestrator_task_definition["task_role_arn"],
            "arn:aws:iam::123456789012:role/cerebro-sec-dev-worker-task-role",
        )
        self.assertEqual(
            orchestrator_events_role_calls[0]["task_role_arn"],
            "arn:aws:iam::123456789012:role/cerebro-sec-dev-worker-task-role",
        )


if __name__ == "__main__":
    unittest.main()
