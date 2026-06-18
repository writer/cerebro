from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("web", Path(__file__).resolve().parents[1] / "aws" / "web.py")
web = importlib.util.module_from_spec(spec)
spec.loader.exec_module(web)


class FakeOutputAll:
    def __init__(self, values: tuple):
        self.values = values

    def apply(self, callback):
        return callback(self.values)


class WebAutoscalingTest(unittest.TestCase):
    def test_web_autoscaling_tracks_cpu_and_memory(self) -> None:
        policy_calls: list[dict] = []

        def fake_named_resource(*args, **kwargs):
            name = kwargs.get("name") or args[0]
            return SimpleNamespace(name=name, id=f"{name}-id", arn=f"arn:aws:test::{name}", resource_id=kwargs.get("resource_id", f"{name}-resource"))

        def fake_args(**kwargs):
            return SimpleNamespace(**kwargs)

        def fake_policy(*args, **kwargs):
            policy_calls.append({"name": args[0], **kwargs})
            return SimpleNamespace(name=args[0])

        with (
            patch.object(web, "_create_execution_role", return_value=SimpleNamespace(arn="arn:aws:iam::123456789012:role/cerebro-web-exec-role")),
            patch.object(web, "_create_task_role", return_value=SimpleNamespace(name="cerebro-web-task-role", arn="arn:aws:iam::123456789012:role/cerebro-web-task-role")),
            patch.object(web, "_create_task_definition", return_value=SimpleNamespace(arn="arn:aws:ecs:us-east-1:123456789012:task-definition/cerebro-web:1")),
            patch.object(web.aws.cloudwatch, "LogGroup", side_effect=fake_named_resource),
            patch.object(web.aws.ecs, "Service", side_effect=fake_named_resource),
            patch.object(web.aws.ecs, "ServiceCapacityProviderStrategyArgs", side_effect=fake_args),
            patch.object(web.aws.ecs, "ServiceNetworkConfigurationArgs", side_effect=fake_args),
            patch.object(web.aws.ecs, "ServiceLoadBalancerArgs", side_effect=fake_args),
            patch.object(web.aws.ecs, "ServiceDeploymentCircuitBreakerArgs", side_effect=fake_args),
            patch.object(web.aws.appautoscaling, "Target", side_effect=fake_named_resource),
            patch.object(web.aws.appautoscaling, "Policy", side_effect=fake_policy),
            patch.object(web.aws.appautoscaling, "PolicyTargetTrackingScalingPolicyConfigurationArgs", side_effect=fake_args),
            patch.object(web.aws.appautoscaling, "PolicyTargetTrackingScalingPolicyConfigurationPredefinedMetricSpecificationArgs", side_effect=fake_args),
            patch.object(web.pulumi, "ResourceOptions", side_effect=fake_args),
        ):
            web.create_web_service(
                name="cerebro-web",
                cluster_id="cluster-id",
                cluster_name="cerebro-cluster",
                subnet_ids=["subnet-1"],
                security_group_id="sg-1",
                target_group_arn="tg-1",
                container_image="image",
                kms_key_id="key-1",
                external_secrets_prefix="/cerebro/web",
                min_instances=1,
                max_instances=3,
            )

        metrics = {
            call["target_tracking_scaling_policy_configuration"].predefined_metric_specification.predefined_metric_type
            for call in policy_calls
        }
        self.assertEqual(
            metrics,
            {"ECSServiceAverageCPUUtilization", "ECSServiceAverageMemoryUtilization"},
        )

    def test_log_insights_policy_allows_query_lifecycle_and_scopes_event_reads(self) -> None:
        role_policies: list[dict] = []

        def fake_role_policy(*args, **kwargs):
            role_policies.append({"name": args[0], **kwargs})
            return SimpleNamespace(name=args[0])

        with (
            patch.object(web.aws.iam, "RolePolicy", side_effect=fake_role_policy),
            patch.object(web.pulumi.Output, "all", side_effect=lambda *values: FakeOutputAll(values)),
        ):
            web._attach_log_insights_policy(
                "cerebro-sec-dev-web",
                SimpleNamespace(name="cerebro-sec-dev-web-task-role"),
                [
                    "arn:aws:logs:us-east-1:123456789012:log-group:/ecs/cerebro-sec-dev",
                    "arn:aws:logs:us-east-1:123456789012:log-group:/ecs/cerebro-sec-dev-web",
                ],
            )

        self.assertEqual(len(role_policies), 1)
        policy = json.loads(role_policies[0]["policy"])
        query_statement = policy["Statement"][0]
        self.assertIn("logs:StartQuery", query_statement["Action"])
        self.assertIn("logs:StopQuery", query_statement["Action"])
        self.assertEqual(query_statement["Resource"], "*")
        filter_statement = policy["Statement"][1]
        self.assertEqual(filter_statement["Action"], ["logs:FilterLogEvents"])
        self.assertEqual(
            filter_statement["Resource"],
            [
                "arn:aws:logs:us-east-1:123456789012:log-group:/ecs/cerebro-sec-dev",
                "arn:aws:logs:us-east-1:123456789012:log-group:/ecs/cerebro-sec-dev:*",
                "arn:aws:logs:us-east-1:123456789012:log-group:/ecs/cerebro-sec-dev-web",
                "arn:aws:logs:us-east-1:123456789012:log-group:/ecs/cerebro-sec-dev-web:*",
            ],
        )
        self.assertEqual(policy["Statement"][2]["Resource"], "*")


if __name__ == "__main__":
    unittest.main()
