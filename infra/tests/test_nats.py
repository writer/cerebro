from __future__ import annotations

from contextlib import ExitStack
import importlib.util
import json
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "aws"))
spec = importlib.util.spec_from_file_location("nats", Path(__file__).resolve().parents[1] / "aws" / "nats.py")
nats = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = nats
spec.loader.exec_module(nats)


class NatsContainerDefinitionTest(unittest.TestCase):
    def test_nats_containers_are_hardened(self) -> None:
        containers = json.loads(
            nats._build_container_definitions(
                name="cerebro-sec-dev",
                log_group_name="/ecs/cerebro-sec-dev/nats",
                region="us-east-1",
                stream_name="CEREBRO_EVENTS",
                subject_prefix="events",
                stream_max_bytes="128849018880",
                stream_max_age="168h",
                lag_probe_image="probe:latest",
                lag_probe_interval_seconds=60,
                enable_lag_probe=True,
            )
        )
        by_name = {container["name"]: container for container in containers}

        self.assertEqual(by_name["nats"]["user"], "10001")
        self.assertIs(by_name["nats"]["readonlyRootFilesystem"], True)
        self.assertEqual(by_name["nats"]["healthCheck"]["interval"], 60)
        self.assertEqual(by_name["nats"]["healthCheck"]["retries"], 10)
        self.assertEqual(by_name["nats"]["healthCheck"]["startPeriod"], 300)
        self.assertEqual(by_name["jetstream-bootstrap"]["user"], "10001")
        bootstrap_env = {item["name"]: item["value"] for item in by_name["jetstream-bootstrap"]["environment"]}
        self.assertEqual(bootstrap_env["NATS_TIMEOUT"], "60s")
        self.assertEqual(bootstrap_env["STREAM_MAX_BYTES"], "128849018880")
        self.assertEqual(bootstrap_env["STREAM_MAX_AGE"], "168h")
        bootstrap_command = " ".join(by_name["jetstream-bootstrap"]["command"])
        self.assertIn("stream edit", bootstrap_command)
        self.assertIn("stream add", bootstrap_command)
        self.assertIn("stream add \"$STREAM_NAME\" \"$@\" --storage file --retention limits", bootstrap_command)
        self.assertIn("stream add \"$STREAM_NAME\" \"$@\" --storage file --retention limits --defaults", bootstrap_command)
        self.assertIn("stream add \"$STREAM_NAME\" \"$@\" --storage file --retention limits --defaults || nats", bootstrap_command)
        self.assertNotIn("stream edit \"$STREAM_NAME\" \"$@\" --defaults", bootstrap_command)
        self.assertNotIn("stream edit \"$STREAM_NAME\" \"$@\" --storage", bootstrap_command)
        self.assertEqual(by_name["jetstream-lag-probe"]["user"], "10001")
        self.assertIs(by_name["jetstream-lag-probe"]["readonlyRootFilesystem"], True)

    def test_cloudmap_health_check_threshold_is_preserved(self) -> None:
        health_check_args: list[dict] = []
        service_args: list[dict] = []

        class FakeOutput:
            def __init__(self, value: str):
                self.value = value

            def apply(self, callback):
                return callback(self.value)

        def fake_resource(*args, **kwargs):
            name = kwargs.get("name", args[0])
            return SimpleNamespace(
                id=f"{name}-id",
                arn=f"arn:aws:test::{name}",
                name=FakeOutput(str(name)),
            )

        def fake_args(**kwargs):
            return SimpleNamespace(**kwargs)

        def fake_health_check_args(**kwargs):
            health_check_args.append(kwargs)
            return fake_args(**kwargs)

        def fake_service(*args, **kwargs):
            service_args.append(kwargs)
            return fake_resource(*args, **kwargs)

        with ExitStack() as stack:
            for patcher in [
                patch.object(nats.aws.servicediscovery, "PrivateDnsNamespace", side_effect=fake_resource),
                patch.object(nats.aws.servicediscovery, "Service", side_effect=fake_resource),
                patch.object(nats.aws.servicediscovery, "ServiceDnsConfigArgs", side_effect=fake_args),
                patch.object(nats.aws.servicediscovery, "ServiceDnsConfigDnsRecordArgs", side_effect=fake_args),
                patch.object(nats.aws.servicediscovery, "ServiceHealthCheckCustomConfigArgs", side_effect=fake_health_check_args),
                patch.object(nats.aws.ec2, "SecurityGroup", side_effect=fake_resource),
                patch.object(nats.aws.ec2, "SecurityGroupIngressArgs", side_effect=fake_args),
                patch.object(nats.aws.ec2, "SecurityGroupEgressArgs", side_effect=fake_args),
                patch.object(nats.storage, "create_efs_volume", return_value={
                    "file_system": SimpleNamespace(id="fs-1", arn="arn:aws:efs:us-east-1:123:file-system/fs-1"),
                    "access_point": SimpleNamespace(id="ap-1"),
                    "mount_targets": [],
                }),
                patch.object(nats.aws.ecs, "Cluster", side_effect=fake_resource),
                patch.object(nats.aws.ecs, "ClusterSettingArgs", side_effect=fake_args),
                patch.object(nats, "_execution_role", return_value=SimpleNamespace(arn="exec-role")),
                patch.object(nats, "_task_role", return_value=SimpleNamespace(arn="task-role")),
                patch.object(nats.aws.cloudwatch, "LogGroup", side_effect=fake_resource),
                patch.object(nats.aws, "get_region", return_value=SimpleNamespace(region="us-east-1")),
                patch.object(nats.aws.ecs, "TaskDefinition", side_effect=fake_resource),
                patch.object(nats.aws.ecs, "TaskDefinitionRuntimePlatformArgs", side_effect=fake_args),
                patch.object(nats.aws.ecs, "TaskDefinitionVolumeArgs", side_effect=fake_args),
                patch.object(nats.aws.ecs, "TaskDefinitionVolumeEfsVolumeConfigurationArgs", side_effect=fake_args),
                patch.object(nats.aws.ecs, "TaskDefinitionVolumeEfsVolumeConfigurationAuthorizationConfigArgs", side_effect=fake_args),
                patch.object(nats.aws.ecs, "Service", side_effect=fake_service),
                patch.object(nats.aws.ecs, "ServiceNetworkConfigurationArgs", side_effect=fake_args),
                patch.object(nats.aws.ecs, "ServiceServiceRegistriesArgs", side_effect=fake_args),
                patch.object(nats.aws.ecs, "ServiceDeploymentCircuitBreakerArgs", side_effect=fake_args),
                patch.object(nats.pulumi, "ResourceOptions", side_effect=fake_args),
                patch.object(nats.pulumi.Output, "concat", side_effect=lambda *values: "".join(str(value) for value in values)),
            ]:
                stack.enter_context(patcher)

            nats.create_nats_service(
                name="cerebro-sec-dev",
                vpc_id="vpc-1",
                subnet_ids=["subnet-1"],
                app_security_group_id="sg-app",
                kms_key_arn="kms-key",
            )

        self.assertEqual(health_check_args, [{"failure_threshold": 1}])
        self.assertEqual(service_args[0]["availability_zone_rebalancing"], "DISABLED")
        self.assertEqual(service_args[0]["deployment_maximum_percent"], 100)
        self.assertEqual(service_args[0]["deployment_minimum_healthy_percent"], 0)


if __name__ == "__main__":
    unittest.main()
