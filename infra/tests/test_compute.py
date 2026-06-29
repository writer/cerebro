from __future__ import annotations

from contextlib import ExitStack
import importlib.util
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from pathlib import Path

from tests.pulumi_test_runtime import ensure_event_loop


ensure_event_loop()

spec = importlib.util.spec_from_file_location("compute", Path(__file__).resolve().parents[1] / "aws" / "compute.py")
compute = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compute)


class SourceRuntimeEnvironmentTest(unittest.TestCase):
    def test_adds_role_allowlist_from_source_runtimes(self) -> None:
        env = compute._source_runtime_environment(
            {"CEREBRO_ENVIRONMENT": "sec-dev"},
            [
                {"sourceId": "aws", "tenantId": "writer", "config": {"role_arn": "arn:aws:iam::222222222222:role/cerebro-org-scan-role"}},
                {"source_id": "aws", "tenant_id": "other", "config": {"role_arn": "arn:aws:iam::111111111111:role/cerebro-org-scan-role"}},
                {"sourceId": "aurelius", "tenantId": "writer", "config": {"role_arn": "arn:aws:iam::333333333333:role/cerebro-aurelius-source-dev"}},
                {"sourceId": "github", "config": {"role_arn": "arn:aws:iam::444444444444:role/ignored-without-tenant"}},
            ],
        )
        self.assertEqual(
            env["CEREBRO_AWS_ASSUME_ROLE_ARNS"],
            "other=arn:aws:iam::111111111111:role/cerebro-org-scan-role,writer=arn:aws:iam::222222222222:role/cerebro-org-scan-role,writer=arn:aws:iam::333333333333:role/cerebro-aurelius-source-dev",
        )
        self.assertEqual(env["CEREBRO_ENVIRONMENT"], "sec-dev")

    def test_preserves_explicit_aws_role_allowlist(self) -> None:
        env = compute._source_runtime_environment(
            {"CEREBRO_AWS_ASSUME_ROLE_ARNS": "custom=arn:aws:iam::999999999999:role/custom"},
            [{"sourceId": "aws", "tenantId": "writer", "config": {"role_arn": "arn:aws:iam::111111111111:role/cerebro-org-scan-role"}}],
        )
        self.assertEqual(env["CEREBRO_AWS_ASSUME_ROLE_ARNS"], "custom=arn:aws:iam::999999999999:role/custom")

    def test_adds_gcp_wif_bindings_from_source_runtimes(self) -> None:
        audience = "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/aws"
        service_account = "scanner@writer-iam.iam.gserviceaccount.com"
        env = compute._source_runtime_environment(
            {"CEREBRO_ENVIRONMENT": "sec-dev"},
            [
                {"sourceId": "gcp", "tenantId": "writer", "config": {"wif_audience": audience, "wif_service_account_email": service_account}},
                {"sourceId": "gcp", "tenantId": "writer", "config": {"wif_audience": audience, "wif_service_account_email": service_account}},
                {"sourceId": "gcp", "tenantId": "other", "config": {"wif_audience": "aud-other", "wif_service_account_email": "scanner@other.example"}},
                {"sourceId": "gcp", "config": {"wif_audience": "ignored-without-tenant", "wif_service_account_email": service_account}},
            ],
        )
        self.assertEqual(
            env["CEREBRO_GCP_WIF_BINDINGS"],
            "other=aud-other|scanner@other.example,writer=//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/aws|scanner@writer-iam.iam.gserviceaccount.com",
        )
        self.assertEqual(env["CEREBRO_ENVIRONMENT"], "sec-dev")

    def test_preserves_explicit_gcp_wif_bindings(self) -> None:
        env = compute._source_runtime_environment(
            {"CEREBRO_GCP_WIF_BINDINGS": "writer=aud|scanner@example.com"},
            [{"sourceId": "gcp", "tenantId": "writer", "config": {"wif_audience": "other-aud", "wif_service_account_email": "other@example.com"}}],
        )
        self.assertEqual(env["CEREBRO_GCP_WIF_BINDINGS"], "writer=aud|scanner@example.com")

    def test_extracts_distinct_role_arns_from_source_runtimes(self) -> None:
        self.assertEqual(
            compute._source_runtime_aws_role_arns(
                [
                    {"sourceId": "aws", "config": {"role_arn": "arn:aws:iam::222222222222:role/cerebro-org-scan-role"}},
                    {"sourceId": "aws", "config": {"role_arn": "arn:aws:iam::111111111111:role/cerebro-org-scan-role"}},
                    {"sourceId": "aurelius", "config": {"role_arn": "arn:aws:iam::333333333333:role/cerebro-aurelius-source-dev"}},
                    {"sourceId": "aws", "config": {"role_arn": "arn:aws:iam::222222222222:role/cerebro-org-scan-role"}},
                ]
            ),
            [
                "arn:aws:iam::111111111111:role/cerebro-org-scan-role",
                "arn:aws:iam::222222222222:role/cerebro-org-scan-role",
                "arn:aws:iam::333333333333:role/cerebro-aurelius-source-dev",
            ],
        )

    def test_filters_service_bootstrap_runtimes_by_id(self) -> None:
        source_runtimes = [
            {"id": "writer-evidence-cas-cases", "sourceId": "evidence_cas"},
            {"id": "writer-cosmo-session", "sourceId": "cosmo"},
        ]

        self.assertEqual(
            compute._source_runtime_service_bootstrap_runtimes(
                source_runtimes,
                ["writer-evidence-cas-cases"],
            ),
            [source_runtimes[0]],
        )
        self.assertEqual(
            compute._source_runtime_service_bootstrap_runtimes(source_runtimes, []),
            [],
        )
        self.assertEqual(
            compute._source_runtime_service_bootstrap_runtimes(source_runtimes, None),
            source_runtimes,
        )
        with self.assertRaisesRegex(ValueError, "unknown source runtime"):
            compute._source_runtime_service_bootstrap_runtimes(
                source_runtimes,
                ["writer-missing-runtime"],
            )


class SourceRuntimeBootstrapRegistryTest(unittest.TestCase):
    def test_environment_files_are_retained_and_expose_prefix_arn(self) -> None:
        object_calls: list[dict] = []

        def fake_bucket(*args, **kwargs):
            return SimpleNamespace(
                id="writer-cerebro-sec-dev-source-runtime-bootstrap",
                arn="arn:aws:s3:::writer-cerebro-sec-dev-source-runtime-bootstrap",
            )

        def fake_resource(*args, **kwargs):
            return SimpleNamespace(name=args[0])

        def fake_object(*args, **kwargs):
            object_calls.append(kwargs)
            return SimpleNamespace(
                arn=f"arn:aws:s3:::writer-cerebro-sec-dev-source-runtime-bootstrap/{kwargs['key']}",
            )

        with (
            patch.object(compute.aws.s3, "Bucket", side_effect=fake_bucket),
            patch.object(compute.aws.s3, "BucketPublicAccessBlock", side_effect=fake_resource),
            patch.object(compute.aws.s3, "BucketServerSideEncryptionConfiguration", side_effect=fake_resource),
            patch.object(compute.aws.s3, "BucketVersioning", side_effect=fake_resource),
            patch.object(compute.aws.s3, "BucketObjectv2", side_effect=fake_object),
            patch.object(compute.pulumi.Output, "concat", side_effect=lambda *parts: "".join(parts)),
            patch.object(compute.pulumi, "ResourceOptions", side_effect=lambda **kwargs: SimpleNamespace(**kwargs)),
        ):
            environment_files = compute._create_source_runtime_bootstrap_environment_files(
                "cerebro-sec-dev",
                "kms-key",
                {"orchestrator": '{"runtimes":[]}'},
            )

        self.assertEqual(len(object_calls), 1)
        self.assertTrue(object_calls[0]["opts"].retain_on_delete)
        self.assertEqual(
            environment_files["orchestrator"]["object_prefix_arn"],
            "arn:aws:s3:::writer-cerebro-sec-dev-source-runtime-bootstrap/source-runtime-bootstrap/*",
        )
        self.assertEqual(
            environment_files["orchestrator"]["environment_file_arn"],
            f"arn:aws:s3:::writer-cerebro-sec-dev-source-runtime-bootstrap/{object_calls[0]['key']}",
        )

    def test_execution_role_grants_registry_prefix_and_exposes_policy_dependency(self) -> None:
        policies: list[dict] = []

        class FakeOutputAll:
            def __init__(self, values: tuple):
                self.values = values

            def apply(self, callback):
                return callback(self.values)

        def fake_role(*args, **kwargs):
            return SimpleNamespace(name=kwargs.get("name", args[0]), arn=f"arn:aws:iam::123456789012:role/{args[0]}")

        def fake_policy(*args, **kwargs):
            policy = SimpleNamespace(name=args[0])
            policies.append({"resource": args[0], **kwargs, "result": policy})
            return policy

        with (
            patch.object(compute.aws, "get_region", return_value=SimpleNamespace(region="us-east-1")),
            patch.object(compute.aws, "get_caller_identity", return_value=SimpleNamespace(account_id="123456789012")),
            patch.object(compute.aws.iam, "Role", side_effect=fake_role),
            patch.object(compute.aws.iam, "RolePolicyAttachment", side_effect=lambda *args, **kwargs: SimpleNamespace(name=args[0])),
            patch.object(compute.aws.iam, "RolePolicy", side_effect=fake_policy),
            patch.object(compute.pulumi.Output, "all", side_effect=lambda *values: FakeOutputAll(values)),
        ):
            role = compute._create_execution_role(
                "cerebro-sec-dev",
                "kms-key",
                ["/cerebro/sec-dev"],
                ["arn:aws:s3:::bootstrap/source-runtime-bootstrap/*"],
                ["arn:aws:s3:::bootstrap"],
            )

        policy_document = json.loads(policies[0]["policy"])
        object_statement = next(statement for statement in policy_document["Statement"] if statement.get("Sid") == "ReadSourceRuntimeBootstrapRegistry")
        self.assertEqual(
            object_statement["Resource"],
            ["arn:aws:s3:::bootstrap/source-runtime-bootstrap/*"],
        )
        self.assertIs(role.policy, policies[0]["result"])


class WorkerTaskRoleTest(unittest.TestCase):
    def test_task_role_assume_policy_uses_declared_role_arns_only(self) -> None:
        policies: list[dict] = []

        def fake_role(*args, **kwargs):
            return SimpleNamespace(name=kwargs.get("name", args[0]), id=f"{args[0]}-id", arn=f"arn:aws:iam::123456789012:role/{args[0]}")

        def fake_policy(*args, **kwargs):
            policies.append(kwargs)
            return SimpleNamespace(name=args[0])

        with (
            patch.object(compute.aws.iam, "Role", side_effect=fake_role),
            patch.object(compute.aws.iam, "RolePolicy", side_effect=fake_policy),
        ):
            compute._create_task_role(
                "cerebro-sec-dev",
                assume_role_arns=[
                    "arn:aws:iam::222222222222:role/cerebro-org-scan-role",
                    "arn:aws:iam::111111111111:role/cerebro-org-scan-role",
                ],
            )

        assume_policy = next(policy for policy in policies if policy["policy"].find("sts:TagSession") >= 0)
        self.assertIn("arn:aws:iam::111111111111:role/cerebro-org-scan-role", assume_policy["policy"])
        self.assertIn("arn:aws:iam::222222222222:role/cerebro-org-scan-role", assume_policy["policy"])
        self.assertNotIn("arn:aws:iam::*:role", assume_policy["policy"])

    def test_task_role_grants_bedrock_invoke_to_configured_models(self) -> None:
        policies: list[dict] = []

        def fake_role(*args, **kwargs):
            return SimpleNamespace(name=kwargs.get("name", args[0]), id=f"{args[0]}-id", arn=f"arn:aws:iam::123456789012:role/{args[0]}")

        def fake_policy(*args, **kwargs):
            policies.append(kwargs)
            return SimpleNamespace(name=args[0])

        with (
            patch.object(compute.aws, "get_caller_identity", return_value=SimpleNamespace(account_id="123456789012")),
            patch.object(compute.aws.iam, "Role", side_effect=fake_role),
            patch.object(compute.aws.iam, "RolePolicy", side_effect=fake_policy),
        ):
            compute._create_task_role(
                "cerebro-sec-dev",
                bedrock_model_ids=["us.anthropic.claude-sonnet-4-6"],
            )

        bedrock_policy = next(policy for policy in policies if policy["policy"].find("bedrock:InvokeModel") >= 0)
        document = json.loads(bedrock_policy["policy"])
        statement = document["Statement"][0]
        self.assertEqual(statement["Action"], ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"])
        self.assertCountEqual(
            statement["Resource"],
            [
                "arn:aws:bedrock:*::foundation-model/anthropic.claude-sonnet-4-6",
                "arn:aws:bedrock:*:123456789012:inference-profile/us.anthropic.claude-sonnet-4-6",
            ],
        )

    def test_task_role_grants_otel_collector_export_permissions(self) -> None:
        policies: list[dict] = []

        def fake_role(*args, **kwargs):
            return SimpleNamespace(name=kwargs.get("name", args[0]), id=f"{args[0]}-id", arn=f"arn:aws:iam::123456789012:role/{args[0]}")

        def fake_policy(*args, **kwargs):
            policies.append(kwargs)
            return SimpleNamespace(name=args[0])

        with (
            patch.object(compute.aws.iam, "Role", side_effect=fake_role),
            patch.object(compute.aws.iam, "RolePolicy", side_effect=fake_policy),
        ):
            compute._create_task_role(
                "cerebro-sec-dev",
                enable_otel_collector=True,
            )

        otel_policy = next(policy for policy in policies if policy["policy"].find("xray:PutTraceSegments") >= 0)
        statement = json.loads(otel_policy["policy"])["Statement"][0]
        self.assertEqual(
            statement["Action"],
            [
                "xray:PutTraceSegments",
                "xray:PutTelemetryRecords",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:DescribeLogStreams",
                "logs:PutLogEvents",
                "logs:PutRetentionPolicy",
            ],
        )
        self.assertEqual(statement["Resource"], "*")

    def test_orchestrator_schedule_role_trusts_events_and_scheduler(self) -> None:
        role_calls: list[dict] = []
        policy_calls: list[dict] = []

        def fake_role(*args, **kwargs):
            role_calls.append(kwargs)
            return SimpleNamespace(name=kwargs.get("name", args[0]), arn=f"arn:aws:iam::123456789012:role/{args[0]}")

        with (
            patch.object(compute.aws.iam, "Role", side_effect=fake_role),
            patch.object(compute.aws.iam, "RolePolicy", side_effect=lambda *args, **kwargs: policy_calls.append(kwargs) or SimpleNamespace(name=args[0])),
            patch.object(compute.pulumi.Output, "all", side_effect=lambda *values: SimpleNamespace(apply=lambda callback: callback(values))),
        ):
            compute._create_orchestrator_events_role(
                name="cerebro-sec-dev",
                task_definition_arns=["task-def"],
                execution_role_arn="exec-role",
                task_role_arn="task-role",
                scheduler_dlq_arn="dlq-arn",
            )

        assume_policy = json.loads(role_calls[0]["assume_role_policy"])
        self.assertEqual(
            assume_policy["Statement"][0]["Principal"]["Service"],
            ["events.amazonaws.com", "scheduler.amazonaws.com"],
        )
        role_policy = json.loads(policy_calls[0]["policy"])
        self.assertIn(
            {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": "dlq-arn"},
            role_policy["Statement"],
        )

    def test_orchestrator_uses_separate_worker_task_role(self) -> None:
        task_role_names: list[str] = []
        task_definition_calls: list[dict] = []
        orchestrator_events_role_calls: list[dict] = []
        event_rule_calls: list[dict] = []
        event_target_calls: list[dict] = []
        panopticon_source_runtimes = [
            {
                "id": "writer-panopticon-alerts",
                "sourceId": "panopticon",
                "tenantId": "writer",
                "config": {
                    "base_url": "env:CEREBRO_SOURCE_PANOPTICON_BASE_URL",
                    "family": "alert",
                    "mode": "api",
                    "token": "env:CEREBRO_SOURCE_PANOPTICON_TOKEN",
                },
            },
            {
                "id": "writer-panopticon-cases",
                "sourceId": "panopticon",
                "tenantId": "writer",
                "config": {
                    "base_url": "env:CEREBRO_SOURCE_PANOPTICON_BASE_URL",
                    "family": "case",
                    "mode": "api",
                    "token": "env:CEREBRO_SOURCE_PANOPTICON_TOKEN",
                },
            },
            {
                "id": "writer-panopticon-iocs",
                "sourceId": "panopticon",
                "tenantId": "writer",
                "config": {
                    "base_url": "env:CEREBRO_SOURCE_PANOPTICON_BASE_URL",
                    "family": "ioc",
                    "mode": "api",
                    "token": "env:CEREBRO_SOURCE_PANOPTICON_TOKEN",
                },
            },
        ]

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

        def fake_event_target(*args, **kwargs):
            event_target_calls.append({"resource": args[0], **kwargs})
            return fake_named_resource(*args, **kwargs)

        def fake_event_rule(*args, **kwargs):
            event_rule_calls.append({"resource": args[0], **kwargs})
            return fake_named_resource(*args, **kwargs)

        with (
            patch.object(
                compute,
                "_create_source_runtime_bootstrap_environment_files",
                return_value={
                    "service": {
                        "environment_file_arn": "arn:aws:s3:::bootstrap/service.env",
                        "bucket_arn": "arn:aws:s3:::bootstrap",
                        "object_arn": "arn:aws:s3:::bootstrap/service.env",
                        "object_prefix_arn": "arn:aws:s3:::bootstrap/source-runtime-bootstrap/*",
                        "resources": ["service-env-file"],
                    },
                },
            ),
            patch.object(compute, "_create_execution_role", return_value=SimpleNamespace(arn="arn:aws:iam::123456789012:role/cerebro-sec-dev-exec-role", policy="exec-policy")),
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
            patch.object(compute.aws.cloudwatch, "EventRule", side_effect=fake_event_rule),
            patch.object(compute.aws.cloudwatch, "EventTarget", side_effect=fake_event_target),
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
                        "name": "panopticon-alerts",
                        "command": ["orchestrator", "run", "runtime_id=writer-panopticon-alerts"],
                    }
                ],
                source_runtimes=panopticon_source_runtimes,
                source_runtime_service_bootstrap_ids=["writer-panopticon-cases"],
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
        orchestrator_task_definition = next(call for call in task_definition_calls if call["name"] == "cerebro-sec-dev-orchestrator")
        self.assertEqual([call["name"] for call in task_definition_calls], ["cerebro-sec-dev", "cerebro-sec-dev-orchestrator"])
        self.assertEqual(
            api_task_definition["task_role_arn"],
            "arn:aws:iam::123456789012:role/cerebro-sec-dev-task-role",
        )
        self.assertEqual(
            orchestrator_task_definition["task_role_arn"],
            "arn:aws:iam::123456789012:role/cerebro-sec-dev-worker-task-role",
        )
        self.assertEqual(
            {
                key: api_task_definition["environment"][key]
                for key in ["ECS_CLUSTER", "ECS_SERVICE_NAME", "ECS_TASK_FAMILY"]
            },
            {
                "ECS_CLUSTER": "cerebro-sec-dev-cluster",
                "ECS_SERVICE_NAME": "cerebro-sec-dev-api",
                "ECS_TASK_FAMILY": "cerebro-sec-dev",
            },
        )
        self.assertEqual(
            {
                key: orchestrator_task_definition["environment"][key]
                for key in ["ECS_CLUSTER", "ECS_TASK_FAMILY"]
            },
            {
                "ECS_CLUSTER": "cerebro-sec-dev-cluster",
                "ECS_TASK_FAMILY": "cerebro-sec-dev-orchestrator",
            },
        )
        self.assertNotIn("ECS_SERVICE_NAME", orchestrator_task_definition["environment"])
        self.assertEqual(
            api_task_definition["source_runtime_bootstrap_environment_file_arn"],
            "arn:aws:s3:::bootstrap/service.env",
        )
        self.assertEqual(api_task_definition["depends_on"], ["service-env-file", "exec-policy"])
        self.assertEqual(
            orchestrator_task_definition["source_runtime_bootstrap_environment_file_arn"],
            None,
        )
        self.assertTrue(orchestrator_task_definition["enable_source_runtime_bootstrap"])
        self.assertEqual(orchestrator_task_definition["depends_on"], ["exec-policy"])
        self.assertEqual(
            orchestrator_events_role_calls[0]["task_role_arn"],
            "arn:aws:iam::123456789012:role/cerebro-sec-dev-worker-task-role",
        )
        self.assertEqual(
            orchestrator_events_role_calls[0]["task_definition_arns"],
            ["arn:aws:ecs:us-east-1:123456789012:task-definition/cerebro-sec-dev-orchestrator:1"],
        )
        self.assertEqual(
            event_target_calls[0]["ecs_target"].task_definition_arn,
            "arn:aws:ecs:us-east-1:123456789012:task-definition/cerebro-sec-dev-orchestrator:1",
        )
        self.assertEqual(event_rule_calls[0]["state"], "ENABLED")
        self.assertNotIn("is_enabled", event_rule_calls[0])
        target_input = json.loads(event_target_calls[0]["input"])
        self.assertEqual(
            target_input["containerOverrides"][0],
            {"name": "cerebro", "command": ["orchestrator", "run", "runtime_id=writer-panopticon-alerts"]},
        )
        bootstrap_override = target_input["containerOverrides"][1]
        self.assertEqual(bootstrap_override["name"], "source-runtime-bootstrap")
        self.assertEqual(bootstrap_override["environmentFiles"], [])
        bootstrap_payload = json.loads(bootstrap_override["environment"][0]["value"])
        self.assertEqual(
            [runtime["id"] for runtime in bootstrap_payload["runtimes"]],
            ["writer-panopticon-alerts"],
        )

    def test_scheduler_backend_uses_eventbridge_scheduler(self) -> None:
        task_definition_calls: list[dict] = []
        scheduler_group_calls: list[dict] = []
        scheduler_dlq_calls: list[dict] = []
        scheduler_schedule_calls: list[dict] = []
        event_target_calls: list[dict] = []

        def fake_named_resource(*args, **kwargs):
            name = kwargs.get("name") or args[0]
            return SimpleNamespace(name=name, id=f"{name}-id", arn=f"arn:aws:test::{name}")

        def fake_args(**kwargs):
            return SimpleNamespace(**kwargs)

        def fake_task_definition(**kwargs):
            task_definition_calls.append(kwargs)
            return SimpleNamespace(arn=f"arn:aws:ecs:us-east-1:123456789012:task-definition/{kwargs['name']}:1")

        def fake_scheduler_group(*args, **kwargs):
            scheduler_group_calls.append({"resource": args[0], **kwargs})
            return SimpleNamespace(name=kwargs["name"], arn=f"arn:aws:scheduler:us-east-1:123456789012:schedule-group/{kwargs['name']}")

        def fake_scheduler_schedule(*args, **kwargs):
            scheduler_schedule_calls.append({"resource": args[0], **kwargs})
            return SimpleNamespace(name=kwargs["name"], arn=f"arn:aws:scheduler:us-east-1:123456789012:schedule/{kwargs['group_name']}/{kwargs['name']}")

        def fake_sqs_queue(*args, **kwargs):
            scheduler_dlq_calls.append({"resource": args[0], **kwargs})
            return SimpleNamespace(name=kwargs["name"], arn=f"arn:aws:sqs:us-east-1:123456789012:{kwargs['name']}")

        with ExitStack() as stack:
            for patcher in [
                patch.object(compute, "_create_execution_role", return_value=SimpleNamespace(arn="arn:aws:iam::123456789012:role/cerebro-sec-dev-exec-role", policy="exec-policy")),
                patch.object(compute, "_create_task_role", return_value=SimpleNamespace(name="task-role", arn="arn:aws:iam::123456789012:role/task-role")),
                patch.object(compute, "_create_task_definition", side_effect=fake_task_definition),
                patch.object(compute, "_create_orchestrator_events_role", return_value=SimpleNamespace(arn="arn:aws:iam::123456789012:role/cerebro-sec-dev-orchestrator-events-role")),
                patch.object(compute.aws.ecs, "Cluster", side_effect=fake_named_resource),
                patch.object(compute.aws.ecs, "ClusterCapacityProviders", side_effect=fake_named_resource),
                patch.object(compute.aws.ecs, "ClusterCapacityProvidersDefaultCapacityProviderStrategyArgs", side_effect=fake_args),
                patch.object(compute.aws.ecs, "Service", side_effect=fake_named_resource),
                patch.object(compute.aws.ecs, "ServiceCapacityProviderStrategyArgs", side_effect=fake_args),
                patch.object(compute.aws.ecs, "ServiceNetworkConfigurationArgs", side_effect=fake_args),
                patch.object(compute.aws.ecs, "ServiceLoadBalancerArgs", side_effect=fake_args),
                patch.object(compute.aws.ecs, "ServiceDeploymentCircuitBreakerArgs", side_effect=fake_args),
                patch.object(compute.aws.cloudwatch, "LogGroup", side_effect=fake_named_resource),
                patch.object(compute.aws.cloudwatch, "EventTarget", side_effect=lambda *args, **kwargs: event_target_calls.append(kwargs) or fake_named_resource(*args, **kwargs)),
                patch.object(compute.aws.scheduler, "ScheduleGroup", side_effect=fake_scheduler_group),
                patch.object(compute.aws.scheduler, "Schedule", side_effect=fake_scheduler_schedule),
                patch.object(compute.aws.scheduler, "ScheduleFlexibleTimeWindowArgs", side_effect=fake_args),
                patch.object(compute.aws.scheduler, "ScheduleTargetArgs", side_effect=fake_args),
                patch.object(compute.aws.scheduler, "ScheduleTargetEcsParametersArgs", side_effect=fake_args),
                patch.object(compute.aws.scheduler, "ScheduleTargetEcsParametersNetworkConfigurationArgs", side_effect=fake_args),
                patch.object(compute.aws.scheduler, "ScheduleTargetRetryPolicyArgs", side_effect=fake_args),
                patch.object(compute.aws.scheduler, "ScheduleTargetDeadLetterConfigArgs", side_effect=fake_args),
                patch.object(compute.aws.sqs, "Queue", side_effect=fake_sqs_queue),
                patch.object(compute.aws.appautoscaling, "Target", side_effect=fake_named_resource),
                patch.object(compute.pulumi, "ResourceOptions", side_effect=fake_args),
            ]:
                stack.enter_context(patcher)
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
                        "name": "gcp-writer-iam-audit",
                        "backend": "scheduler",
                        "state": "DISABLED",
                        "flexibleWindowMinutes": 10,
                        "command": ["orchestrator", "run", "runtime_id=writer-gcp-prod-writer-iam-audit"],
                    }
                ],
            )

        self.assertEqual(event_target_calls, [])
        self.assertEqual(scheduler_group_calls[0]["name"], "cerebro-sec-dev-orchestrator")
        self.assertEqual(scheduler_dlq_calls[0]["name"], "cerebro-sec-dev-orchestrator-scheduler-dlq")
        schedule_call = scheduler_schedule_calls[0]
        self.assertEqual(schedule_call["name"], "cerebro-sec-dev-orchestrator-gcp-writer-iam-audit")
        self.assertEqual(schedule_call["group_name"], "cerebro-sec-dev-orchestrator")
        self.assertEqual(schedule_call["state"], "DISABLED")
        self.assertEqual(schedule_call["flexible_time_window"].maximum_window_in_minutes, 10)
        self.assertEqual(schedule_call["target"].dead_letter_config.arn, "arn:aws:sqs:us-east-1:123456789012:cerebro-sec-dev-orchestrator-scheduler-dlq")
        self.assertEqual(
            json.loads(schedule_call["target"].input),
            {"containerOverrides": [{"name": "cerebro", "command": ["orchestrator", "run", "runtime_id=writer-gcp-prod-writer-iam-audit"]}]},
        )
        self.assertEqual(
            schedule_call["target"].ecs_parameters.task_definition_arn,
            "arn:aws:ecs:us-east-1:123456789012:task-definition/cerebro-sec-dev-orchestrator:1",
        )
        self.assertEqual(len(result["orchestrator_scheduler_schedules"]), 1)
        self.assertEqual(result["orchestrator_scheduler_dlq"].name, "cerebro-sec-dev-orchestrator-scheduler-dlq")
        self.assertEqual(result["orchestrator_rules"], [])

    def test_task_definition_bootstraps_panopticon_source_runtimes(self) -> None:
        task_definition_calls: list[dict] = []

        class FakeOutputAll:
            def __init__(self, values: tuple):
                self.values = values

            def apply(self, callback):
                return callback(self.values)

        def fake_task_definition(*args, **kwargs):
            task_definition_calls.append({"resource": args[0], **kwargs})
            return SimpleNamespace(arn=f"arn:aws:ecs:us-east-1:123456789012:task-definition/{kwargs['family']}:1")

        with (
            patch.object(compute.aws, "get_region", return_value=SimpleNamespace(region="us-east-1")),
            patch.object(compute.aws, "get_caller_identity", return_value=SimpleNamespace(account_id="123456789012")),
            patch.object(compute.aws.ecs, "TaskDefinition", side_effect=fake_task_definition),
            patch.object(compute.aws.ecs, "TaskDefinitionRuntimePlatformArgs", side_effect=lambda **kwargs: SimpleNamespace(**kwargs)),
            patch.object(compute.pulumi.Output, "all", side_effect=lambda *values: FakeOutputAll(values)),
        ):
            compute._create_task_definition(
                name="cerebro-sec-dev-orchestrator",
                container_image="image",
                cpu=1024,
                memory=2048,
                execution_role_arn="exec-role",
                task_role_arn="task-role",
                log_group_name="/ecs/cerebro-sec-dev",
                environment={"CEREBRO_ENVIRONMENT": "sec-dev"},
                secret_keys=[],
                external_secrets_prefix="/cerebro/sec-dev",
                container_command=["orchestrator", "run", "source_id=panopticon"],
                expose_http=False,
                enable_health_check=False,
                log_stream_prefix="orchestrator",
                source_runtimes=[
                    {"id": "writer-panopticon-alerts", "sourceId": "panopticon", "tenantId": "writer", "config": {"kind": "alerts"}},
                    {"id": "writer-panopticon-cases", "sourceId": "panopticon", "tenantId": "writer", "config": {"kind": "cases"}},
                    {"id": "writer-panopticon-iocs", "sourceId": "panopticon", "tenantId": "writer", "config": {"kind": "iocs"}},
                ],
            )

        containers = json.loads(task_definition_calls[0]["container_definitions"])
        bootstrap_container = next(container for container in containers if container["name"] == "source-runtime-bootstrap")
        cerebro_container = next(container for container in containers if container["name"] == "cerebro")
        bootstrap_env = {entry["name"]: entry["value"] for entry in bootstrap_container["environment"]}
        bootstrap_payload = json.loads(bootstrap_env["CEREBRO_SOURCE_RUNTIME_BOOTSTRAP_JSON"])
        runtime_ids = [runtime["id"] for runtime in bootstrap_payload["runtimes"]]

        self.assertFalse(bootstrap_container["essential"])
        self.assertEqual(
            bootstrap_container["command"],
            ["source-runtime", "bootstrap", "env=CEREBRO_SOURCE_RUNTIME_BOOTSTRAP_JSON"],
        )
        self.assertEqual(
            runtime_ids,
            ["writer-panopticon-alerts", "writer-panopticon-cases", "writer-panopticon-iocs"],
        )
        self.assertEqual(
            cerebro_container["dependsOn"],
            [{"containerName": "source-runtime-bootstrap", "condition": "SUCCESS"}],
        )

    def test_task_definition_deduplicates_identical_secret_env_entries(self) -> None:
        task_definition_calls: list[dict] = []

        class FakeOutputAll:
            def __init__(self, values: tuple):
                self.values = values

            def apply(self, callback):
                return callback(self.values)

        def fake_task_definition(*args, **kwargs):
            task_definition_calls.append({"resource": args[0], **kwargs})
            return SimpleNamespace(arn=f"arn:aws:ecs:us-east-1:123456789012:task-definition/{kwargs['family']}:1")

        with (
            patch.object(compute.aws, "get_region", return_value=SimpleNamespace(region="us-east-1")),
            patch.object(compute.aws, "get_caller_identity", return_value=SimpleNamespace(account_id="123456789012")),
            patch.object(compute.aws.ecs, "TaskDefinition", side_effect=fake_task_definition),
            patch.object(compute.aws.ecs, "TaskDefinitionRuntimePlatformArgs", side_effect=lambda **kwargs: SimpleNamespace(**kwargs)),
            patch.object(compute.pulumi.Output, "all", side_effect=lambda *values: FakeOutputAll(values)),
        ):
            compute._create_task_definition(
                name="cerebro-sec-dev",
                container_image="image",
                cpu=1024,
                memory=2048,
                execution_role_arn="exec-role",
                task_role_arn="task-role",
                log_group_name="/ecs/cerebro-sec-dev",
                environment={"CEREBRO_ENVIRONMENT": "sec-dev"},
                secret_keys=[
                    {"name": "SOURCE_BASE_URL", "source": "SOURCE_BASE_URL", "prefix": "/cerebro/sec-dev"},
                    {"name": "SOURCE_BASE_URL", "source": "SOURCE_BASE_URL", "prefix": "/cerebro/sec-dev"},
                    {"name": "SOURCE_TOKEN", "source": "SOURCE_TOKEN", "prefix": "/cerebro/sec-dev"},
                ],
                external_secrets_prefix="/cerebro/sec-dev",
            )

        containers = json.loads(task_definition_calls[0]["container_definitions"])
        cerebro_container = next(container for container in containers if container["name"] == "cerebro")
        self.assertEqual(
            cerebro_container["secrets"],
            [
                {
                    "name": "SOURCE_BASE_URL",
                    "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:/cerebro/sec-dev/SOURCE_BASE_URL",
                },
                {
                    "name": "SOURCE_TOKEN",
                    "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:/cerebro/sec-dev/SOURCE_TOKEN",
                },
            ],
        )

    def test_task_definition_rejects_secret_env_name_conflicts(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate ECS secret env name"):
            compute._container_secret_specs(
                [
                    {"name": "SOURCE_BASE_URL", "source": "SOURCE_BASE_URL", "prefix": "/cerebro/sec-dev"},
                    {"name": "SOURCE_BASE_URL", "source": "OTHER_SOURCE_BASE_URL", "prefix": "/cerebro/sec-dev"},
                ],
                "/cerebro/sec-dev",
            )

    def test_task_definition_uses_bootstrap_environment_file(self) -> None:
        task_definition_calls: list[dict] = []

        class FakeOutputAll:
            def __init__(self, values: tuple):
                self.values = values

            def apply(self, callback):
                return callback(self.values)

        def fake_task_definition(*args, **kwargs):
            task_definition_calls.append({"resource": args[0], **kwargs})
            return SimpleNamespace(arn=f"arn:aws:ecs:us-east-1:123456789012:task-definition/{kwargs['family']}:1")

        with (
            patch.object(compute.aws, "get_region", return_value=SimpleNamespace(region="us-east-1")),
            patch.object(compute.aws, "get_caller_identity", return_value=SimpleNamespace(account_id="123456789012")),
            patch.object(compute.aws.ecs, "TaskDefinition", side_effect=fake_task_definition),
            patch.object(compute.aws.ecs, "TaskDefinitionRuntimePlatformArgs", side_effect=lambda **kwargs: SimpleNamespace(**kwargs)),
            patch.object(compute.pulumi.Output, "all", side_effect=lambda *values: FakeOutputAll(values)),
        ):
            compute._create_task_definition(
                name="cerebro-sec-dev-orchestrator",
                container_image="image",
                cpu=1024,
                memory=2048,
                execution_role_arn="exec-role",
                task_role_arn="task-role",
                log_group_name="/ecs/cerebro-sec-dev",
                environment={"CEREBRO_ENVIRONMENT": "sec-dev"},
                secret_keys=[],
                external_secrets_prefix="/cerebro/sec-dev",
                expose_http=False,
                enable_health_check=False,
                source_runtime_bootstrap_environment_file_arn="arn:aws:s3:::bootstrap/orchestrator.env",
            )

        containers = json.loads(task_definition_calls[0]["container_definitions"])
        bootstrap_container = next(container for container in containers if container["name"] == "source-runtime-bootstrap")
        self.assertEqual(
            bootstrap_container["environmentFiles"],
            [{"value": "arn:aws:s3:::bootstrap/orchestrator.env", "type": "s3"}],
        )
        bootstrap_env = {entry["name"]: entry["value"] for entry in bootstrap_container["environment"]}
        self.assertNotIn("CEREBRO_SOURCE_RUNTIME_BOOTSTRAP_JSON", bootstrap_env)

    def test_task_definition_can_enable_bootstrap_container_without_payload(self) -> None:
        task_definition_calls: list[dict] = []

        class FakeOutputAll:
            def __init__(self, values: tuple):
                self.values = values

            def apply(self, callback):
                return callback(self.values)

        def fake_task_definition(*args, **kwargs):
            task_definition_calls.append({"resource": args[0], **kwargs})
            return SimpleNamespace(arn=f"arn:aws:ecs:us-east-1:123456789012:task-definition/{kwargs['family']}:1")

        with (
            patch.object(compute.aws, "get_region", return_value=SimpleNamespace(region="us-east-1")),
            patch.object(compute.aws, "get_caller_identity", return_value=SimpleNamespace(account_id="123456789012")),
            patch.object(compute.aws.ecs, "TaskDefinition", side_effect=fake_task_definition),
            patch.object(compute.aws.ecs, "TaskDefinitionRuntimePlatformArgs", side_effect=lambda **kwargs: SimpleNamespace(**kwargs)),
            patch.object(compute.pulumi.Output, "all", side_effect=lambda *values: FakeOutputAll(values)),
        ):
            compute._create_task_definition(
                name="cerebro-sec-dev-orchestrator",
                container_image="image",
                cpu=1024,
                memory=2048,
                execution_role_arn="exec-role",
                task_role_arn="task-role",
                log_group_name="/ecs/cerebro-sec-dev",
                environment={"CEREBRO_ENVIRONMENT": "sec-dev"},
                secret_keys=[],
                external_secrets_prefix="/cerebro/sec-dev",
                expose_http=False,
                enable_health_check=False,
                enable_source_runtime_bootstrap=True,
            )

        containers = json.loads(task_definition_calls[0]["container_definitions"])
        bootstrap_container = next(container for container in containers if container["name"] == "source-runtime-bootstrap")
        self.assertNotIn("environmentFiles", bootstrap_container)
        bootstrap_env = {entry["name"]: entry["value"] for entry in bootstrap_container["environment"]}
        self.assertNotIn("CEREBRO_SOURCE_RUNTIME_BOOTSTRAP_JSON", bootstrap_env)

    def test_task_definition_includes_otel_collector_sidecar(self) -> None:
        task_definition_calls: list[dict] = []

        class FakeOutputAll:
            def __init__(self, values: tuple):
                self.values = values

            def apply(self, callback):
                return callback(self.values)

        def fake_task_definition(*args, **kwargs):
            task_definition_calls.append({"resource": args[0], **kwargs})
            return SimpleNamespace(arn=f"arn:aws:ecs:us-east-1:123456789012:task-definition/{kwargs['family']}:1")

        with (
            patch.object(compute.aws, "get_region", return_value=SimpleNamespace(region="us-east-1")),
            patch.object(compute.aws, "get_caller_identity", return_value=SimpleNamespace(account_id="123456789012")),
            patch.object(compute.aws.ecs, "TaskDefinition", side_effect=fake_task_definition),
            patch.object(compute.aws.ecs, "TaskDefinitionRuntimePlatformArgs", side_effect=lambda **kwargs: SimpleNamespace(**kwargs)),
            patch.object(compute.pulumi.Output, "all", side_effect=lambda *values: FakeOutputAll(values)),
        ):
            compute._create_task_definition(
                name="cerebro-sec-dev",
                container_image="image",
                cpu=1024,
                memory=2048,
                execution_role_arn="exec-role",
                task_role_arn="task-role",
                log_group_name="/ecs/cerebro-sec-dev",
                environment={"CEREBRO_ENVIRONMENT": "sec-dev"},
                secret_keys=[],
                external_secrets_prefix="/cerebro/sec-dev",
                otel_collector_log_group_name="/ecs/cerebro-sec-dev/otel-collector",
                otel_collector={
                    "enabled": True,
                    "image": "public.ecr.aws/aws-observability/aws-otel-collector:v0.48.0",
                    "config_secret_name": "CEREBRO_OTEL_COLLECTOR_CONFIG",
                    "config_secret_prefix": "/cerebro/sec-dev",
                    "config_fingerprint": "abc123",
                    "cpu": 128,
                    "memory": 256,
                },
            )

        containers = json.loads(task_definition_calls[0]["container_definitions"])
        collector_container = next(container for container in containers if container["name"] == "otel-collector")
        cerebro_container = next(container for container in containers if container["name"] == "cerebro")

        self.assertEqual(containers[0]["name"], "otel-collector")
        self.assertEqual(collector_container["image"], "public.ecr.aws/aws-observability/aws-otel-collector:v0.48.0")
        self.assertEqual(collector_container["cpu"], 128)
        self.assertEqual(collector_container["memoryReservation"], 256)
        self.assertEqual(
            collector_container["secrets"],
            [
                {
                    "name": "AOT_CONFIG_CONTENT",
                    "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:/cerebro/sec-dev/CEREBRO_OTEL_COLLECTOR_CONFIG",
                }
            ],
        )
        self.assertEqual(
            collector_container["logConfiguration"]["options"]["awslogs-stream-prefix"],
            "otel-collector",
        )
        self.assertEqual(
            collector_container["logConfiguration"]["options"]["awslogs-group"],
            "/ecs/cerebro-sec-dev/otel-collector",
        )
        self.assertEqual(
            collector_container["environment"],
            [
                {"name": "AWS_REGION", "value": "us-east-1"},
                {"name": "AWS_DEFAULT_REGION", "value": "us-east-1"},
                {"name": "CEREBRO_OTEL_COLLECTOR_CONFIG_SHA256", "value": "abc123"},
            ],
        )
        self.assertEqual(
            collector_container["healthCheck"]["command"],
            ["CMD", "/healthcheck"],
        )
        self.assertEqual(
            cerebro_container["dependsOn"],
            [{"containerName": "otel-collector", "condition": "HEALTHY"}],
        )

    def test_cluster_uses_dedicated_otel_collector_log_group(self) -> None:
        task_definition_calls: list[dict] = []
        task_role_calls: list[dict] = []
        log_group_names: list[str] = []

        def fake_named_resource(*args, **kwargs):
            name = kwargs.get("name") or args[0]
            if args[0].endswith("-logs"):
                log_group_names.append(name)
            return SimpleNamespace(name=name, id=f"{name}-id", arn=f"arn:aws:test::{name}", resource_id=kwargs.get("resource_id", f"{name}-resource"))

        def fake_args(**kwargs):
            return SimpleNamespace(**kwargs)

        def fake_task_role(*args, **kwargs):
            task_role_calls.append({"name": args[0], **kwargs})
            return SimpleNamespace(name=f"{args[0]}-task-role", arn=f"arn:aws:iam::123456789012:role/{args[0]}-task-role")

        def fake_task_definition(*args, **kwargs):
            task_definition_calls.append(kwargs)
            return SimpleNamespace(arn=f"arn:aws:ecs:us-east-1:123456789012:task-definition/{kwargs['name']}:1")

        with (
            patch.object(compute, "_create_execution_role", return_value=SimpleNamespace(arn="arn:aws:iam::123456789012:role/cerebro-sec-dev-exec-role")),
            patch.object(compute, "_create_task_role", side_effect=fake_task_role),
            patch.object(compute, "_create_task_definition", side_effect=fake_task_definition),
            patch.object(compute.aws.ecs, "Cluster", side_effect=fake_named_resource),
            patch.object(compute.aws.ecs, "ClusterCapacityProviders", side_effect=fake_named_resource),
            patch.object(compute.aws.ecs, "ClusterCapacityProvidersDefaultCapacityProviderStrategyArgs", side_effect=fake_args),
            patch.object(compute.aws.ecs, "Service", side_effect=fake_named_resource),
            patch.object(compute.aws.ecs, "ServiceCapacityProviderStrategyArgs", side_effect=fake_args),
            patch.object(compute.aws.ecs, "ServiceNetworkConfigurationArgs", side_effect=fake_args),
            patch.object(compute.aws.ecs, "ServiceLoadBalancerArgs", side_effect=fake_args),
            patch.object(compute.aws.ecs, "ServiceDeploymentCircuitBreakerArgs", side_effect=fake_args),
            patch.object(compute.aws.cloudwatch, "LogGroup", side_effect=fake_named_resource),
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
                otel_collector={
                    "enabled": True,
                    "image": "public.ecr.aws/aws-observability/aws-otel-collector:v0.48.0",
                    "config_secret_name": "CEREBRO_OTEL_COLLECTOR_CONFIG",
                },
            )

        self.assertIn("/ecs/cerebro-sec-dev", log_group_names)
        self.assertIn("/ecs/cerebro-sec-dev/otel-collector", log_group_names)
        self.assertEqual(result["otel_collector_log_group"].name, "/ecs/cerebro-sec-dev/otel-collector")
        self.assertEqual(task_definition_calls[0]["otel_collector_log_group_name"], "/ecs/cerebro-sec-dev/otel-collector")
        self.assertTrue(task_role_calls[0]["enable_otel_collector"])


class ServiceAutoscalingTest(unittest.TestCase):
    def test_api_autoscaling_tracks_cpu_and_memory(self) -> None:
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
            patch.object(compute, "_create_execution_role", return_value=SimpleNamespace(arn="arn:aws:iam::123456789012:role/cerebro-sec-dev-exec-role")),
            patch.object(compute, "_create_task_role", return_value=SimpleNamespace(name="cerebro-sec-dev-task-role", arn="arn:aws:iam::123456789012:role/cerebro-sec-dev-task-role")),
            patch.object(compute, "_create_task_definition", return_value=SimpleNamespace(arn="arn:aws:ecs:us-east-1:123456789012:task-definition/cerebro-sec-dev:1")),
            patch.object(compute.aws.ecs, "Cluster", side_effect=fake_named_resource),
            patch.object(compute.aws.ecs, "ClusterCapacityProviders", side_effect=fake_named_resource),
            patch.object(compute.aws.ecs, "ClusterCapacityProvidersDefaultCapacityProviderStrategyArgs", side_effect=fake_args),
            patch.object(compute.aws.ecs, "Service", side_effect=fake_named_resource),
            patch.object(compute.aws.ecs, "ServiceCapacityProviderStrategyArgs", side_effect=fake_args),
            patch.object(compute.aws.ecs, "ServiceNetworkConfigurationArgs", side_effect=fake_args),
            patch.object(compute.aws.ecs, "ServiceLoadBalancerArgs", side_effect=fake_args),
            patch.object(compute.aws.ecs, "ServiceDeploymentCircuitBreakerArgs", side_effect=fake_args),
            patch.object(compute.aws.cloudwatch, "LogGroup", side_effect=fake_named_resource),
            patch.object(compute.aws.appautoscaling, "Target", side_effect=fake_named_resource),
            patch.object(compute.aws.appautoscaling, "Policy", side_effect=fake_policy),
            patch.object(compute.aws.appautoscaling, "PolicyTargetTrackingScalingPolicyConfigurationArgs", side_effect=fake_args),
            patch.object(compute.aws.appautoscaling, "PolicyTargetTrackingScalingPolicyConfigurationPredefinedMetricSpecificationArgs", side_effect=fake_args),
            patch.object(compute.pulumi, "ResourceOptions", side_effect=fake_args),
        ):
            compute.create_ecs_cluster(
                name="cerebro-sec-dev",
                vpc_id="vpc-1",
                subnet_ids=["subnet-1"],
                security_group_id="sg-1",
                kms_key_id="key-1",
                target_group_arn="tg-1",
                container_image="image",
                external_secrets_prefix="/cerebro/sec-dev",
                api_min_instances=1,
                api_max_instances=3,
            )

        metrics = {
            call["target_tracking_scaling_policy_configuration"].predefined_metric_specification.predefined_metric_type
            for call in policy_calls
        }
        self.assertEqual(
            metrics,
            {"ECSServiceAverageCPUUtilization", "ECSServiceAverageMemoryUtilization"},
        )

    def test_api_autoscaling_can_track_alb_request_count_per_target(self) -> None:
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
            patch.object(compute, "_create_execution_role", return_value=SimpleNamespace(arn="arn:aws:iam::123456789012:role/cerebro-sec-dev-exec-role")),
            patch.object(compute, "_create_task_role", return_value=SimpleNamespace(name="cerebro-sec-dev-task-role", arn="arn:aws:iam::123456789012:role/cerebro-sec-dev-task-role")),
            patch.object(compute, "_create_task_definition", return_value=SimpleNamespace(arn="arn:aws:ecs:us-east-1:123456789012:task-definition/cerebro-sec-dev:1")),
            patch.object(compute.aws.ecs, "Cluster", side_effect=fake_named_resource),
            patch.object(compute.aws.ecs, "ClusterCapacityProviders", side_effect=fake_named_resource),
            patch.object(compute.aws.ecs, "ClusterCapacityProvidersDefaultCapacityProviderStrategyArgs", side_effect=fake_args),
            patch.object(compute.aws.ecs, "Service", side_effect=fake_named_resource),
            patch.object(compute.aws.ecs, "ServiceCapacityProviderStrategyArgs", side_effect=fake_args),
            patch.object(compute.aws.ecs, "ServiceNetworkConfigurationArgs", side_effect=fake_args),
            patch.object(compute.aws.ecs, "ServiceLoadBalancerArgs", side_effect=fake_args),
            patch.object(compute.aws.ecs, "ServiceDeploymentCircuitBreakerArgs", side_effect=fake_args),
            patch.object(compute.aws.cloudwatch, "LogGroup", side_effect=fake_named_resource),
            patch.object(compute.aws.appautoscaling, "Target", side_effect=fake_named_resource),
            patch.object(compute.aws.appautoscaling, "Policy", side_effect=fake_policy),
            patch.object(compute.aws.appautoscaling, "PolicyTargetTrackingScalingPolicyConfigurationArgs", side_effect=fake_args),
            patch.object(compute.aws.appautoscaling, "PolicyTargetTrackingScalingPolicyConfigurationPredefinedMetricSpecificationArgs", side_effect=fake_args),
            patch.object(compute.pulumi, "Output", SimpleNamespace(concat=lambda *args: "".join(str(arg) for arg in args))),
            patch.object(compute.pulumi, "ResourceOptions", side_effect=fake_args),
        ):
            compute.create_ecs_cluster(
                name="cerebro-sec-dev",
                vpc_id="vpc-1",
                subnet_ids=["subnet-1"],
                security_group_id="sg-1",
                kms_key_id="key-1",
                target_group_arn="tg-1",
                container_image="image",
                external_secrets_prefix="/cerebro/sec-dev",
                api_min_instances=1,
                api_max_instances=3,
                alb_arn_suffix="app/alb/123",
                target_group_arn_suffix="targetgroup/api/456",
                api_request_count_per_target_scaling_target=300,
            )

        request_policy = next(call for call in policy_calls if call["name"] == "cerebro-sec-dev-request-count-scaling")
        metric_spec = request_policy["target_tracking_scaling_policy_configuration"].predefined_metric_specification
        self.assertEqual(metric_spec.predefined_metric_type, "ALBRequestCountPerTarget")
        self.assertEqual(metric_spec.resource_label, "app/alb/123/targetgroup/api/456")


if __name__ == "__main__":
    unittest.main()
