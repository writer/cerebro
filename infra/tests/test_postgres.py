from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.pulumi_test_runtime import ensure_event_loop


ensure_event_loop()

spec = importlib.util.spec_from_file_location("postgres", Path(__file__).resolve().parents[1] / "aws" / "postgres.py")
postgres = importlib.util.module_from_spec(spec)
spec.loader.exec_module(postgres)


class _FakeResource:
    def __init__(self, resource_name: str, **kwargs):
        self.id = f"{resource_name}-id"
        self.name = kwargs.get("name", resource_name)
        self.kwargs = kwargs


class _FakePassword:
    def __init__(self, resource_name: str, **kwargs):
        self.id = f"{resource_name}-id"
        self.result = "generated-password"
        self.kwargs = kwargs


class _FakeInstance(_FakeResource):
    def __init__(self, resource_name: str, **kwargs):
        super().__init__(resource_name, **kwargs)
        self.address = "postgres.example.internal"


class PostgresStorageTest(unittest.TestCase):
    def test_storage_args_default_to_gp3_without_burst_credit_dependency(self) -> None:
        args = postgres._postgres_storage_args(allocated_storage=100, storage_type="")

        self.assertEqual(args["storage_type"], "gp3")
        self.assertEqual(args["max_allocated_storage"], 200)
        self.assertNotIn("iops", args)
        self.assertNotIn("storage_throughput", args)

    def test_storage_args_pass_through_explicit_gp3_capacity(self) -> None:
        args = postgres._postgres_storage_args(
            allocated_storage=400,
            storage_type="gp3",
            max_allocated_storage=800,
            iops=3000,
            storage_throughput=125,
        )

        self.assertEqual(
            args,
            {
                "storage_type": "gp3",
                "max_allocated_storage": 800,
                "iops": 3000,
                "storage_throughput": 125,
            },
        )

    def test_storage_args_reject_invalid_autoscaling_ceiling(self) -> None:
        with self.assertRaises(ValueError):
            postgres._postgres_storage_args(
                allocated_storage=100,
                storage_type="gp3",
                max_allocated_storage=50,
            )

    def test_create_postgres_passes_configurable_storage_options(self) -> None:
        captured_instance_kwargs = {}

        def fake_instance(name: str, **kwargs):
            captured_instance_kwargs.update(kwargs)
            return _FakeInstance(name, **kwargs)

        with (
            patch.object(postgres.aws.ec2, "SecurityGroup", _FakeResource),
            patch.object(postgres.aws.rds, "SubnetGroup", _FakeResource),
            patch.object(postgres.aws.rds, "Instance", fake_instance),
            patch.object(postgres.aws.secretsmanager, "Secret", _FakeResource),
            patch.object(postgres.aws.secretsmanager, "SecretVersion", _FakeResource),
            patch.object(postgres.random, "RandomPassword", _FakePassword),
        ):
            stack = postgres.create_postgres(
                name="cerebro-sec-dev",
                vpc_id="vpc-1",
                subnet_ids=["subnet-1", "subnet-2"],
                app_security_group_id="sg-1",
                kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/example",
                secret_name="cerebro-sec-dev/CEREBRO_POSTGRES_DSN",
                instance_class="db.t4g.small",
                allocated_storage=100,
                max_allocated_storage=200,
                storage_type="gp3",
                iops=3000,
                storage_throughput=125,
                deletion_protection=True,
                apply_immediately=False,
                final_snapshot_identifier="cerebro-sec-dev-postgres-final-review",
            )

        self.assertEqual(stack["instance"].address, "postgres.example.internal")
        kwargs = captured_instance_kwargs
        self.assertEqual(kwargs["instance_class"], "db.t4g.small")
        self.assertEqual(kwargs["allocated_storage"], 100)
        self.assertEqual(kwargs["max_allocated_storage"], 200)
        self.assertEqual(kwargs["storage_type"], "gp3")
        self.assertEqual(kwargs["iops"], 3000)
        self.assertEqual(kwargs["storage_throughput"], 125)
        self.assertIs(kwargs["apply_immediately"], False)
        self.assertEqual(kwargs["final_snapshot_identifier"], "cerebro-sec-dev-postgres-final-review")


if __name__ == "__main__":
    unittest.main()
