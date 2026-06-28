from __future__ import annotations

from pathlib import Path
import sys
from typing import Any

import pulumi
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aws_stack import _container_definition, _existing_aws_secret_refs
from azure_stack import _container_app_secret_refs, _container_app_secrets, _managed_identity
from gcp_stack import _cloud_run_job_run_uri, _existing_gcp_secret_refs
from runtime import CerebroRuntimeConfig, ExistingSecretRef, ScheduledJob


class RecordingMocks(pulumi.runtime.Mocks):
    def __init__(self) -> None:
        self.resources: list[pulumi.runtime.MockResourceArgs] = []

    def new_resource(self, args: pulumi.runtime.MockResourceArgs) -> tuple[str, dict[str, Any]]:
        self.resources.append(args)
        return f"{args.name}_id", dict(args.inputs)

    def call(self, args: pulumi.runtime.MockCallArgs) -> tuple[dict[str, Any], None]:
        return dict(args.args), None


MOCKS = RecordingMocks()
pulumi.runtime.set_mocks(MOCKS, project="cerebro-cloud-pulumi", stack="unit", preview=True)


@pytest.fixture(autouse=True)
def clear_mocks() -> None:
    MOCKS.resources.clear()


def test_production_guardrails_block_unsafe_public_config() -> None:
    config = _config(
        "aws",
        deployment_profile="production",
        image="ghcr.io/writer/cerebro:latest",
        api_auth_enabled=False,
        public_origin="http://cerebro.example.com",
    )

    with pytest.raises(ValueError, match="unsafe production deployment config"):
        config.validate_guardrails()


def test_production_guardrails_allow_documented_override() -> None:
    config = _config(
        "aws",
        deployment_profile="production",
        allow_unsafe_production=True,
        unsafe_production_justification="temporary private preview behind a controlled edge",
        image="ghcr.io/writer/cerebro:latest",
        api_auth_enabled=False,
        edge_auth_managed=True,
    )

    config.validate_guardrails()


def test_aws_secret_refs_drive_state_store_env_without_copying_secret_values() -> None:
    config = _config(
        "aws",
        existing_secret_refs=[
            ExistingSecretRef(
                name="CEREBRO_POSTGRES_DSN",
                aws_arn="arn:aws:secretsmanager:us-east-1:111122223333:secret:cerebro/postgres",
            )
        ],
        scheduled_jobs=[_scheduled_job()],
    )

    secret_refs = _existing_aws_secret_refs(config.existing_secret_refs)
    container = _container_definition(config, "/ecs/unit-aws", secret_refs)

    assert secret_refs == [
        {
            "name": "CEREBRO_POSTGRES_DSN",
            "arn": "arn:aws:secretsmanager:us-east-1:111122223333:secret:cerebro/postgres",
        }
    ]
    assert {"name": "CEREBRO_STATE_STORE_DRIVER", "value": "postgres"} in container["environment"]
    assert container["secrets"] == [{"name": "CEREBRO_POSTGRES_DSN", "valueFrom": secret_refs[0]["arn"]}]


def test_gcp_existing_secret_ref_and_scheduler_target_uri_are_stable() -> None:
    config = _config(
        "gcp",
        existing_secret_refs=[
            ExistingSecretRef(
                name="CEREBRO_POSTGRES_DSN",
                gcp_secret="projects/example-project/secrets/cerebro-postgres-dsn",
                gcp_version="latest",
            )
        ],
        scheduled_jobs=[_scheduled_job(schedule="*/15 * * * *")],
    )

    secret_refs = _existing_gcp_secret_refs(config.existing_secret_refs)
    uri = _cloud_run_job_run_uri(config, "unit-gcp-sync-example")

    assert secret_refs == [
        {
            "name": "CEREBRO_POSTGRES_DSN",
            "secret": "projects/example-project/secrets/cerebro-postgres-dsn",
            "version": "latest",
        }
    ]
    assert uri == (
        "https://us-central1-run.googleapis.com/apis/run.googleapis.com/v1/"
        "namespaces/example-project/jobs/unit-gcp-sync-example:run"
    )


def test_azure_key_vault_secret_ref_enables_system_identity() -> None:
    config = _config(
        "azure",
        existing_secret_refs=[
            ExistingSecretRef(
                name="CEREBRO_POSTGRES_DSN",
                azure_secret_name="cerebro-postgres-dsn",
                azure_key_vault_url="https://example-vault.vault.azure.net/secrets/cerebro-postgres-dsn",
            )
        ],
        scheduled_jobs=[_scheduled_job(schedule="*/15 * * * *")],
    )

    secret_refs = _container_app_secret_refs(config)
    secrets = _container_app_secrets(config)

    assert secret_refs == [{"env": "CEREBRO_POSTGRES_DSN", "secret": "cerebro-postgres-dsn"}]
    assert _managed_identity(config) is not None
    assert len(secrets) == 1


def test_checked_in_example_stacks_stay_preview_safe() -> None:
    root = Path(__file__).resolve().parents[1]
    expectations = {
        "Pulumi.aws.yaml": "cerebro:cloud: aws",
        "Pulumi.gcp.yaml": "cerebro:cloud: gcp",
        "Pulumi.azure.yaml": "cerebro:cloud: azure",
    }

    for filename, cloud_marker in expectations.items():
        body = (root / filename).read_text(encoding="utf-8")
        assert cloud_marker in body
        assert "cerebro:deploymentProfile: preview" in body
        assert 'cerebro:apiAuthEnabled: "false"' in body
        assert "cerebro:publicOrigin: https://cerebro.example.com" in body


def _scheduled_job(schedule: str = "rate(15 minutes)") -> ScheduledJob:
    return ScheduledJob(
        name="sync-example",
        schedule=schedule,
        command=["source-runtime", "sync", "example-runtime", "page_limit=100"],
    )


def _config(cloud: str, **overrides: Any) -> CerebroRuntimeConfig:
    values: dict[str, Any] = {
        "cloud": cloud,
        "name": f"unit-{cloud}",
        "image": "ghcr.io/writer/cerebro:v2.1.475",
        "container_port": 8080,
        "min_replicas": 1,
        "max_replicas": 2,
        "cpu": 1.0,
        "memory_mib": 2048,
        "shutdown_timeout": "10s",
        "deployment_profile": "preview",
        "allow_unsafe_production": False,
        "unsafe_production_justification": "",
        "edge_auth_managed": False,
        "public_origin": "https://cerebro.example.com",
        "trusted_proxy_cidrs": "",
        "trusted_proxy_count": 1,
        "ingress_cidrs": ["0.0.0.0/0"],
        "api_auth_enabled": True,
        "allowed_tenants": "",
        "extra_env": {},
        "extra_secrets": {},
        "existing_secret_refs": [],
        "scheduled_jobs": [],
        "api_keys": None,
        "api_credentials_json": None,
        "postgres_dsn": None,
        "jetstream_url": None,
        "neo4j_uri": None,
        "neo4j_username": None,
        "neo4j_password": None,
        "connector_credential_key": None,
        "connector_transit_private_key": None,
        "capability_token_secrets": None,
        "aws_region": "us-east-1",
        "aws_availability_zones": ["us-east-1a", "us-east-1b"],
        "aws_vpc_cidr": "10.42.0.0/16",
        "aws_public_subnet_cidrs": ["10.42.0.0/24", "10.42.1.0/24"],
        "aws_private_subnet_cidrs": ["10.42.100.0/24", "10.42.101.0/24"],
        "aws_assign_public_ip": True,
        "aws_enable_private_subnets": False,
        "aws_enable_nat_gateway": False,
        "aws_certificate_arn": "",
        "aws_redirect_http_to_https": True,
        "aws_log_retention_days": 30,
        "aws_skip_credentials_validation": True,
        "gcp_project": "example-project",
        "gcp_region": "us-central1",
        "gcp_ingress": "INGRESS_TRAFFIC_ALL",
        "gcp_allow_unauthenticated": False,
        "gcp_service_account_email": "cerebro-runtime@example-project.iam.gserviceaccount.com",
        "gcp_scheduler_service_account_email": "cerebro-scheduler@example-project.iam.gserviceaccount.com",
        "gcp_vpc_connector": "",
        "azure_location": "eastus",
        "azure_resource_group_name": f"unit-{cloud}-rg",
        "azure_external_ingress": True,
        "azure_enable_system_identity": False,
    }
    values.update(overrides)
    return CerebroRuntimeConfig(**values)
