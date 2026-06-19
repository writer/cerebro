from __future__ import annotations

import pulumi
import pulumi_gcp as gcp

from runtime import CerebroRuntimeConfig, SecretEnv, normalized_secret_name


def deploy(config: CerebroRuntimeConfig) -> None:
    if not config.gcp_project:
        raise ValueError("cerebro:gcpProject is required for GCP deployments")

    provider = gcp.Provider(
        "gcp-provider",
        project=config.gcp_project,
        region=config.gcp_region,
    )
    opts = pulumi.ResourceOptions(provider=provider)

    secret_refs = _create_secrets(config.name, config.secret_env(), opts)
    service = gcp.cloudrunv2.Service(
        f"{config.name}-service",
        name=config.name,
        location=config.gcp_region,
        ingress=config.gcp_ingress,
        template=gcp.cloudrunv2.ServiceTemplateArgs(
            scaling=gcp.cloudrunv2.ServiceTemplateScalingArgs(
                min_instance_count=config.min_replicas,
                max_instance_count=config.max_replicas,
            ),
            containers=[
                gcp.cloudrunv2.ServiceTemplateContainerArgs(
                    image=config.image,
                    commands=["/usr/local/bin/cerebro"],
                    args=["serve"],
                    ports=gcp.cloudrunv2.ServiceTemplateContainerPortsArgs(
                        container_port=config.container_port,
                    ),
                    envs=_plain_env(config) + _secret_env(secret_refs),
                    resources=gcp.cloudrunv2.ServiceTemplateContainerResourcesArgs(
                        limits={
                            "cpu": str(config.cpu),
                            "memory": f"{config.memory_mib}Mi",
                        },
                    ),
                    startup_probe=gcp.cloudrunv2.ServiceTemplateContainerStartupProbeArgs(
                        http_get=gcp.cloudrunv2.ServiceTemplateContainerStartupProbeHttpGetArgs(
                            path="/livez",
                            port=config.container_port,
                        ),
                        initial_delay_seconds=10,
                        timeout_seconds=5,
                        period_seconds=10,
                        failure_threshold=12,
                    ),
                    liveness_probe=gcp.cloudrunv2.ServiceTemplateContainerLivenessProbeArgs(
                        http_get=gcp.cloudrunv2.ServiceTemplateContainerLivenessProbeHttpGetArgs(
                            path="/livez",
                            port=config.container_port,
                        ),
                        timeout_seconds=5,
                        period_seconds=30,
                        failure_threshold=3,
                    ),
                )
            ],
        ),
        opts=opts,
    )

    if config.gcp_allow_unauthenticated:
        gcp.cloudrunv2.ServiceIamMember(
            f"{config.name}-invoker",
            name=service.name,
            location=service.location,
            role="roles/run.invoker",
            member="allUsers",
            opts=opts,
        )

    pulumi.export("cloud", "gcp")
    pulumi.export("service_name", service.name)
    pulumi.export("url", service.uri)


def _create_secrets(name: str, secrets: list[SecretEnv], opts: pulumi.ResourceOptions) -> list[dict[str, pulumi.Input[str]]]:
    refs = []
    for secret in secrets:
        secret_id = normalized_secret_name(f"{name}-{secret.name}")
        secret_resource = gcp.secretmanager.Secret(
            secret_id,
            secret_id=secret_id,
            replication=gcp.secretmanager.SecretReplicationArgs(
                auto=gcp.secretmanager.SecretReplicationAutoArgs(),
            ),
            opts=opts,
        )
        version = gcp.secretmanager.SecretVersion(
            f"{secret_id}-version",
            secret=secret_resource.id,
            secret_data=secret.value,
            opts=opts,
        )
        refs.append({"name": secret.name, "secret": secret_resource.secret_id, "version": version.version})
    return refs


def _plain_env(config: CerebroRuntimeConfig) -> list[gcp.cloudrunv2.ServiceTemplateContainerEnvArgs]:
    return [
        gcp.cloudrunv2.ServiceTemplateContainerEnvArgs(name=key, value=value)
        for key, value in sorted(config.plain_env().items())
    ]


def _secret_env(secret_refs: list[dict[str, pulumi.Input[str]]]) -> list[gcp.cloudrunv2.ServiceTemplateContainerEnvArgs]:
    return [
        gcp.cloudrunv2.ServiceTemplateContainerEnvArgs(
            name=ref["name"],
            value_source=gcp.cloudrunv2.ServiceTemplateContainerEnvValueSourceArgs(
                secret_key_ref=gcp.cloudrunv2.ServiceTemplateContainerEnvValueSourceSecretKeyRefArgs(
                    secret=ref["secret"],
                    version=ref["version"],
                )
            ),
        )
        for ref in secret_refs
    ]
