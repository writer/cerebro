from __future__ import annotations

import pulumi
import pulumi_azure_native as azure

from runtime import CerebroRuntimeConfig, SecretEnv, normalized_secret_name


def deploy(config: CerebroRuntimeConfig) -> None:
    provider = azure.Provider("azure-provider")
    opts = pulumi.ResourceOptions(provider=provider)

    resource_group = azure.resources.ResourceGroup(
        f"{config.name}-rg",
        resource_group_name=config.azure_resource_group_name,
        location=config.azure_location,
        opts=opts,
    )
    environment = azure.app.ManagedEnvironment(
        f"{config.name}-env",
        environment_name=f"{config.name}-env",
        resource_group_name=resource_group.name,
        location=resource_group.location,
        opts=opts,
    )

    secrets = _container_app_secrets(config.secret_env())
    container_app = azure.app.ContainerApp(
        f"{config.name}-app",
        container_app_name=config.name,
        resource_group_name=resource_group.name,
        location=resource_group.location,
        managed_environment_id=environment.id,
        configuration=azure.app.ConfigurationArgs(
            ingress=azure.app.IngressArgs(
                external=config.azure_external_ingress,
                target_port=config.container_port,
                transport="auto",
            ),
            secrets=secrets,
        ),
        template=azure.app.TemplateArgs(
            containers=[
                azure.app.ContainerArgs(
                    name="cerebro",
                    image=config.image,
                    args=["serve"],
                    env=_plain_env(config) + _secret_env(config.secret_env()),
                    resources=azure.app.ContainerResourcesArgs(
                        cpu=config.cpu,
                        memory=f"{config.memory_mib / 1024:g}Gi",
                    ),
                    probes=[
                        azure.app.ContainerAppProbeArgs(
                            type="Liveness",
                            http_get=azure.app.ContainerAppProbeHttpGetArgs(
                                path="/livez",
                                port=config.container_port,
                            ),
                            period_seconds=30,
                            timeout_seconds=5,
                            failure_threshold=3,
                        )
                    ],
                )
            ],
            scale=azure.app.ScaleArgs(
                min_replicas=config.min_replicas,
                max_replicas=config.max_replicas,
            ),
        ),
        opts=opts,
    )

    pulumi.export("cloud", "azure")
    pulumi.export("resource_group_name", resource_group.name)
    pulumi.export("service_name", container_app.name)
    pulumi.export("url", container_app.configuration.apply(lambda cfg: f"https://{cfg.ingress.fqdn}" if cfg and cfg.ingress and cfg.ingress.fqdn else ""))


def _container_app_secrets(secrets: list[SecretEnv]) -> list[azure.app.SecretArgs]:
    return [
        azure.app.SecretArgs(
            name=normalized_secret_name(secret.name),
            value=secret.value,
        )
        for secret in secrets
    ]

def _plain_env(config: CerebroRuntimeConfig) -> list[azure.app.EnvironmentVarArgs]:
    return [
        azure.app.EnvironmentVarArgs(name=key, value=value)
        for key, value in sorted(config.plain_env().items())
    ]


def _secret_env(secrets: list[SecretEnv]) -> list[azure.app.EnvironmentVarArgs]:
    return [
        azure.app.EnvironmentVarArgs(
            name=secret.name,
            secret_ref=normalized_secret_name(secret.name),
        )
        for secret in secrets
    ]
