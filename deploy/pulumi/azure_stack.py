from __future__ import annotations

import pulumi
import pulumi_azure_native as azure

from runtime import CerebroRuntimeConfig, ExistingSecretRef, SecretEnv, ScheduledJob, normalized_secret_name


class AzureCerebroService(pulumi.ComponentResource):
    def __init__(
        self,
        name: str,
        config: CerebroRuntimeConfig,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        super().__init__("cerebro:cloud:AzureService", name, None, opts)
        provider = azure.Provider(f"{name}-azure-provider", opts=pulumi.ResourceOptions(parent=self))
        child_opts = pulumi.ResourceOptions(provider=provider, parent=self)

        resource_group = azure.resources.ResourceGroup(
            f"{config.name}-rg",
            resource_group_name=config.azure_resource_group_name,
            location=config.azure_location,
            opts=child_opts,
        )
        environment = azure.app.ManagedEnvironment(
            f"{config.name}-env",
            environment_name=f"{config.name}-env",
            resource_group_name=resource_group.name,
            location=resource_group.location,
            opts=child_opts,
        )

        secret_refs = _container_app_secret_refs(config)
        identity = _managed_identity(config)
        container_app = azure.app.ContainerApp(
            f"{config.name}-app",
            container_app_name=config.name,
            resource_group_name=resource_group.name,
            location=resource_group.location,
            managed_environment_id=environment.id,
            identity=identity,
            configuration=azure.app.ConfigurationArgs(
                ingress=azure.app.IngressArgs(
                    external=config.azure_external_ingress,
                    target_port=config.container_port,
                    transport="auto",
                ),
                secrets=_container_app_secrets(config),
            ),
            template=azure.app.TemplateArgs(
                containers=[
                    azure.app.ContainerArgs(
                        name="cerebro",
                        image=config.image,
                        args=["serve"],
                        env=_plain_env(config) + _secret_env(secret_refs),
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
            opts=child_opts,
        )

        job_names = _create_jobs(config, environment.id, resource_group, identity, secret_refs, child_opts)

        self.outputs = {
            "cloud": "azure",
            "resource_group_name": resource_group.name,
            "service_name": container_app.name,
            "url": container_app.configuration.apply(
                lambda cfg: f"https://{cfg.ingress.fqdn}" if cfg and cfg.ingress and cfg.ingress.fqdn else ""
            ),
            "job_names": job_names,
        }
        self.register_outputs(self.outputs)


def deploy(config: CerebroRuntimeConfig) -> AzureCerebroService:
    service = AzureCerebroService(config.name, config)
    for key, value in service.outputs.items():
        pulumi.export(key, value)
    return service


def _container_app_secret_refs(config: CerebroRuntimeConfig) -> list[dict[str, str]]:
    refs = []
    refs.extend({"env": secret.name, "secret": normalized_secret_name(secret.name)} for secret in config.created_secret_env())
    for secret in config.existing_secret_refs:
        if secret.azure_key_vault_url:
            refs.append({"env": secret.name, "secret": secret.azure_secret_name or normalized_secret_name(secret.name)})
        elif secret.azure_secret_name:
            refs.append({"env": secret.name, "secret": secret.azure_secret_name})
        else:
            raise ValueError(
                f"cerebro:existingSecretRefs.{secret.name}.azureKeyVaultUrl or azureSecretName is required for Azure"
            )
    return refs


def _container_app_secrets(config: CerebroRuntimeConfig) -> list[azure.app.SecretArgs]:
    secrets = [
        azure.app.SecretArgs(
            name=normalized_secret_name(secret.name),
            value=secret.value,
        )
        for secret in config.created_secret_env()
    ]
    for secret in config.existing_secret_refs:
        if secret.azure_key_vault_url:
            secrets.append(
                azure.app.SecretArgs(
                    name=secret.azure_secret_name or normalized_secret_name(secret.name),
                    key_vault_url=secret.azure_key_vault_url,
                    identity="system",
                )
            )
    return secrets


def _create_jobs(
    config: CerebroRuntimeConfig,
    environment_id: pulumi.Input[str],
    resource_group: azure.resources.ResourceGroup,
    identity: azure.app.ManagedServiceIdentityArgs | None,
    secret_refs: list[dict[str, str]],
    opts: pulumi.ResourceOptions,
) -> list[pulumi.Input[str]]:
    job_names: list[pulumi.Input[str]] = []
    for job in config.scheduled_jobs:
        container_job = azure.app.Job(
            f"{config.name}-{job.name}-job",
            job_name=f"{config.name}-{job.name}",
            resource_group_name=resource_group.name,
            location=resource_group.location,
            environment_id=environment_id,
            identity=identity,
            configuration=azure.app.JobConfigurationArgs(
                trigger_type="Schedule",
                replica_timeout=job.timeout_seconds,
                replica_retry_limit=job.retry_limit,
                schedule_trigger_config=azure.app.JobConfigurationScheduleTriggerConfigArgs(
                    cron_expression=job.schedule,
                    parallelism=1,
                    replica_completion_count=1,
                ),
                secrets=_container_app_secrets(config),
            ),
            template=azure.app.JobTemplateArgs(
                containers=[
                    azure.app.ContainerArgs(
                        name="cerebro",
                        image=config.image,
                        args=job.command,
                        env=_plain_env(config) + _secret_env(secret_refs),
                        resources=azure.app.ContainerResourcesArgs(
                            cpu=job.cpu or config.cpu,
                            memory=f"{(job.memory_mib or config.memory_mib) / 1024:g}Gi",
                        ),
                    )
                ],
            ),
            opts=opts,
        )
        job_names.append(container_job.name)
    return job_names


def _managed_identity(config: CerebroRuntimeConfig) -> azure.app.ManagedServiceIdentityArgs | None:
    if not (config.azure_enable_system_identity or config.uses_azure_key_vault_refs()):
        return None
    return azure.app.ManagedServiceIdentityArgs(type="SystemAssigned")


def _plain_env(config: CerebroRuntimeConfig) -> list[azure.app.EnvironmentVarArgs]:
    return [
        azure.app.EnvironmentVarArgs(name=key, value=value)
        for key, value in sorted(config.plain_env().items())
    ]


def _secret_env(secrets: list[dict[str, str]]) -> list[azure.app.EnvironmentVarArgs]:
    return [
        azure.app.EnvironmentVarArgs(
            name=secret["env"],
            secret_ref=secret["secret"],
        )
        for secret in secrets
    ]
