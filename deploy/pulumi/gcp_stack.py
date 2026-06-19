from __future__ import annotations

import pulumi
import pulumi_gcp as gcp

from runtime import CerebroRuntimeConfig, ExistingSecretRef, SecretEnv, ScheduledJob, normalized_secret_name


class GcpCerebroService(pulumi.ComponentResource):
    def __init__(
        self,
        name: str,
        config: CerebroRuntimeConfig,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        super().__init__("cerebro:cloud:GcpService", name, None, opts)
        if not config.gcp_project:
            raise ValueError("cerebro:gcpProject is required for GCP deployments")

        provider = gcp.Provider(
            f"{name}-gcp-provider",
            project=config.gcp_project,
            region=config.gcp_region,
            opts=pulumi.ResourceOptions(parent=self),
        )
        child_opts = pulumi.ResourceOptions(provider=provider, parent=self)

        created_secret_refs = _create_secrets(config.name, config.created_secret_env(), child_opts)
        secret_refs = created_secret_refs + _existing_gcp_secret_refs(config.existing_secret_refs)
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
                service_account=config.gcp_service_account_email or None,
                vpc_access=_service_vpc_access(config),
                containers=[
                    gcp.cloudrunv2.ServiceTemplateContainerArgs(
                        image=config.image,
                        commands=["/usr/local/bin/cerebro"],
                        args=["serve"],
                        ports=gcp.cloudrunv2.ServiceTemplateContainerPortsArgs(
                            container_port=config.container_port,
                        ),
                        envs=_service_plain_env(config) + _service_secret_env(secret_refs),
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
            opts=child_opts,
        )

        if config.gcp_allow_unauthenticated:
            gcp.cloudrunv2.ServiceIamMember(
                f"{config.name}-invoker",
                name=service.name,
                location=service.location,
                role="roles/run.invoker",
                member="allUsers",
                opts=child_opts,
            )

        job_names, scheduler_names = _create_jobs(config, secret_refs, child_opts)

        self.outputs = {
            "cloud": "gcp",
            "service_name": service.name,
            "url": service.uri,
            "job_names": job_names,
            "scheduler_names": scheduler_names,
        }
        self.register_outputs(self.outputs)


def deploy(config: CerebroRuntimeConfig) -> GcpCerebroService:
    service = GcpCerebroService(config.name, config)
    for key, value in service.outputs.items():
        pulumi.export(key, value)
    return service


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


def _existing_gcp_secret_refs(secrets: list[ExistingSecretRef]) -> list[dict[str, pulumi.Input[str]]]:
    refs = []
    for secret in secrets:
        if not secret.gcp_secret:
            raise ValueError(f"cerebro:existingSecretRefs.{secret.name}.gcpSecret is required for GCP")
        refs.append({"name": secret.name, "secret": secret.gcp_secret, "version": secret.gcp_version})
    return refs


def _create_jobs(
    config: CerebroRuntimeConfig,
    secret_refs: list[dict[str, pulumi.Input[str]]],
    opts: pulumi.ResourceOptions,
) -> tuple[list[pulumi.Input[str]], list[pulumi.Input[str]]]:
    job_names: list[pulumi.Input[str]] = []
    scheduler_names: list[pulumi.Input[str]] = []
    for job in config.scheduled_jobs:
        job_name = _gcp_job_name(config, job)
        job_resource = gcp.cloudrunv2.Job(
            f"{config.name}-{job.name}-job",
            name=job_name,
            location=config.gcp_region,
            project=config.gcp_project,
            template=gcp.cloudrunv2.JobTemplateArgs(
                task_count=1,
                parallelism=1,
                template=gcp.cloudrunv2.JobTemplateTemplateArgs(
                    service_account=config.gcp_service_account_email or None,
                    timeout=f"{job.timeout_seconds}s",
                    max_retries=job.retry_limit,
                    vpc_access=_job_vpc_access(config),
                    containers=[
                        gcp.cloudrunv2.JobTemplateTemplateContainerArgs(
                            image=config.image,
                            commands=["/usr/local/bin/cerebro"],
                            args=job.command,
                            envs=_job_plain_env(config) + _job_secret_env(secret_refs),
                            resources=gcp.cloudrunv2.JobTemplateTemplateContainerResourcesArgs(
                                limits={
                                    "cpu": str(job.cpu or config.cpu),
                                    "memory": f"{job.memory_mib or config.memory_mib}Mi",
                                },
                            ),
                        )
                    ],
                ),
            ),
            opts=opts,
        )
        job_names.append(job_resource.name)
        if config.gcp_scheduler_service_account_email:
            scheduler = gcp.cloudscheduler.Job(
                f"{config.name}-{job.name}-scheduler",
                name=f"projects/{config.gcp_project}/locations/{config.gcp_region}/jobs/{job_name}",
                project=config.gcp_project,
                region=config.gcp_region,
                schedule=job.schedule,
                time_zone=job.time_zone,
                paused=not job.enabled,
                description=job.description or f"Cerebro scheduled job {job.name}",
                http_target=gcp.cloudscheduler.JobHttpTargetArgs(
                    uri=_cloud_run_job_run_uri(config, job_name),
                    http_method="POST",
                    oauth_token=gcp.cloudscheduler.JobHttpTargetOauthTokenArgs(
                        service_account_email=config.gcp_scheduler_service_account_email,
                        scope="https://www.googleapis.com/auth/cloud-platform",
                    ),
                ),
                opts=opts,
            )
            scheduler_names.append(scheduler.name)
    return job_names, scheduler_names


def _service_plain_env(config: CerebroRuntimeConfig) -> list[gcp.cloudrunv2.ServiceTemplateContainerEnvArgs]:
    return [
        gcp.cloudrunv2.ServiceTemplateContainerEnvArgs(name=key, value=value)
        for key, value in sorted(config.plain_env().items())
    ]


def _service_secret_env(secret_refs: list[dict[str, pulumi.Input[str]]]) -> list[gcp.cloudrunv2.ServiceTemplateContainerEnvArgs]:
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


def _job_plain_env(config: CerebroRuntimeConfig) -> list[gcp.cloudrunv2.JobTemplateTemplateContainerEnvArgs]:
    return [
        gcp.cloudrunv2.JobTemplateTemplateContainerEnvArgs(name=key, value=value)
        for key, value in sorted(config.plain_env().items())
    ]


def _job_secret_env(secret_refs: list[dict[str, pulumi.Input[str]]]) -> list[gcp.cloudrunv2.JobTemplateTemplateContainerEnvArgs]:
    return [
        gcp.cloudrunv2.JobTemplateTemplateContainerEnvArgs(
            name=ref["name"],
            value_source=gcp.cloudrunv2.JobTemplateTemplateContainerEnvValueSourceArgs(
                secret_key_ref=gcp.cloudrunv2.JobTemplateTemplateContainerEnvValueSourceSecretKeyRefArgs(
                    secret=ref["secret"],
                    version=ref["version"],
                )
            ),
        )
        for ref in secret_refs
    ]


def _service_vpc_access(config: CerebroRuntimeConfig) -> gcp.cloudrunv2.ServiceTemplateVpcAccessArgs | None:
    if not config.gcp_vpc_connector:
        return None
    return gcp.cloudrunv2.ServiceTemplateVpcAccessArgs(
        connector=config.gcp_vpc_connector,
        egress="PRIVATE_RANGES_ONLY",
    )


def _job_vpc_access(config: CerebroRuntimeConfig) -> gcp.cloudrunv2.JobTemplateTemplateVpcAccessArgs | None:
    if not config.gcp_vpc_connector:
        return None
    return gcp.cloudrunv2.JobTemplateTemplateVpcAccessArgs(
        connector=config.gcp_vpc_connector,
        egress="PRIVATE_RANGES_ONLY",
    )


def _gcp_job_name(config: CerebroRuntimeConfig, job: ScheduledJob) -> str:
    return f"{config.name}-{job.name}"


def _cloud_run_job_run_uri(config: CerebroRuntimeConfig, job_name: str) -> str:
    return (
        f"https://{config.gcp_region}-run.googleapis.com/apis/run.googleapis.com/v1/"
        f"namespaces/{config.gcp_project}/jobs/{job_name}:run"
    )
