"""
GCP Cloud Run compute infrastructure.

Creates:
- Cloud Run services for API, workers
- Service accounts with IAM bindings
- VPC connectors for private access
- Autoscaling configuration
- Cloud Tasks queues for Celery
"""

import pulumi
import pulumi_gcp as gcp


def create_cloud_run_services(
    name: str,
    project: str,
    region: str,
    container_image: str,
    network_id: pulumi.Output[str],
    subnet_id: pulumi.Output[str],
    database_connection_name: pulumi.Output[str],
    redis_host: pulumi.Output[str],
    kms_key_id: pulumi.Output[str],
    secret_ids: dict[str, pulumi.Output[str]],
    api_min_instances: int = 2,
    api_max_instances: int = 20,
    api_cpu: str = "2",
    api_memory: str = "2Gi",
    worker_min_instances: int = 1,
    worker_max_instances: int = 50,
    worker_cpu: str = "4",
    worker_memory: str = "4Gi",
) -> dict:
    """
    Create Cloud Run services for Cerebro.

    Args:
        name: Service name prefix
        project: GCP project ID
        region: GCP region
        container_image: Container image URI (Artifact Registry/GCR)
        network_id: VPC network ID
        subnet_id: Subnet ID for VPC connector
        database_connection_name: Cloud SQL connection name
        redis_host: Redis host address
        kms_key_id: KMS key ID
        secret_ids: Dictionary of secret IDs
        api_min_instances: Minimum API instances
        api_max_instances: Maximum API instances
        api_cpu: API CPU allocation
        api_memory: API memory allocation
        worker_min_instances: Minimum worker instances
        worker_max_instances: Maximum worker instances
        worker_cpu: Worker CPU allocation
        worker_memory: Worker memory allocation

    Returns:
        Dictionary with Cloud Run resources
    """
    # Create VPC Connector for private VPC access
    vpc_connector = gcp.vpcaccess.Connector(
        f"{name}-vpc-connector",
        name=f"{name}-vpc-connector",
        project=project,
        region=region,
        network=network_id,
        ip_cidr_range="10.8.0.0/28",  # /28 for VPC connector
        min_throughput=200,
        max_throughput=1000,
    )

    # Create service account for Cloud Run services
    service_account = gcp.serviceaccount.Account(
        f"{name}-cloudrun-sa",
        account_id=f"{name}-cloudrun-sa",
        project=project,
        display_name=f"Cloud Run service account for {name}",
    )

    # Grant Cloud SQL Client role
    gcp.projects.IAMMember(
        f"{name}-sql-client-binding",
        project=project,
        role="roles/cloudsql.client",
        member=service_account.email.apply(lambda e: f"serviceAccount:{e}"),
    )

    # Grant KMS encrypter/decrypter role
    gcp.projects.IAMMember(
        f"{name}-kms-binding",
        project=project,
        role="roles/cloudkms.cryptoKeyEncrypterDecrypter",
        member=service_account.email.apply(lambda e: f"serviceAccount:{e}"),
    )

    # Grant Secret Manager accessor role
    gcp.projects.IAMMember(
        f"{name}-secret-accessor-binding",
        project=project,
        role="roles/secretmanager.secretAccessor",
        member=service_account.email.apply(lambda e: f"serviceAccount:{e}"),
    )

    # Base environment variables
    base_env = [
        gcp.cloudrun.ServiceTemplateSpecContainerEnvArgs(
            name="DATABASE_CONNECTION_NAME",
            value=database_connection_name,
        ),
        gcp.cloudrun.ServiceTemplateSpecContainerEnvArgs(
            name="REDIS_HOST",
            value=redis_host,
        ),
        gcp.cloudrun.ServiceTemplateSpecContainerEnvArgs(
            name="KMS_KEY_ID",
            value=kms_key_id,
        ),
    ]

    # Add secret environment variables
    for key, secret_id in secret_ids.items():
        base_env.append(
            gcp.cloudrun.ServiceTemplateSpecContainerEnvArgs(
                name=key.upper(),
                value_from=gcp.cloudrun.ServiceTemplateSpecContainerEnvValueFromArgs(
                    secret_key_ref=gcp.cloudrun.ServiceTemplateSpecContainerEnvValueFromSecretKeyRefArgs(
                        name=secret_id,
                        key="latest",
                    )
                ),
            )
        )

    # Create API service
    api_service = gcp.cloudrun.Service(
        f"{name}-api",
        name=f"{name}-api",
        project=project,
        location=region,
        template=gcp.cloudrun.ServiceTemplateArgs(
            metadata=gcp.cloudrun.ServiceTemplateMetadataArgs(
                annotations={
                    "autoscaling.knative.dev/minScale": str(api_min_instances),
                    "autoscaling.knative.dev/maxScale": str(api_max_instances),
                    "run.googleapis.com/cloudsql-instances": database_connection_name,
                    "run.googleapis.com/vpc-access-connector": vpc_connector.name,
                    "run.googleapis.com/vpc-access-egress": "private-ranges-only",
                },
            ),
            spec=gcp.cloudrun.ServiceTemplateSpecArgs(
                service_account_name=service_account.email,
                containers=[
                    gcp.cloudrun.ServiceTemplateSpecContainerArgs(
                        image=container_image,
                        args=[
                            "uvicorn",
                            "cerebro.api.main:app",
                            "--host",
                            "0.0.0.0",
                            "--port",
                            "8000",
                        ],
                        ports=[
                            gcp.cloudrun.ServiceTemplateSpecContainerPortArgs(
                                container_port=8000,
                            )
                        ],
                        resources=gcp.cloudrun.ServiceTemplateSpecContainerResourcesArgs(
                            limits={
                                "cpu": api_cpu,
                                "memory": api_memory,
                            },
                        ),
                        envs=base_env,
                    )
                ],
                container_concurrency=80,  # Max concurrent requests per instance
                timeout_seconds=300,  # 5 minutes
            ),
        ),
        traffics=[
            gcp.cloudrun.ServiceTrafficArgs(
                percent=100,
                latest_revision=True,
            )
        ],
    )

    # Make API service publicly accessible
    gcp.cloudrun.IamMember(
        f"{name}-api-invoker",
        project=project,
        location=region,
        service=api_service.name,
        role="roles/run.invoker",
        member="allUsers",
    )

    # Create Worker service (for Celery workers)
    # Note: Cloud Run is not ideal for long-running workers
    # Consider using GKE or Compute Engine for Celery workers
    worker_service = gcp.cloudrun.Service(
        f"{name}-worker",
        name=f"{name}-worker",
        project=project,
        location=region,
        template=gcp.cloudrun.ServiceTemplateArgs(
            metadata=gcp.cloudrun.ServiceTemplateMetadataArgs(
                annotations={
                    "autoscaling.knative.dev/minScale": str(worker_min_instances),
                    "autoscaling.knative.dev/maxScale": str(worker_max_instances),
                    "run.googleapis.com/cloudsql-instances": database_connection_name,
                    "run.googleapis.com/vpc-access-connector": vpc_connector.name,
                    "run.googleapis.com/vpc-access-egress": "private-ranges-only",
                },
            ),
            spec=gcp.cloudrun.ServiceTemplateSpecArgs(
                service_account_name=service_account.email,
                containers=[
                    gcp.cloudrun.ServiceTemplateSpecContainerArgs(
                        image=container_image,
                        args=[
                            "celery",
                            "-A",
                            "cerebro.tasks.celery_app",
                            "worker",
                            "-l",
                            "info",
                        ],
                        resources=gcp.cloudrun.ServiceTemplateSpecContainerResourcesArgs(
                            limits={
                                "cpu": worker_cpu,
                                "memory": worker_memory,
                            },
                        ),
                        envs=base_env,
                    )
                ],
                container_concurrency=1,  # One worker per instance
                timeout_seconds=3600,  # 1 hour for long tasks
            ),
        ),
    )

    # Create Cloud Tasks queue for Celery tasks
    # This is a GCP-native alternative to Redis as a broker
    task_queue = gcp.cloudtasks.Queue(
        f"{name}-task-queue",
        name=f"{name}-task-queue",
        project=project,
        location=region,
        rate_limits=gcp.cloudtasks.QueueRateLimitsArgs(
            max_concurrent_dispatches=100,
            max_dispatches_per_second=50,
        ),
        retry_config=gcp.cloudtasks.QueueRetryConfigArgs(
            max_attempts=5,
            max_retry_duration="3600s",
            min_backoff="60s",
            max_backoff="3600s",
            max_doublings=5,
        ),
    )

    return {
        "api_service": api_service,
        "worker_service": worker_service,
        "service_account": service_account,
        "vpc_connector": vpc_connector,
        "task_queue": task_queue,
        "api_url": api_service.statuses[0].url,
    }


def create_service_account(
    name: str,
    project: str,
    display_name: str,
    roles: list[str] = None,
) -> gcp.serviceaccount.Account:
    """
    Create a service account with IAM roles.

    Args:
        name: Service account name
        project: GCP project ID
        display_name: Display name
        roles: List of IAM roles to grant

    Returns:
        Service account resource
    """
    sa = gcp.serviceaccount.Account(
        f"{name}-sa",
        account_id=name,
        project=project,
        display_name=display_name,
    )

    # Grant roles if specified
    if roles:
        for i, role in enumerate(roles):
            gcp.projects.IAMMember(
                f"{name}-role-{i}",
                project=project,
                role=role,
                member=sa.email.apply(lambda e: f"serviceAccount:{e}"),
            )

    return sa
