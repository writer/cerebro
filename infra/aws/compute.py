"""
AWS ECS Fargate compute infrastructure.

Creates:
- ECS cluster with Fargate
- Task definitions for API, workers, beat scheduler, and monitoring
- ECS services with autoscaling
- IAM roles and policies
- CloudWatch log groups
"""
import json

import pulumi
import pulumi_aws as aws


def create_ecs_cluster(
    name: str,
    vpc_id: pulumi.Output[str],
    subnet_ids: list[pulumi.Output[str]],
    security_group_id: pulumi.Output[str],
    secrets_arn: pulumi.Output[str],
    database_endpoint: pulumi.Output[str],
    redis_endpoint: pulumi.Output[str],
    db_password: pulumi.Input[str],
    redis_password: pulumi.Input[str],
    kms_key_id: pulumi.Output[str],
    target_group_arn: pulumi.Output[str],
    container_image: str = "cerebro:latest",
    api_cpu: int = 1024,
    api_memory: int = 2048,
    api_min_instances: int = 2,
    api_max_instances: int = 20,
    worker_cpu: int = 2048,
    worker_memory: int = 4096,
    worker_min_instances: int = 2,
    worker_max_instances: int = 50,
    enable_flower: bool = True,
) -> dict:
    """
    Create ECS cluster with Fargate services.

    Args:
        name: Cluster name prefix
        vpc_id: VPC ID
        subnet_ids: Private subnet IDs for ECS tasks
        security_group_id: Security group for ECS tasks
        secrets_arn: Secrets Manager ARN for environment variables
        database_endpoint: Database endpoint
        redis_endpoint: Redis endpoint
        kms_key_id: KMS key ID for encryption
        target_group_arn: ALB target group ARN for API service
        container_image: Docker image URI (ECR)
        api_cpu: API task CPU units (1024 = 1 vCPU)
        api_memory: API task memory in MB
        api_min_instances: Minimum API instances
        api_max_instances: Maximum API instances
        worker_cpu: Worker task CPU units
        worker_memory: Worker task memory in MB
        worker_min_instances: Minimum worker instances
        worker_max_instances: Maximum worker instances
        enable_flower: Deploy Flower monitoring UI

    Returns:
        Dictionary with ECS resources
    """
    # Create ECS cluster
    cluster = aws.ecs.Cluster(
        f"{name}-cluster",
        name=f"{name}-cluster",
        settings=[
            aws.ecs.ClusterSettingArgs(
                name="containerInsights",
                value="enabled",
            )
        ],
        tags={
            "Name": f"{name}-cluster",
            "ManagedBy": "Pulumi",
        },
    )

    # Create IAM execution role (for pulling images, secrets)
    execution_role = _create_execution_role(name, secrets_arn, kms_key_id)

    # Create IAM task role (for application AWS API access)
    task_role = _create_task_role(name, kms_key_id)

    # Create CloudWatch log groups
    api_log_group = _create_log_group(f"/ecs/{name}-api")
    worker_log_group = _create_log_group(f"/ecs/{name}-worker")
    beat_log_group = _create_log_group(f"/ecs/{name}-beat")

    # Base environment variables
    base_env = {
        "DATABASE_URL": pulumi.Output.all(
            database_endpoint, db_password
        ).apply(lambda args: _build_database_url(*args)),
        "REDIS_URL": pulumi.Output.all(
            redis_endpoint, redis_password
        ).apply(lambda args: _build_redis_url(*args)),
        "KMS_KEY_ID": kms_key_id,
        "KMS_PROVIDER": "aws",
    }

    # Create API task definition
    api_task_definition = _create_task_definition(
        name=f"{name}-api",
        container_name="cerebro-api",
        container_image=container_image,
        command=["uvicorn", "cerebro.api.main:app", "--host", "0.0.0.0", "--port", "8000"],
        cpu=api_cpu,
        memory=api_memory,
        execution_role_arn=execution_role.arn,
        task_role_arn=task_role.arn,
        log_group=api_log_group.name,
        environment=base_env,
        secrets_arn=secrets_arn,
        port_mappings=[{"containerPort": 8000, "protocol": "tcp"}],
    )

    # Create API service
    api_service = aws.ecs.Service(
        f"{name}-api-service",
        name=f"{name}-api",
        cluster=cluster.id,
        task_definition=api_task_definition.arn,
        desired_count=api_min_instances,
        launch_type="FARGATE",
        network_configuration=aws.ecs.ServiceNetworkConfigurationArgs(
            subnets=subnet_ids,
            security_groups=[security_group_id],
            assign_public_ip=False,
        ),
        load_balancers=[
            aws.ecs.ServiceLoadBalancerArgs(
                target_group_arn=target_group_arn,
                container_name="cerebro-api",
                container_port=8000,
            )
        ],
        health_check_grace_period_seconds=60,
        tags={
            "Name": f"{name}-api-service",
        },
    )

    # Create API autoscaling target
    api_scaling_target = aws.appautoscaling.Target(
        f"{name}-api-scaling-target",
        service_namespace="ecs",
        resource_id=pulumi.Output.concat(
            "service/", cluster.name, "/", api_service.name
        ),
        scalable_dimension="ecs:service:DesiredCount",
        min_capacity=api_min_instances,
        max_capacity=api_max_instances,
    )

    # CPU-based scaling for API
    aws.appautoscaling.Policy(
        f"{name}-api-cpu-scaling",
        service_namespace="ecs",
        resource_id=api_scaling_target.resource_id,
        scalable_dimension="ecs:service:DesiredCount",
        policy_type="TargetTrackingScaling",
        target_tracking_scaling_policy_configuration=aws.appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationArgs(
            target_value=70.0,
            predefined_metric_specification=aws.appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationPredefinedMetricSpecificationArgs(
                predefined_metric_type="ECSServiceAverageCPUUtilization",
            ),
            scale_in_cooldown=300,
            scale_out_cooldown=60,
        ),
    )

    # Create Worker task definition
    worker_task_definition = _create_task_definition(
        name=f"{name}-worker",
        container_name="cerebro-worker",
        container_image=container_image,
        command=["celery", "-A", "cerebro.tasks.celery_app", "worker", "-l", "info"],
        cpu=worker_cpu,
        memory=worker_memory,
        execution_role_arn=execution_role.arn,
        task_role_arn=task_role.arn,
        log_group=worker_log_group.name,
        environment=base_env,
        secrets_arn=secrets_arn,
    )

    # Create Worker service
    worker_service = aws.ecs.Service(
        f"{name}-worker-service",
        name=f"{name}-worker",
        cluster=cluster.id,
        task_definition=worker_task_definition.arn,
        desired_count=worker_min_instances,
        launch_type="FARGATE",
        network_configuration=aws.ecs.ServiceNetworkConfigurationArgs(
            subnets=subnet_ids,
            security_groups=[security_group_id],
            assign_public_ip=False,
        ),
        tags={
            "Name": f"{name}-worker-service",
        },
    )

    # Create Worker autoscaling target
    worker_scaling_target = aws.appautoscaling.Target(
        f"{name}-worker-scaling-target",
        service_namespace="ecs",
        resource_id=pulumi.Output.concat(
            "service/", cluster.name, "/", worker_service.name
        ),
        scalable_dimension="ecs:service:DesiredCount",
        min_capacity=worker_min_instances,
        max_capacity=worker_max_instances,
    )

    # CPU-based scaling for workers
    aws.appautoscaling.Policy(
        f"{name}-worker-cpu-scaling",
        service_namespace="ecs",
        resource_id=worker_scaling_target.resource_id,
        scalable_dimension="ecs:service:DesiredCount",
        policy_type="TargetTrackingScaling",
        target_tracking_scaling_policy_configuration=aws.appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationArgs(
            target_value=70.0,
            predefined_metric_specification=aws.appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationPredefinedMetricSpecificationArgs(
                predefined_metric_type="ECSServiceAverageCPUUtilization",
            ),
            scale_in_cooldown=300,
            scale_out_cooldown=60,
        ),
    )

    # Create Beat (scheduler) task definition
    beat_task_definition = _create_task_definition(
        name=f"{name}-beat",
        container_name="cerebro-beat",
        container_image=container_image,
        command=["celery", "-A", "cerebro.tasks.celery_app", "beat", "-l", "info"],
        cpu=512,
        memory=1024,
        execution_role_arn=execution_role.arn,
        task_role_arn=task_role.arn,
        log_group=beat_log_group.name,
        environment=base_env,
        secrets_arn=secrets_arn,
    )

    # Create Beat service (single instance)
    beat_service = aws.ecs.Service(
        f"{name}-beat-service",
        name=f"{name}-beat",
        cluster=cluster.id,
        task_definition=beat_task_definition.arn,
        desired_count=1,
        launch_type="FARGATE",
        network_configuration=aws.ecs.ServiceNetworkConfigurationArgs(
            subnets=subnet_ids,
            security_groups=[security_group_id],
            assign_public_ip=False,
        ),
        tags={
            "Name": f"{name}-beat-service",
        },
    )

    result = {
        "cluster": cluster,
        "api_service": api_service,
        "worker_service": worker_service,
        "beat_service": beat_service,
        "execution_role": execution_role,
        "task_role": task_role,
    }

    # Optional Flower monitoring UI
    if enable_flower:
        flower_log_group = _create_log_group(f"/ecs/{name}-flower")
        flower_task_definition = _create_task_definition(
            name=f"{name}-flower",
            container_name="cerebro-flower",
            container_image=container_image,
            command=["celery", "-A", "cerebro.tasks.celery_app", "flower"],
            cpu=512,
            memory=1024,
            execution_role_arn=execution_role.arn,
            task_role_arn=task_role.arn,
            log_group=flower_log_group.name,
            environment=base_env,
            secrets_arn=secrets_arn,
            port_mappings=[{"containerPort": 5555, "protocol": "tcp"}],
        )

        flower_service = aws.ecs.Service(
            f"{name}-flower-service",
            name=f"{name}-flower",
            cluster=cluster.id,
            task_definition=flower_task_definition.arn,
            desired_count=1,
            launch_type="FARGATE",
            network_configuration=aws.ecs.ServiceNetworkConfigurationArgs(
                subnets=subnet_ids,
                security_groups=[security_group_id],
                assign_public_ip=False,
            ),
            tags={
                "Name": f"{name}-flower-service",
            },
        )

        result["flower_service"] = flower_service

    return result


def _create_execution_role(
    name: str,
    secrets_arn: pulumi.Output[str],
    kms_key_id: pulumi.Output[str],
) -> aws.iam.Role:
    """Create IAM role for ECS task execution."""
    role = aws.iam.Role(
        f"{name}-execution-role",
        assume_role_policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        tags={"Name": f"{name}-execution-role"},
    )

    # Attach AWS managed policy for ECS task execution
    aws.iam.RolePolicyAttachment(
        f"{name}-execution-policy-attachment",
        role=role.name,
        policy_arn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
    )

    # Add inline policy for Secrets Manager and KMS access
    aws.iam.RolePolicy(
        f"{name}-execution-secrets-policy",
        role=role.name,
        policy=pulumi.Output.all(secrets_arn, kms_key_id).apply(
            lambda args: json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "secretsmanager:GetSecretValue",
                            ],
                            "Resource": args[0],
                        },
                        {
                            "Effect": "Allow",
                            "Action": [
                                "kms:Decrypt",
                                "kms:DescribeKey",
                            ],
                            "Resource": f"arn:aws:kms:*:*:key/{args[1]}",
                        },
                    ],
                }
            )
        ),
    )

    return role


def _create_task_role(name: str, kms_key_id: pulumi.Output[str]) -> aws.iam.Role:
    """Create IAM role for ECS tasks (application permissions)."""
    role = aws.iam.Role(
        f"{name}-task-role",
        assume_role_policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        tags={"Name": f"{name}-task-role"},
    )

    # Add inline policy for KMS access (for application encryption)
    aws.iam.RolePolicy(
        f"{name}-task-kms-policy",
        role=role.name,
        policy=kms_key_id.apply(
            lambda key_id: json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "kms:Encrypt",
                                "kms:Decrypt",
                                "kms:GenerateDataKey",
                                "kms:DescribeKey",
                            ],
                            "Resource": f"arn:aws:kms:*:*:key/{key_id}",
                        }
                    ],
                }
            )
        ),
    )

    return role


def _create_log_group(name: str, retention_days: int = 30) -> aws.cloudwatch.LogGroup:
    """Create CloudWatch log group."""
    return aws.cloudwatch.LogGroup(
        name.replace("/", "-"),
        name=name,
        retention_in_days=retention_days,
        tags={
            "Name": name,
        },
    )


def _create_task_definition(
    name: str,
    container_name: str,
    container_image: str,
    command: list[str],
    cpu: int,
    memory: int,
    execution_role_arn: pulumi.Output[str],
    task_role_arn: pulumi.Output[str],
    log_group: pulumi.Output[str],
    environment: dict,
    secrets_arn: pulumi.Output[str],
    port_mappings: list[dict] = None,
) -> aws.ecs.TaskDefinition:
    """Create ECS task definition."""
    container_def = {
        "name": container_name,
        "image": container_image,
        "command": command,
        "essential": True,
        "logConfiguration": {
            "logDriver": "awslogs",
            "options": {
                "awslogs-group": log_group,
                "awslogs-region": aws.get_region().name,
                "awslogs-stream-prefix": "ecs",
            },
        },
        "environment": [
            {"name": key, "value": value} for key, value in environment.items()
        ],
        "secrets": _build_secret_references(secrets_arn),
    }

    if port_mappings:
        container_def["portMappings"] = port_mappings

    return aws.ecs.TaskDefinition(
        f"{name}-task-def",
        family=name,
        cpu=str(cpu),
        memory=str(memory),
        network_mode="awsvpc",
        requires_compatibilities=["FARGATE"],
        execution_role_arn=execution_role_arn,
        task_role_arn=task_role_arn,
        container_definitions=pulumi.Output.json_dumps([container_def]),
        tags={
            "Name": name,
        },
    )


def _build_database_url(endpoint: str, password: str) -> str:
    """Compose the SQLAlchemy database URL."""
    return f"postgresql://cerebro:{password}@{endpoint}/cerebro"


def _build_redis_url(endpoint: str, password: str) -> str:
    """Compose the Redis connection URL used by Celery."""
    return f"rediss://:{password}@{endpoint}:6379/0"


def _build_secret_references(secrets_arn: pulumi.Output[str]) -> list[dict]:
    """Return the set of secret environment variable mappings."""
    return [
        {
            "name": "DATABASE_PASSWORD",
            "valueFrom": pulumi.Output.concat(secrets_arn, ":DB_PASSWORD::"),
        },
        {
            "name": "REDIS_PASSWORD",
            "valueFrom": pulumi.Output.concat(secrets_arn, ":REDIS_PASSWORD::"),
        },
        {
            "name": "SECRET_KEY",
            "valueFrom": pulumi.Output.concat(secrets_arn, ":SECRET_KEY::"),
        },
    ]