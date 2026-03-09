"""
AWS ECS Fargate compute for Cerebro Go application.
"""

import json

import pulumi
import pulumi_aws as aws


def create_ecs_cluster(
    name: str,
    vpc_id: pulumi.Output[str],
    subnet_ids: list[pulumi.Output[str]],
    security_group_id: pulumi.Output[str],
    kms_key_id: pulumi.Output[str],
    target_group_arn: pulumi.Output[str],
    container_image: str,
    api_cpu: int = 1024,
    api_memory: int = 2048,
    api_min_instances: int = 2,
    api_max_instances: int = 10,
    log_retention_days: int = 30,
    environment: dict = None,
    secret_keys: list[str] = None,
    external_secrets_prefix: str = None,
    job_queue_url: pulumi.Output[str] = None,
    job_queue_arn: pulumi.Output[str] = None,
    job_table_name: pulumi.Output[str] = None,
    log_group_kms_key_id: pulumi.Output[str] = None,
    s3_source_iam_configs: list[dict] = None,
    fargate_base: int = 1,
    fargate_weight: int = 1,
    fargate_spot_base: int = 0,
    fargate_spot_weight: int = 2,
    enable_circuit_breaker: bool = True,
) -> dict:
    """
    Create ECS cluster with Fargate service for Go API.
    """
    # ECS Cluster
    cluster = aws.ecs.Cluster(
        f"{name}-cluster",
        name=f"{name}-cluster",
        settings=[
            aws.ecs.ClusterSettingArgs(
                name="containerInsights",
                value="enabled",
            )
        ],
        tags={"Name": f"{name}-cluster"},
    )

    # Capacity providers for Fargate and Fargate Spot
    capacity_providers = aws.ecs.ClusterCapacityProviders(
        f"{name}-capacity-providers",
        cluster_name=cluster.name,
        capacity_providers=["FARGATE", "FARGATE_SPOT"],
        default_capacity_provider_strategies=[
            aws.ecs.ClusterCapacityProvidersDefaultCapacityProviderStrategyArgs(
                capacity_provider="FARGATE",
                weight=1,
                base=1,
            ),
        ],
    )

    # IAM roles
    execution_role = _create_execution_role(name, kms_key_id, external_secrets_prefix)
    task_role = _create_task_role(name, kms_key_id, job_queue_arn, s3_source_iam_configs)

    # CloudWatch log group with optional KMS encryption
    log_group = aws.cloudwatch.LogGroup(
        f"{name}-logs",
        name=f"/ecs/{name}",
        retention_in_days=log_retention_days,
        kms_key_id=log_group_kms_key_id,
        tags={"Name": f"{name}-logs"},
    )

    # Task definition
    task_definition = _create_task_definition(
        name=name,
        container_image=container_image,
        cpu=api_cpu,
        memory=api_memory,
        execution_role_arn=execution_role.arn,
        task_role_arn=task_role.arn,
        log_group_name=log_group.name,
        environment=environment or {},
        secret_keys=secret_keys or [],
        external_secrets_prefix=external_secrets_prefix,
        job_queue_url=job_queue_url,
        job_table_name=job_table_name,
    )

    # Build capacity provider strategies
    capacity_provider_strategies = []
    if fargate_base > 0 or fargate_weight > 0:
        capacity_provider_strategies.append(
            aws.ecs.ServiceCapacityProviderStrategyArgs(
                capacity_provider="FARGATE",
                base=fargate_base,
                weight=fargate_weight,
            )
        )
    if fargate_spot_base > 0 or fargate_spot_weight > 0:
        capacity_provider_strategies.append(
            aws.ecs.ServiceCapacityProviderStrategyArgs(
                capacity_provider="FARGATE_SPOT",
                base=fargate_spot_base,
                weight=fargate_spot_weight,
            )
        )

    # ECS Service with capacity providers and circuit breaker
    api_service = aws.ecs.Service(
        f"{name}-service",
        name=f"{name}-api",
        cluster=cluster.id,
        task_definition=task_definition.arn,
        desired_count=api_min_instances,
        capacity_provider_strategies=capacity_provider_strategies if capacity_provider_strategies else None,
        network_configuration=aws.ecs.ServiceNetworkConfigurationArgs(
            subnets=subnet_ids,
            security_groups=[security_group_id],
            assign_public_ip=False,
        ),
        load_balancers=[
            aws.ecs.ServiceLoadBalancerArgs(
                target_group_arn=target_group_arn,
                container_name="cerebro",
                container_port=8080,
            )
        ],
        health_check_grace_period_seconds=120,
        deployment_maximum_percent=200,
        deployment_minimum_healthy_percent=100,
        force_new_deployment=True,
        deployment_circuit_breaker=(
            aws.ecs.ServiceDeploymentCircuitBreakerArgs(
                enable=True,
                rollback=True,
            )
            if enable_circuit_breaker
            else None
        ),
        tags={"Name": f"{name}-service"},
        opts=pulumi.ResourceOptions(depends_on=[capacity_providers]),
    )

    # Auto Scaling
    scaling_target = aws.appautoscaling.Target(
        f"{name}-scaling-target",
        service_namespace="ecs",
        resource_id=pulumi.Output.concat("service/", cluster.name, "/", api_service.name),
        scalable_dimension="ecs:service:DesiredCount",
        min_capacity=api_min_instances,
        max_capacity=api_max_instances,
    )

    # CPU scaling policy
    aws.appautoscaling.Policy(
        f"{name}-cpu-scaling",
        service_namespace="ecs",
        resource_id=scaling_target.resource_id,
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

    # Memory scaling policy
    aws.appautoscaling.Policy(
        f"{name}-memory-scaling",
        service_namespace="ecs",
        resource_id=scaling_target.resource_id,
        scalable_dimension="ecs:service:DesiredCount",
        policy_type="TargetTrackingScaling",
        target_tracking_scaling_policy_configuration=aws.appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationArgs(
            target_value=80.0,
            predefined_metric_specification=aws.appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationPredefinedMetricSpecificationArgs(
                predefined_metric_type="ECSServiceAverageMemoryUtilization",
            ),
            scale_in_cooldown=300,
            scale_out_cooldown=60,
        ),
    )

    return {
        "cluster": cluster,
        "capacity_providers": capacity_providers,
        "api_service": api_service,
        "task_definition": task_definition,
        "task_role": task_role,
        "log_group": log_group,
    }


def _create_execution_role(
    name: str,
    kms_key_id: pulumi.Output[str],
    external_secrets_prefix: str = None,
) -> aws.iam.Role:
    """Create IAM execution role for ECS."""
    if not external_secrets_prefix:
        raise ValueError("external_secrets_prefix is required for Infisical-managed secrets")

    role = aws.iam.Role(
        f"{name}-exec-role",
        name=f"{name}-exec-role",
        assume_role_policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        tags={"Name": f"{name}-exec-role"},
    )

    aws.iam.RolePolicyAttachment(
        f"{name}-exec-policy",
        role=role.name,
        policy_arn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
    )

    # Get account/region for ARN construction
    caller = aws.get_caller_identity()
    region = aws.get_region()

    # External secrets mode: allow access to Infisical-synced secrets
    secrets_resources = [
        f"arn:aws:secretsmanager:{region.region}:{caller.account_id}:secret:{external_secrets_prefix}/*"
    ]

    if secrets_resources:
        aws.iam.RolePolicy(
            f"{name}-exec-secrets",
            role=role.name,
            policy=pulumi.Output.all(secrets_resources, kms_key_id).apply(
                lambda args: json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["secretsmanager:GetSecretValue"],
                            "Resource": args[0],
                        },
                        {
                            "Effect": "Allow",
                            "Action": ["kms:Decrypt"],
                            "Resource": f"arn:aws:kms:*:*:key/{args[1]}",
                        },
                    ],
                })
            ),
        )

    return role


def _create_task_role(
    name: str,
    kms_key_id: pulumi.Output[str],
    job_queue_arn: pulumi.Output[str] = None,
    s3_source_iam_configs: list[dict] = None,
) -> aws.iam.Role:
    """Create IAM task role for application."""
    role = aws.iam.Role(
        f"{name}-task-role",
        name=f"{name}-task-role",
        assume_role_policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        tags={"Name": f"{name}-task-role"},
    )

    # CloudWatch metrics
    aws.iam.RolePolicy(
        f"{name}-task-cloudwatch",
        role=role.name,
        policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["cloudwatch:PutMetricData"],
                "Resource": "*",
            }],
        }),
    )

    # Cross-account assume-role for AWS inspections via cerebro-org-scan-role
    aws.iam.RolePolicy(
        f"{name}-task-assume-role",
        role=role.name,
        policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [
                    "sts:AssumeRole",
                    "sts:TagSession",
                ],
                "Resource": "arn:aws:iam::*:role/cerebro-org-scan-role",
            }],
        }),
    )

    # SQS permissions for sending jobs to queue (if queue ARN provided)
    # Use `is not None` to avoid boolean evaluation of Pulumi Output
    if job_queue_arn is not None:
        aws.iam.RolePolicy(
            f"{name}-task-sqs",
            role=role.name,
            policy=job_queue_arn.apply(
                lambda arn: json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": [
                            "sqs:SendMessage",
                            "sqs:GetQueueAttributes",
                        ],
                        "Resource": arn,
                    }],
                })
            ),
        )

    if s3_source_iam_configs:
        bucket_arns = []
        object_arns = []
        role_arns = []
        for cfg in s3_source_iam_configs:
            bucket_arn = cfg["bucket_arn"]
            bucket_arns.append(bucket_arn)
            prefixes = cfg.get("prefixes") or []
            if prefixes:
                for prefix in prefixes:
                    object_arns.append(f"{bucket_arn}/{prefix}*")
            else:
                object_arns.append(f"{bucket_arn}/*")
            if cfg.get("role_arn"):
                role_arns.append(cfg["role_arn"])

        statements = [
            {
                "Sid": "ListS3SourceBuckets",
                "Effect": "Allow",
                "Action": ["s3:ListBucket"],
                "Resource": bucket_arns,
            },
            {
                "Sid": "ReadS3SourceObjects",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": object_arns,
            },
        ]
        if role_arns:
            statements.append({
                "Sid": "AssumeS3SourceRoles",
                "Effect": "Allow",
                "Action": ["sts:AssumeRole"],
                "Resource": role_arns,
            })

        aws.iam.RolePolicy(
            f"{name}-task-s3-sources",
            role=role.name,
            policy=json.dumps({
                "Version": "2012-10-17",
                "Statement": statements,
            }),
        )

    return role


def _create_task_definition(
    name: str,
    container_image: str,
    cpu: int,
    memory: int,
    execution_role_arn: pulumi.Output[str],
    task_role_arn: pulumi.Output[str],
    log_group_name: pulumi.Output[str],
    environment: dict,
    secret_keys: list[str],
    external_secrets_prefix: str = None,
    job_queue_url: pulumi.Output[str] = None,
    job_table_name: pulumi.Output[str] = None,
) -> aws.ecs.TaskDefinition:
    """Create ECS task definition."""
    region_obj = aws.get_region()
    region = region_obj.region
    caller = aws.get_caller_identity()

    if not external_secrets_prefix:
        raise ValueError("external_secrets_prefix is required for Infisical-managed secrets")

    # External secrets mode: each secret is a separate Secrets Manager secret
    # synced by Infisical to {prefix}/{KEY}
    secrets_list = [
        {
            "name": key,
            "valueFrom": f"arn:aws:secretsmanager:{region}:{caller.account_id}:secret:{external_secrets_prefix}/{key}",
        }
        for key in secret_keys
    ]

    # Build static environment vars
    env_list = [{"name": k, "value": str(v)} for k, v in environment.items()]

    # Build container definition with dynamic job queue values
    def build_container_def(queue_url, table_name, log_group):
        env = env_list.copy()
        if queue_url:
            env.append({"name": "JOB_QUEUE_URL", "value": queue_url})
        if table_name:
            env.append({"name": "JOB_TABLE_NAME", "value": table_name})
        
        return [{
            "name": "cerebro",
            "image": container_image,
            "essential": True,
            "user": "10001",
            "readonlyRootFilesystem": True,
            "portMappings": [{"containerPort": 8080, "protocol": "tcp"}],
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {
                    "awslogs-group": log_group,
                    "awslogs-region": region,
                    "awslogs-stream-prefix": "ecs",
                },
            },
            "environment": env,
            "secrets": secrets_list,
            "healthCheck": {
                "command": ["CMD-SHELL", "wget -qO- http://localhost:8080/health || exit 1"],
                "interval": 30,
                "timeout": 5,
                "retries": 3,
                "startPeriod": 60,
            },
        }]

    container_definitions = pulumi.Output.all(
        job_queue_url or "",
        job_table_name or "",
        log_group_name,
    ).apply(lambda args: json.dumps(build_container_def(args[0], args[1], args[2])))

    return aws.ecs.TaskDefinition(
        f"{name}-task",
        family=name,
        cpu=str(cpu),
        memory=str(memory),
        network_mode="awsvpc",
        requires_compatibilities=["FARGATE"],
        runtime_platform=aws.ecs.TaskDefinitionRuntimePlatformArgs(
            operating_system_family="LINUX",
            cpu_architecture="ARM64",
        ),
        execution_role_arn=execution_role_arn,
        task_role_arn=task_role_arn,
        container_definitions=container_definitions,
        tags={"Name": f"{name}-task"},
    )
