"""
AWS ECS Fargate compute for the Cerebro rewrite runtime.
"""

import json

import pulumi
import pulumi_aws as aws


def create_ecs_cluster(
    name: str,
    vpc_id: pulumi.Input[str],
    subnet_ids: list[pulumi.Input[str]],
    security_group_id: pulumi.Input[str],
    kms_key_id: pulumi.Input[str],
    target_group_arn: pulumi.Input[str],
    container_image: str,
    api_cpu: int = 1024,
    api_memory: int = 2048,
    api_min_instances: int = 1,
    api_max_instances: int = 1,
    log_retention_days: int = 30,
    environment: dict = None,
    secret_keys: list[str] = None,
    external_secrets_prefix: str = None,
    log_group_kms_key_id: pulumi.Input[str] = None,
    s3_source_iam_configs: list[dict] = None,
    efs_file_system_id: pulumi.Input[str] = None,
    efs_access_point_id: pulumi.Input[str] = None,
    efs_container_path: str = None,
    depends_on: list[pulumi.Resource] = None,
    fargate_base: int = 1,
    fargate_weight: int = 1,
    fargate_spot_base: int = 0,
    fargate_spot_weight: int = 0,
    enable_circuit_breaker: bool = True,
) -> dict:
    """Create ECS cluster with an API service."""
    cluster = aws.ecs.Cluster(
        f"{name}-cluster",
        name=f"{name}-cluster",
        settings=[aws.ecs.ClusterSettingArgs(name="containerInsights", value="enabled")],
        tags={"Name": f"{name}-cluster"},
    )

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

    execution_role = _create_execution_role(name, kms_key_id, external_secrets_prefix)
    task_role = _create_task_role(name, s3_source_iam_configs, efs_file_system_id)

    log_group = aws.cloudwatch.LogGroup(
        f"{name}-logs",
        name=f"/ecs/{name}",
        retention_in_days=log_retention_days,
        kms_key_id=log_group_kms_key_id,
        tags={"Name": f"{name}-logs"},
    )

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
        efs_file_system_id=efs_file_system_id,
        efs_access_point_id=efs_access_point_id,
        efs_container_path=efs_container_path,
    )

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

    service_dependencies = [capacity_providers]
    if depends_on:
        service_dependencies.extend(depends_on)

    uses_singleton_deployments = api_max_instances == 1

    api_service = aws.ecs.Service(
        f"{name}-service",
        name=f"{name}-api",
        cluster=cluster.id,
        task_definition=task_definition.arn,
        desired_count=api_min_instances,
        capacity_provider_strategies=capacity_provider_strategies if capacity_provider_strategies else None,
        availability_zone_rebalancing="DISABLED" if uses_singleton_deployments else "ENABLED",
        network_configuration=aws.ecs.ServiceNetworkConfigurationArgs(
            subnets=subnet_ids,
            security_groups=[security_group_id],
            assign_public_ip=False,
        ),
        load_balancers=[aws.ecs.ServiceLoadBalancerArgs(
            target_group_arn=target_group_arn,
            container_name="cerebro",
            container_port=8080,
        )],
        health_check_grace_period_seconds=120,
        deployment_maximum_percent=100 if uses_singleton_deployments else 200,
        deployment_minimum_healthy_percent=0 if uses_singleton_deployments else 100,
        force_new_deployment=True,
        deployment_circuit_breaker=(
            aws.ecs.ServiceDeploymentCircuitBreakerArgs(enable=True, rollback=True)
            if enable_circuit_breaker
            else None
        ),
        tags={"Name": f"{name}-service"},
        opts=pulumi.ResourceOptions(depends_on=service_dependencies),
    )

    scaling_target = aws.appautoscaling.Target(
        f"{name}-scaling-target",
        service_namespace="ecs",
        resource_id=pulumi.Output.concat("service/", cluster.name, "/", api_service.name),
        scalable_dimension="ecs:service:DesiredCount",
        min_capacity=api_min_instances,
        max_capacity=api_max_instances,
    )

    if api_max_instances > api_min_instances:
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

    return {
        "cluster": cluster,
        "capacity_providers": capacity_providers,
        "api_service": api_service,
        "task_definition": task_definition,
        "task_role": task_role,
        "log_group": log_group,
    }


def _create_execution_role(name: str, kms_key_id: pulumi.Input[str], external_secrets_prefix: str) -> aws.iam.Role:
    if not external_secrets_prefix:
        raise ValueError("external_secrets_prefix is required")

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

    caller = aws.get_caller_identity()
    region = aws.get_region()
    secret_resources = [f"arn:aws:secretsmanager:{region.region}:{caller.account_id}:secret:{external_secrets_prefix}/*"]

    aws.iam.RolePolicy(
        f"{name}-exec-secrets",
        role=role.name,
        policy=pulumi.Output.all(secret_resources, kms_key_id).apply(lambda args: json.dumps({
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
        })),
    )

    return role


def _create_task_role(
    name: str,
    s3_source_iam_configs: list[dict] = None,
    efs_file_system_id: pulumi.Input[str] = None,
) -> aws.iam.Role:
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

    aws.iam.RolePolicy(
        f"{name}-task-assume-role",
        role=role.name,
        policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["sts:AssumeRole", "sts:TagSession"],
                "Resource": [
                    "arn:aws:iam::*:role/cerebro-org-scan-role",
                    "arn:aws:iam::*:role/cerebro-*-source-*",
                ],
            }],
        }),
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
            {"Sid": "ListS3SourceBuckets", "Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": bucket_arns},
            {"Sid": "ReadS3SourceObjects", "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": object_arns},
        ]
        if role_arns:
            statements.append({"Sid": "AssumeS3SourceRoles", "Effect": "Allow", "Action": ["sts:AssumeRole"], "Resource": role_arns})
        aws.iam.RolePolicy(
            f"{name}-task-s3-sources",
            role=role.name,
            policy=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )

    if efs_file_system_id is not None:
        aws.iam.RolePolicy(
            f"{name}-task-efs",
            role=role.name,
            policy=pulumi.Output.all(efs_file_system_id).apply(lambda args: json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"],
                    "Resource": f"arn:aws:elasticfilesystem:*:*:file-system/{args[0]}",
                }],
            })),
        )

    return role


def _create_task_definition(
    name: str,
    container_image: str,
    cpu: int,
    memory: int,
    execution_role_arn: pulumi.Input[str],
    task_role_arn: pulumi.Input[str],
    log_group_name: pulumi.Input[str],
    environment: dict,
    secret_keys: list[str],
    external_secrets_prefix: str,
    efs_file_system_id: pulumi.Input[str] = None,
    efs_access_point_id: pulumi.Input[str] = None,
    efs_container_path: str = None,
) -> aws.ecs.TaskDefinition:
    if not external_secrets_prefix:
        raise ValueError("external_secrets_prefix is required")

    region = aws.get_region().region
    caller = aws.get_caller_identity()
    secrets_prefix_arn = f"arn:aws:secretsmanager:{region}:{caller.account_id}:secret:{external_secrets_prefix}"
    secret_specs = []
    for secret_key in secret_keys:
        if isinstance(secret_key, dict):
            secret_specs.append((secret_key["name"], secret_key["source"]))
        else:
            secret_specs.append((secret_key, secret_key))
    env_items = sorted(environment.items())
    env_values = [value for _, value in env_items]

    def build_container_def(args):
        log_group = args[0]
        resolved_env_values = args[1:]
        env = [
            {"name": key, "value": str(value)}
            for (key, _), value in zip(env_items, resolved_env_values)
        ]
        container = {
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
            "secrets": [{"name": name, "valueFrom": f"{secrets_prefix_arn}/{source}"} for name, source in secret_specs],
            "healthCheck": {
                "command": ["CMD-SHELL", "curl -fsS http://localhost:8080/health || exit 1"],
                "interval": 30,
                "timeout": 5,
                "retries": 3,
                "startPeriod": 60,
            },
        }
        if efs_container_path:
            container["mountPoints"] = [{"sourceVolume": "cerebro-data", "containerPath": efs_container_path, "readOnly": False}]
        return [container]

    container_definitions = pulumi.Output.all(log_group_name, *env_values).apply(lambda args: json.dumps(build_container_def(args)))

    volumes = None
    if efs_file_system_id is not None and efs_access_point_id is not None:
        volumes = [aws.ecs.TaskDefinitionVolumeArgs(
            name="cerebro-data",
            efs_volume_configuration=aws.ecs.TaskDefinitionVolumeEfsVolumeConfigurationArgs(
                file_system_id=efs_file_system_id,
                transit_encryption="ENABLED",
                authorization_config=aws.ecs.TaskDefinitionVolumeEfsVolumeConfigurationAuthorizationConfigArgs(
                    access_point_id=efs_access_point_id,
                    iam="ENABLED",
                ),
            ),
        )]

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
        volumes=volumes,
        tags={"Name": f"{name}-task"},
    )
