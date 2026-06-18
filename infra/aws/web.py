"""AWS ECS Fargate service for the Cerebro web console."""

import json

import pulumi
import pulumi_aws as aws


def create_web_service(
    name: str,
    cluster_id: pulumi.Input[str],
    cluster_name: pulumi.Input[str],
    subnet_ids: list[pulumi.Input[str]],
    security_group_id: pulumi.Input[str],
    target_group_arn: pulumi.Input[str],
    container_image: str,
    kms_key_id: pulumi.Input[str],
    external_secrets_prefix: str,
    cpu: int = 512,
    memory: int = 1024,
    min_instances: int = 1,
    max_instances: int = 1,
    container_port: int = 3000,
    log_retention_days: int = 30,
    log_group_kms_key_id: pulumi.Input[str] = None,
    environment: dict = None,
    secret_keys: list = None,
    log_insights_log_group_arns: list[pulumi.Input[str]] = None,
    fargate_base: int = 1,
    fargate_weight: int = 1,
    fargate_spot_base: int = 0,
    fargate_spot_weight: int = 0,
    depends_on: list[pulumi.Resource] = None,
) -> dict:
    if not external_secrets_prefix:
        raise ValueError("external_secrets_prefix is required")

    execution_role = _create_execution_role(name, kms_key_id, external_secrets_prefix)
    task_role = _create_task_role(name)
    log_group = aws.cloudwatch.LogGroup(
        f"{name}-logs",
        name=f"/ecs/{name}",
        retention_in_days=log_retention_days,
        kms_key_id=log_group_kms_key_id,
        tags={"Name": f"{name}-logs"},
    )
    if log_insights_log_group_arns:
        _attach_log_insights_policy(name, task_role, [*log_insights_log_group_arns, log_group.arn])

    task_definition = _create_task_definition(
        name=name,
        container_image=container_image,
        cpu=cpu,
        memory=memory,
        execution_role_arn=execution_role.arn,
        task_role_arn=task_role.arn,
        log_group_name=log_group.name,
        environment=environment or {},
        secret_keys=secret_keys or [],
        external_secrets_prefix=external_secrets_prefix,
        container_port=container_port,
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

    service = aws.ecs.Service(
        f"{name}-service",
        name=f"{name}",
        cluster=cluster_id,
        task_definition=task_definition.arn,
        desired_count=min_instances,
        capacity_provider_strategies=capacity_provider_strategies if capacity_provider_strategies else None,
        availability_zone_rebalancing="DISABLED" if max_instances == 1 else "ENABLED",
        network_configuration=aws.ecs.ServiceNetworkConfigurationArgs(
            subnets=subnet_ids,
            security_groups=[security_group_id],
            assign_public_ip=False,
        ),
        load_balancers=[aws.ecs.ServiceLoadBalancerArgs(
            target_group_arn=target_group_arn,
            container_name="cerebro-web",
            container_port=container_port,
        )],
        health_check_grace_period_seconds=120,
        deployment_maximum_percent=200,
        deployment_minimum_healthy_percent=100,
        force_new_deployment=True,
        deployment_circuit_breaker=aws.ecs.ServiceDeploymentCircuitBreakerArgs(enable=True, rollback=True),
        tags={"Name": f"{name}-service"},
        opts=pulumi.ResourceOptions(depends_on=depends_on or []),
    )

    scaling_target = aws.appautoscaling.Target(
        f"{name}-scaling-target",
        service_namespace="ecs",
        resource_id=pulumi.Output.concat("service/", cluster_name, "/", service.name),
        scalable_dimension="ecs:service:DesiredCount",
        min_capacity=min_instances,
        max_capacity=max_instances,
    )

    if max_instances > min_instances:
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
        aws.appautoscaling.Policy(
            f"{name}-memory-scaling",
            service_namespace="ecs",
            resource_id=scaling_target.resource_id,
            scalable_dimension="ecs:service:DesiredCount",
            policy_type="TargetTrackingScaling",
            target_tracking_scaling_policy_configuration=aws.appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationArgs(
                target_value=75.0,
                predefined_metric_specification=aws.appautoscaling.PolicyTargetTrackingScalingPolicyConfigurationPredefinedMetricSpecificationArgs(
                    predefined_metric_type="ECSServiceAverageMemoryUtilization",
                ),
                scale_in_cooldown=300,
                scale_out_cooldown=60,
            ),
        )

    return {
        "service": service,
        "task_definition": task_definition,
        "execution_role": execution_role,
        "task_role": task_role,
        "log_group": log_group,
    }


def _create_execution_role(name: str, kms_key_id: pulumi.Input[str], external_secrets_prefix: str) -> aws.iam.Role:
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


def _create_task_role(name: str) -> aws.iam.Role:
    return aws.iam.Role(
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


def _attach_log_insights_policy(name: str, role: aws.iam.Role, log_group_arns: list[pulumi.Input[str]]) -> aws.iam.RolePolicy:
    def log_group_resources(log_groups: list[str]) -> list[str]:
        resources: list[str] = []
        for log_group in log_groups:
            resources.append(log_group)
            resources.append(f"{log_group}:*")
        return resources

    return aws.iam.RolePolicy(
        f"{name}-task-log-insights",
        role=role.name,
        policy=pulumi.Output.all(*log_group_arns).apply(lambda log_groups: json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:StartQuery",
                        "logs:StopQuery",
                    ],
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:FilterLogEvents",
                    ],
                    "Resource": log_group_resources(list(log_groups)),
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:DescribeLogGroups",
                        "logs:GetQueryResults",
                    ],
                    "Resource": "*",
                },
            ],
        })),
    )


def _create_task_definition(
    name: str,
    container_image: str,
    cpu: int,
    memory: int,
    execution_role_arn: pulumi.Input[str],
    task_role_arn: pulumi.Input[str],
    log_group_name: pulumi.Input[str],
    environment: dict,
    secret_keys: list,
    external_secrets_prefix: str,
    container_port: int,
) -> aws.ecs.TaskDefinition:
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
        secret_env = [{"name": name, "valueFrom": f"{secrets_prefix_arn}/{source}"} for name, source in secret_specs]
        return [{
            "name": "cerebro-web",
            "image": container_image,
            "essential": True,
            "user": "10001",
            "readonlyRootFilesystem": True,
            "portMappings": [{"containerPort": container_port, "protocol": "tcp"}],
            "healthCheck": {
                "command": [
                    "CMD-SHELL",
                    f"node -e \"const host=require('os').hostname();fetch('http://'+host+':{container_port}/api/health').then((r)=>{{if(!r.ok)process.exit(1)}}).catch(()=>process.exit(1))\"",
                ],
                "interval": 30,
                "timeout": 5,
                "retries": 3,
                "startPeriod": 60,
            },
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {
                    "awslogs-group": log_group,
                    "awslogs-region": region,
                    "awslogs-stream-prefix": "web",
                },
            },
            "environment": env,
            "secrets": secret_env,
        }]

    container_definitions = pulumi.Output.all(log_group_name, *env_values).apply(lambda args: json.dumps(build_container_def(args)))

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
