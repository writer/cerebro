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
    secrets_arn: pulumi.Output[str],
    kms_key_id: pulumi.Output[str],
    target_group_arn: pulumi.Output[str],
    container_image: str,
    api_cpu: int = 1024,
    api_memory: int = 2048,
    api_min_instances: int = 2,
    api_max_instances: int = 10,
    log_retention_days: int = 30,
    environment: dict = None,
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

    # IAM roles
    execution_role = _create_execution_role(name, secrets_arn, kms_key_id)
    task_role = _create_task_role(name, kms_key_id)

    # CloudWatch log group
    log_group = aws.cloudwatch.LogGroup(
        f"{name}-logs",
        name=f"/ecs/{name}",
        retention_in_days=log_retention_days,
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
        secrets_arn=secrets_arn,
        environment=environment or {},
    )

    # ECS Service
    api_service = aws.ecs.Service(
        f"{name}-service",
        name=f"{name}-api",
        cluster=cluster.id,
        task_definition=task_definition.arn,
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
                container_name="cerebro",
                container_port=8080,
            )
        ],
        health_check_grace_period_seconds=120,
        deployment_configuration=aws.ecs.ServiceDeploymentConfigurationArgs(
            maximum_percent=200,
            minimum_healthy_percent=100,
        ),
        tags={"Name": f"{name}-service"},
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
        "api_service": api_service,
        "task_definition": task_definition,
        "log_group": log_group,
    }


def _create_execution_role(
    name: str,
    secrets_arn: pulumi.Output[str],
    kms_key_id: pulumi.Output[str],
) -> aws.iam.Role:
    """Create IAM execution role for ECS."""
    role = aws.iam.Role(
        f"{name}-exec-role",
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

    aws.iam.RolePolicy(
        f"{name}-exec-secrets",
        role=role.name,
        policy=pulumi.Output.all(secrets_arn, kms_key_id).apply(
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


def _create_task_role(name: str, kms_key_id: pulumi.Output[str]) -> aws.iam.Role:
    """Create IAM task role for application."""
    role = aws.iam.Role(
        f"{name}-task-role",
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

    return role


def _create_task_definition(
    name: str,
    container_image: str,
    cpu: int,
    memory: int,
    execution_role_arn: pulumi.Output[str],
    task_role_arn: pulumi.Output[str],
    log_group_name: pulumi.Output[str],
    secrets_arn: pulumi.Output[str],
    environment: dict,
) -> aws.ecs.TaskDefinition:
    """Create ECS task definition."""
    region = aws.get_region().name

    container_def = {
        "name": "cerebro",
        "image": container_image,
        "command": ["serve"],
        "essential": True,
        "portMappings": [{"containerPort": 8080, "protocol": "tcp"}],
        "logConfiguration": {
            "logDriver": "awslogs",
            "options": {
                "awslogs-group": log_group_name,
                "awslogs-region": region,
                "awslogs-stream-prefix": "ecs",
            },
        },
        "environment": [{"name": k, "value": str(v)} for k, v in environment.items()],
        "secrets": [
            {"name": "SNOWFLAKE_CONNECTION_STRING", "valueFrom": pulumi.Output.concat(secrets_arn, ":SNOWFLAKE_CONNECTION_STRING::")},
            {"name": "ANTHROPIC_API_KEY", "valueFrom": pulumi.Output.concat(secrets_arn, ":ANTHROPIC_API_KEY::")},
            {"name": "OPENAI_API_KEY", "valueFrom": pulumi.Output.concat(secrets_arn, ":OPENAI_API_KEY::")},
            {"name": "SLACK_WEBHOOK_URL", "valueFrom": pulumi.Output.concat(secrets_arn, ":SLACK_WEBHOOK_URL::")},
            {"name": "JIRA_API_TOKEN", "valueFrom": pulumi.Output.concat(secrets_arn, ":JIRA_API_TOKEN::")},
            {"name": "LINEAR_API_KEY", "valueFrom": pulumi.Output.concat(secrets_arn, ":LINEAR_API_KEY::")},
        ],
        "healthCheck": {
            "command": ["CMD-SHELL", "wget -q --spider http://localhost:8080/health || exit 1"],
            "interval": 30,
            "timeout": 5,
            "retries": 3,
            "startPeriod": 60,
        },
    }

    return aws.ecs.TaskDefinition(
        f"{name}-task",
        family=name,
        cpu=str(cpu),
        memory=str(memory),
        network_mode="awsvpc",
        requires_compatibilities=["FARGATE"],
        execution_role_arn=execution_role_arn,
        task_role_arn=task_role_arn,
        container_definitions=pulumi.Output.json_dumps([container_def]),
        tags={"Name": f"{name}-task"},
    )
