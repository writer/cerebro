from __future__ import annotations

import json

import pulumi
import pulumi_aws as aws

from runtime import CerebroRuntimeConfig, SecretEnv, aws_cpu_units


def deploy(config: CerebroRuntimeConfig) -> None:
    provider = aws.Provider(
        "aws-provider",
        region=config.aws_region,
        skip_credentials_validation=config.aws_skip_credentials_validation,
        skip_metadata_api_check=config.aws_skip_credentials_validation,
        skip_requesting_account_id=config.aws_skip_credentials_validation,
    )
    opts = pulumi.ResourceOptions(provider=provider)

    subnet_cidrs = config.aws_public_subnet_cidrs
    if len(subnet_cidrs) < 2:
        raise ValueError("cerebro:awsPublicSubnetCidrs must contain at least two subnet CIDRs")
    availability_zones = config.aws_availability_zones or [
        f"{config.aws_region}a",
        f"{config.aws_region}b",
    ]
    if len(availability_zones) < len(subnet_cidrs):
        raise ValueError("cerebro:awsAvailabilityZones must cover every public subnet CIDR")

    vpc = aws.ec2.Vpc(
        f"{config.name}-vpc",
        cidr_block=config.aws_vpc_cidr,
        enable_dns_hostnames=True,
        enable_dns_support=True,
        tags={"Name": f"{config.name}-vpc"},
        opts=opts,
    )
    internet_gateway = aws.ec2.InternetGateway(
        f"{config.name}-igw",
        vpc_id=vpc.id,
        tags={"Name": f"{config.name}-igw"},
        opts=opts,
    )
    route_table = aws.ec2.RouteTable(
        f"{config.name}-public-rt",
        vpc_id=vpc.id,
        routes=[aws.ec2.RouteTableRouteArgs(cidr_block="0.0.0.0/0", gateway_id=internet_gateway.id)],
        tags={"Name": f"{config.name}-public-rt"},
        opts=opts,
    )
    subnets = []
    for index, cidr in enumerate(subnet_cidrs):
        subnet = aws.ec2.Subnet(
            f"{config.name}-public-{index + 1}",
            vpc_id=vpc.id,
            cidr_block=cidr,
            availability_zone=availability_zones[index],
            map_public_ip_on_launch=True,
            tags={"Name": f"{config.name}-public-{index + 1}"},
            opts=opts,
        )
        aws.ec2.RouteTableAssociation(
            f"{config.name}-public-{index + 1}-rt",
            subnet_id=subnet.id,
            route_table_id=route_table.id,
            opts=opts,
        )
        subnets.append(subnet)

    alb_sg = aws.ec2.SecurityGroup(
        f"{config.name}-alb-sg",
        vpc_id=vpc.id,
        description="Cerebro ALB ingress",
        ingress=[
            aws.ec2.SecurityGroupIngressArgs(
                protocol="tcp",
                from_port=80,
                to_port=80,
                cidr_blocks=["0.0.0.0/0"],
            )
        ],
        egress=[
            aws.ec2.SecurityGroupEgressArgs(
                protocol="-1",
                from_port=0,
                to_port=0,
                cidr_blocks=["0.0.0.0/0"],
            )
        ],
        tags={"Name": f"{config.name}-alb-sg"},
        opts=opts,
    )
    app_sg = aws.ec2.SecurityGroup(
        f"{config.name}-app-sg",
        vpc_id=vpc.id,
        description="Cerebro ECS task ingress",
        ingress=[
            aws.ec2.SecurityGroupIngressArgs(
                protocol="tcp",
                from_port=config.container_port,
                to_port=config.container_port,
                security_groups=[alb_sg.id],
            )
        ],
        egress=[
            aws.ec2.SecurityGroupEgressArgs(
                protocol="-1",
                from_port=0,
                to_port=0,
                cidr_blocks=["0.0.0.0/0"],
            )
        ],
        tags={"Name": f"{config.name}-app-sg"},
        opts=opts,
    )

    cluster = aws.ecs.Cluster(
        f"{config.name}-cluster",
        name=_aws_name(config.name, "cluster", 255),
        settings=[aws.ecs.ClusterSettingArgs(name="containerInsights", value="enabled")],
        tags={"Name": f"{config.name}-cluster"},
        opts=opts,
    )
    log_group = aws.cloudwatch.LogGroup(
        f"{config.name}-logs",
        name=f"/ecs/{config.name}",
        retention_in_days=30,
        opts=opts,
    )
    execution_role = aws.iam.Role(
        f"{config.name}-execution-role",
        name=_aws_name(config.name, "execution-role", 64),
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
        opts=opts,
    )
    execution_policy_attachment = aws.iam.RolePolicyAttachment(
        f"{config.name}-execution-policy",
        role=execution_role.name,
        policy_arn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
        opts=opts,
    )
    task_role = aws.iam.Role(
        f"{config.name}-task-role",
        name=_aws_name(config.name, "task-role", 64),
        assume_role_policy=execution_role.assume_role_policy,
        opts=opts,
    )

    secret_refs = _create_secrets(config.name, config.secret_env(), opts)
    if secret_refs:
        aws.iam.RolePolicy(
            f"{config.name}-execution-secrets",
            role=execution_role.id,
            policy=pulumi.Output.json_dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["secretsmanager:GetSecretValue"],
                            "Resource": [secret["arn"] for secret in secret_refs],
                        }
                    ],
                }
            ),
            opts=opts,
        )

    container_definition = _container_definition(config, log_group.name, secret_refs)
    task_definition = aws.ecs.TaskDefinition(
        f"{config.name}-task",
        family=config.name,
        cpu=aws_cpu_units(config.cpu),
        memory=str(config.memory_mib),
        network_mode="awsvpc",
        requires_compatibilities=["FARGATE"],
        execution_role_arn=execution_role.arn,
        task_role_arn=task_role.arn,
        container_definitions=pulumi.Output.json_dumps([container_definition]),
        opts=pulumi.ResourceOptions(provider=provider, depends_on=[execution_policy_attachment]),
    )

    load_balancer = aws.lb.LoadBalancer(
        f"{config.name}-alb",
        name=_aws_name(config.name, "alb", 32),
        load_balancer_type="application",
        security_groups=[alb_sg.id],
        subnets=[subnet.id for subnet in subnets],
        tags={"Name": f"{config.name}-alb"},
        opts=opts,
    )
    target_group = aws.lb.TargetGroup(
        f"{config.name}-tg",
        name=_aws_name(config.name, "tg", 32),
        port=config.container_port,
        protocol="HTTP",
        target_type="ip",
        vpc_id=vpc.id,
        health_check=aws.lb.TargetGroupHealthCheckArgs(
            path="/health",
            matcher="200-399",
            interval=30,
            timeout=5,
            healthy_threshold=2,
            unhealthy_threshold=3,
        ),
        tags={"Name": f"{config.name}-tg"},
        opts=opts,
    )
    listener = aws.lb.Listener(
        f"{config.name}-http",
        load_balancer_arn=load_balancer.arn,
        port=80,
        protocol="HTTP",
        default_actions=[
            aws.lb.ListenerDefaultActionArgs(
                type="forward",
                target_group_arn=target_group.arn,
            )
        ],
        opts=opts,
    )
    service = aws.ecs.Service(
        f"{config.name}-api",
        name=_aws_name(config.name, "api", 255),
        cluster=cluster.id,
        desired_count=max(config.min_replicas, 1),
        launch_type="FARGATE",
        task_definition=task_definition.arn,
        network_configuration=aws.ecs.ServiceNetworkConfigurationArgs(
            subnets=[subnet.id for subnet in subnets],
            security_groups=[app_sg.id],
            assign_public_ip=config.aws_assign_public_ip,
        ),
        load_balancers=[
            aws.ecs.ServiceLoadBalancerArgs(
                target_group_arn=target_group.arn,
                container_name="cerebro",
                container_port=config.container_port,
            )
        ],
        deployment_circuit_breaker=aws.ecs.ServiceDeploymentCircuitBreakerArgs(enable=True, rollback=True),
        opts=pulumi.ResourceOptions(provider=provider, depends_on=[listener]),
    )

    pulumi.export("cloud", "aws")
    pulumi.export("service_name", service.name)
    pulumi.export("cluster_name", cluster.name)
    pulumi.export("url", pulumi.Output.concat("http://", load_balancer.dns_name))


def _create_secrets(name: str, secrets: list[SecretEnv], opts: pulumi.ResourceOptions) -> list[dict[str, pulumi.Input[str]]]:
    refs = []
    for secret in secrets:
        resource_name = f"{name}-{secret.name.lower().replace('_', '-')}"
        secret_resource = aws.secretsmanager.Secret(
            resource_name,
            name=f"{name}/{secret.name}",
            opts=opts,
        )
        aws.secretsmanager.SecretVersion(
            f"{resource_name}-version",
            secret_id=secret_resource.id,
            secret_string=secret.value,
            opts=opts,
        )
        refs.append({"name": secret.name, "arn": secret_resource.arn})
    return refs


def _aws_name(prefix: str, suffix: str, max_length: int) -> str:
    value = f"{prefix}-{suffix}"
    if len(value) <= max_length:
        return value
    suffix_part = f"-{suffix}"
    keep = max_length - len(suffix_part)
    if keep <= 0:
        return suffix[:max_length]
    return f"{prefix[:keep].rstrip('-')}{suffix_part}"


def _container_definition(
    config: CerebroRuntimeConfig,
    log_group_name: pulumi.Input[str],
    secret_refs: list[dict[str, pulumi.Input[str]]],
) -> dict:
    return {
        "name": "cerebro",
        "image": config.image,
        "essential": True,
        "command": ["serve"],
        "portMappings": [
            {
                "containerPort": config.container_port,
                "hostPort": config.container_port,
                "protocol": "tcp",
            }
        ],
        "environment": [{"name": key, "value": value} for key, value in sorted(config.plain_env().items())],
        "secrets": [{"name": ref["name"], "valueFrom": ref["arn"]} for ref in secret_refs],
        "logConfiguration": {
            "logDriver": "awslogs",
            "options": {
                "awslogs-group": log_group_name,
                "awslogs-region": config.aws_region,
                "awslogs-stream-prefix": "cerebro",
            },
        },
        "healthCheck": {
            "command": ["CMD-SHELL", f"curl -fsS http://127.0.0.1:{config.container_port}/livez >/dev/null || exit 1"],
            "interval": 30,
            "timeout": 5,
            "retries": 3,
            "startPeriod": 20,
        },
    }
