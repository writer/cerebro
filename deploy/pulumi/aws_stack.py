from __future__ import annotations

import json

import pulumi
import pulumi_aws as aws

from runtime import CerebroRuntimeConfig, ExistingSecretRef, SecretEnv, ScheduledJob, aws_cpu_units, normalized_secret_name


class AwsCerebroService(pulumi.ComponentResource):
    def __init__(
        self,
        name: str,
        config: CerebroRuntimeConfig,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        super().__init__("cerebro:cloud:AwsService", name, None, opts)
        provider = aws.Provider(
            f"{name}-aws-provider",
            region=config.aws_region,
            skip_credentials_validation=config.aws_skip_credentials_validation,
            skip_metadata_api_check=config.aws_skip_credentials_validation,
            skip_requesting_account_id=config.aws_skip_credentials_validation,
            opts=pulumi.ResourceOptions(parent=self),
        )
        child_opts = pulumi.ResourceOptions(provider=provider, parent=self)

        network = _create_network(config, child_opts)
        alb_sg, app_sg = _create_security_groups(config, network["vpc_id"], child_opts)

        cluster = aws.ecs.Cluster(
            f"{config.name}-cluster",
            name=_aws_name(config.name, "cluster", 255),
            settings=[aws.ecs.ClusterSettingArgs(name="containerInsights", value="enabled")],
            tags={"Name": f"{config.name}-cluster"},
            opts=child_opts,
        )
        log_group = aws.cloudwatch.LogGroup(
            f"{config.name}-logs",
            name=f"/ecs/{config.name}",
            retention_in_days=config.aws_log_retention_days,
            opts=child_opts,
        )
        execution_role = aws.iam.Role(
            f"{config.name}-execution-role",
            name=_aws_name(config.name, "execution-role", 64),
            assume_role_policy=_assume_role_policy("ecs-tasks.amazonaws.com"),
            opts=child_opts,
        )
        execution_policy_attachment = aws.iam.RolePolicyAttachment(
            f"{config.name}-execution-policy",
            role=execution_role.name,
            policy_arn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
            opts=child_opts,
        )
        task_role = aws.iam.Role(
            f"{config.name}-task-role",
            name=_aws_name(config.name, "task-role", 64),
            assume_role_policy=execution_role.assume_role_policy,
            opts=child_opts,
        )

        created_secret_refs = _create_secrets(config.name, config.created_secret_env(), child_opts)
        existing_secret_refs = _existing_aws_secret_refs(config.existing_secret_refs)
        secret_refs = created_secret_refs + existing_secret_refs
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
                opts=child_opts,
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
            opts=pulumi.ResourceOptions(provider=provider, parent=self, depends_on=[execution_policy_attachment]),
        )

        load_balancer = aws.lb.LoadBalancer(
            f"{config.name}-alb",
            name=_aws_name(config.name, "alb", 32),
            load_balancer_type="application",
            security_groups=[alb_sg.id],
            subnets=network["public_subnet_ids"],
            tags={"Name": f"{config.name}-alb"},
            opts=child_opts,
        )
        target_group = aws.lb.TargetGroup(
            f"{config.name}-tg",
            name=_aws_name(config.name, "tg", 32),
            port=config.container_port,
            protocol="HTTP",
            target_type="ip",
            vpc_id=network["vpc_id"],
            health_check=aws.lb.TargetGroupHealthCheckArgs(
                path="/health",
                matcher="200-399",
                interval=30,
                timeout=5,
                healthy_threshold=2,
                unhealthy_threshold=3,
            ),
            tags={"Name": f"{config.name}-tg"},
            opts=child_opts,
        )
        listeners = _create_listeners(config, load_balancer.arn, target_group.arn, child_opts)
        service = aws.ecs.Service(
            f"{config.name}-api",
            name=_aws_name(config.name, "api", 255),
            cluster=cluster.id,
            desired_count=max(config.min_replicas, 1),
            launch_type="FARGATE",
            task_definition=task_definition.arn,
            network_configuration=aws.ecs.ServiceNetworkConfigurationArgs(
                subnets=network["service_subnet_ids"],
                security_groups=[app_sg.id],
                assign_public_ip=config.aws_assign_public_ip if not config.aws_enable_private_subnets else False,
            ),
            load_balancers=[
                aws.ecs.ServiceLoadBalancerArgs(
                    target_group_arn=target_group.arn,
                    container_name="cerebro",
                    container_port=config.container_port,
                )
            ],
            deployment_circuit_breaker=aws.ecs.ServiceDeploymentCircuitBreakerArgs(enable=True, rollback=True),
            opts=pulumi.ResourceOptions(provider=provider, parent=self, depends_on=listeners),
        )

        schedule_names = _create_schedules(
            config,
            cluster.arn,
            task_definition.arn,
            execution_role.arn,
            task_role.arn,
            network["service_subnet_ids"],
            [app_sg.id],
            child_opts,
        )

        url_scheme = "https" if config.aws_certificate_arn else "http"
        self.outputs = {
            "cloud": "aws",
            "service_name": service.name,
            "cluster_name": cluster.name,
            "cluster_arn": cluster.arn,
            "task_definition_arn": task_definition.arn,
            "url": pulumi.Output.concat(url_scheme, "://", load_balancer.dns_name),
            "schedule_names": schedule_names,
        }
        self.register_outputs(self.outputs)


def deploy(config: CerebroRuntimeConfig) -> AwsCerebroService:
    service = AwsCerebroService(config.name, config)
    for key, value in service.outputs.items():
        pulumi.export(key, value)
    return service


def _create_network(config: CerebroRuntimeConfig, opts: pulumi.ResourceOptions) -> dict[str, list[pulumi.Input[str]] | pulumi.Input[str]]:
    public_subnet_cidrs = config.aws_public_subnet_cidrs
    if len(public_subnet_cidrs) < 2:
        raise ValueError("cerebro:awsPublicSubnetCidrs must contain at least two subnet CIDRs")
    private_subnet_cidrs = config.aws_private_subnet_cidrs if config.aws_enable_private_subnets else []
    availability_zones = config.aws_availability_zones or [f"{config.aws_region}a", f"{config.aws_region}b"]
    if len(availability_zones) < max(len(public_subnet_cidrs), len(private_subnet_cidrs)):
        raise ValueError("cerebro:awsAvailabilityZones must cover every configured subnet CIDR")

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
    public_route_table = aws.ec2.RouteTable(
        f"{config.name}-public-rt",
        vpc_id=vpc.id,
        routes=[aws.ec2.RouteTableRouteArgs(cidr_block="0.0.0.0/0", gateway_id=internet_gateway.id)],
        tags={"Name": f"{config.name}-public-rt"},
        opts=opts,
    )

    public_subnets = []
    for index, cidr in enumerate(public_subnet_cidrs):
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
            route_table_id=public_route_table.id,
            opts=opts,
        )
        public_subnets.append(subnet)

    service_subnets = public_subnets
    if private_subnet_cidrs:
        private_route_table_routes = []
        if config.aws_enable_nat_gateway:
            eip = aws.ec2.Eip(
                f"{config.name}-nat-eip",
                domain="vpc",
                tags={"Name": f"{config.name}-nat-eip"},
                opts=opts,
            )
            nat_gateway = aws.ec2.NatGateway(
                f"{config.name}-nat",
                allocation_id=eip.id,
                subnet_id=public_subnets[0].id,
                tags={"Name": f"{config.name}-nat"},
                opts=opts,
            )
            private_route_table_routes.append(aws.ec2.RouteTableRouteArgs(cidr_block="0.0.0.0/0", nat_gateway_id=nat_gateway.id))

        private_route_table = aws.ec2.RouteTable(
            f"{config.name}-private-rt",
            vpc_id=vpc.id,
            routes=private_route_table_routes,
            tags={"Name": f"{config.name}-private-rt"},
            opts=opts,
        )
        private_subnets = []
        for index, cidr in enumerate(private_subnet_cidrs):
            subnet = aws.ec2.Subnet(
                f"{config.name}-private-{index + 1}",
                vpc_id=vpc.id,
                cidr_block=cidr,
                availability_zone=availability_zones[index],
                map_public_ip_on_launch=False,
                tags={"Name": f"{config.name}-private-{index + 1}"},
                opts=opts,
            )
            aws.ec2.RouteTableAssociation(
                f"{config.name}-private-{index + 1}-rt",
                subnet_id=subnet.id,
                route_table_id=private_route_table.id,
                opts=opts,
            )
            private_subnets.append(subnet)
        service_subnets = private_subnets

    return {
        "vpc_id": vpc.id,
        "public_subnet_ids": [subnet.id for subnet in public_subnets],
        "service_subnet_ids": [subnet.id for subnet in service_subnets],
    }


def _create_security_groups(
    config: CerebroRuntimeConfig,
    vpc_id: pulumi.Input[str],
    opts: pulumi.ResourceOptions,
) -> tuple[aws.ec2.SecurityGroup, aws.ec2.SecurityGroup]:
    alb_ingress = []
    if config.aws_certificate_arn:
        alb_ingress.append(
            aws.ec2.SecurityGroupIngressArgs(
                protocol="tcp",
                from_port=443,
                to_port=443,
                cidr_blocks=config.ingress_cidrs,
            )
        )
    if not config.aws_certificate_arn or config.aws_redirect_http_to_https:
        alb_ingress.append(
            aws.ec2.SecurityGroupIngressArgs(
                protocol="tcp",
                from_port=80,
                to_port=80,
                cidr_blocks=config.ingress_cidrs,
            )
        )

    alb_sg = aws.ec2.SecurityGroup(
        f"{config.name}-alb-sg",
        vpc_id=vpc_id,
        description="Cerebro ALB ingress",
        ingress=alb_ingress,
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
        vpc_id=vpc_id,
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
    return alb_sg, app_sg


def _create_listeners(
    config: CerebroRuntimeConfig,
    load_balancer_arn: pulumi.Input[str],
    target_group_arn: pulumi.Input[str],
    opts: pulumi.ResourceOptions,
) -> list[pulumi.Resource]:
    listeners: list[pulumi.Resource] = []
    if config.aws_certificate_arn:
        https_listener = aws.lb.Listener(
            f"{config.name}-https",
            load_balancer_arn=load_balancer_arn,
            port=443,
            protocol="HTTPS",
            certificate_arn=config.aws_certificate_arn,
            ssl_policy="ELBSecurityPolicy-TLS13-1-2-2021-06",
            default_actions=[
                aws.lb.ListenerDefaultActionArgs(
                    type="forward",
                    target_group_arn=target_group_arn,
                )
            ],
            opts=opts,
        )
        listeners.append(https_listener)
        if config.aws_redirect_http_to_https:
            listeners.append(
                aws.lb.Listener(
                    f"{config.name}-http-redirect",
                    load_balancer_arn=load_balancer_arn,
                    port=80,
                    protocol="HTTP",
                    default_actions=[
                        aws.lb.ListenerDefaultActionArgs(
                            type="redirect",
                            redirect=aws.lb.ListenerDefaultActionRedirectArgs(
                                port="443",
                                protocol="HTTPS",
                                status_code="HTTP_301",
                            ),
                        )
                    ],
                    opts=opts,
                )
            )
        return listeners

    listeners.append(
        aws.lb.Listener(
            f"{config.name}-http",
            load_balancer_arn=load_balancer_arn,
            port=80,
            protocol="HTTP",
            default_actions=[
                aws.lb.ListenerDefaultActionArgs(
                    type="forward",
                    target_group_arn=target_group_arn,
                )
            ],
            opts=opts,
        )
    )
    return listeners


def _create_secrets(name: str, secrets: list[SecretEnv], opts: pulumi.ResourceOptions) -> list[dict[str, pulumi.Input[str]]]:
    refs = []
    for secret in secrets:
        resource_name = f"{name}-{normalized_secret_name(secret.name)}"
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


def _existing_aws_secret_refs(secrets: list[ExistingSecretRef]) -> list[dict[str, pulumi.Input[str]]]:
    refs = []
    for secret in secrets:
        if not secret.aws_arn:
            raise ValueError(f"cerebro:existingSecretRefs.{secret.name}.awsArn is required for AWS")
        refs.append({"name": secret.name, "arn": secret.aws_arn})
    return refs


def _create_schedules(
    config: CerebroRuntimeConfig,
    cluster_arn: pulumi.Input[str],
    task_definition_arn: pulumi.Input[str],
    execution_role_arn: pulumi.Input[str],
    task_role_arn: pulumi.Input[str],
    subnet_ids: list[pulumi.Input[str]],
    security_group_ids: list[pulumi.Input[str]],
    opts: pulumi.ResourceOptions,
) -> list[pulumi.Input[str]]:
    if not config.scheduled_jobs:
        return []

    schedule_role = aws.iam.Role(
        f"{config.name}-scheduler-role",
        name=_aws_name(config.name, "scheduler-role", 64),
        assume_role_policy=_assume_role_policy("scheduler.amazonaws.com"),
        opts=opts,
    )
    run_task_policy = aws.iam.RolePolicy(
        f"{config.name}-scheduler-run-task",
        role=schedule_role.id,
        policy=pulumi.Output.json_dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["ecs:RunTask"],
                        "Resource": task_definition_arn,
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["iam:PassRole"],
                        "Resource": [execution_role_arn, task_role_arn],
                    },
                ],
            }
        ),
        opts=opts,
    )
    schedule_opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(depends_on=[run_task_policy]))

    schedules = []
    for job in config.scheduled_jobs:
        schedule = aws.scheduler.Schedule(
            f"{config.name}-{job.name}-schedule",
            name=_aws_name(config.name, f"{job.name}-schedule", 64),
            description=job.description or f"Cerebro scheduled job {job.name}",
            schedule_expression=job.schedule,
            schedule_expression_timezone=job.time_zone,
            state="ENABLED" if job.enabled else "DISABLED",
            flexible_time_window=aws.scheduler.ScheduleFlexibleTimeWindowArgs(mode="OFF"),
            target=aws.scheduler.ScheduleTargetArgs(
                arn=cluster_arn,
                role_arn=schedule_role.arn,
                input=_ecs_schedule_input(job),
                ecs_parameters=aws.scheduler.ScheduleTargetEcsParametersArgs(
                    task_definition_arn=task_definition_arn,
                    launch_type="FARGATE",
                    task_count=1,
                    network_configuration=aws.scheduler.ScheduleTargetEcsParametersNetworkConfigurationArgs(
                        subnets=subnet_ids,
                        security_groups=security_group_ids,
                        assign_public_ip=config.aws_assign_public_ip if not config.aws_enable_private_subnets else False,
                    ),
                ),
            ),
            opts=schedule_opts,
        )
        schedules.append(schedule.name)
    return schedules


def _ecs_schedule_input(job: ScheduledJob) -> pulumi.Output[str]:
    return pulumi.Output.json_dumps({"containerOverrides": [{"name": "cerebro", "command": job.command}]})


def _assume_role_policy(service_principal: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": service_principal},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


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
