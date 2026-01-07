"""
AWS CodeDeploy Blue-Green Deployment module for Cerebro.

Provides zero-downtime deployments with automatic rollback.
"""

import pulumi
import pulumi_aws as aws


def create_blue_green_deployment(
    name: str,
    cluster_name: pulumi.Input[str],
    service_name: pulumi.Input[str],
    listener_arn: pulumi.Input[str],
    target_group_names: tuple[pulumi.Input[str], pulumi.Input[str]],
    termination_wait_time_minutes: int = 5,
    tags: dict[str, str] | None = None,
) -> dict[str, pulumi.Output]:
    """
    Create CodeDeploy resources for ECS blue-green deployments.

    Args:
        name: Resource name prefix
        cluster_name: ECS cluster name
        service_name: ECS service name
        listener_arn: ALB listener ARN
        target_group_names: Tuple of (blue, green) target group names
        termination_wait_time_minutes: Minutes to wait before terminating blue
        tags: Resource tags

    Returns:
        Dictionary containing CodeDeploy resources
    """
    resource_tags = tags or {}

    # IAM role for CodeDeploy
    codedeploy_role = aws.iam.Role(
        f"{name}-codedeploy-role",
        name=f"{name}-codedeploy-role",
        assume_role_policy=pulumi.Output.from_input(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "codedeploy.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ).apply(lambda p: pulumi.Output.json_dumps(p)),
        tags=resource_tags,
    )

    # Attach CodeDeploy ECS policy
    aws.iam.RolePolicyAttachment(
        f"{name}-codedeploy-policy",
        role=codedeploy_role.name,
        policy_arn="arn:aws:iam::aws:policy/AWSCodeDeployRoleForECS",
    )

    # CodeDeploy Application
    application = aws.codedeploy.Application(
        f"{name}-codedeploy-app",
        name=name,
        compute_platform="ECS",
        tags=resource_tags,
    )

    # CodeDeploy Deployment Group
    deployment_group = aws.codedeploy.DeploymentGroup(
        f"{name}-deployment-group",
        app_name=application.name,
        deployment_group_name=f"{name}-dg",
        service_role_arn=codedeploy_role.arn,
        deployment_config_name="CodeDeployDefault.ECSLinear10PercentEvery1Minutes",
        ecs_service=aws.codedeploy.DeploymentGroupEcsServiceArgs(
            cluster_name=cluster_name,
            service_name=service_name,
        ),
        deployment_style=aws.codedeploy.DeploymentGroupDeploymentStyleArgs(
            deployment_option="WITH_TRAFFIC_CONTROL",
            deployment_type="BLUE_GREEN",
        ),
        blue_green_deployment_config=aws.codedeploy.DeploymentGroupBlueGreenDeploymentConfigArgs(
            deployment_ready_option=aws.codedeploy.DeploymentGroupBlueGreenDeploymentConfigDeploymentReadyOptionArgs(
                action_on_timeout="CONTINUE_DEPLOYMENT",
                wait_time_in_minutes=0,
            ),
            terminate_blue_instances_on_deployment_success=aws.codedeploy.DeploymentGroupBlueGreenDeploymentConfigTerminateBlueInstancesOnDeploymentSuccessArgs(
                action="TERMINATE",
                termination_wait_time_in_minutes=termination_wait_time_minutes,
            ),
        ),
        load_balancer_info=aws.codedeploy.DeploymentGroupLoadBalancerInfoArgs(
            target_group_pair_info=aws.codedeploy.DeploymentGroupLoadBalancerInfoTargetGroupPairInfoArgs(
                prod_traffic_route=aws.codedeploy.DeploymentGroupLoadBalancerInfoTargetGroupPairInfoProdTrafficRouteArgs(
                    listener_arns=[listener_arn],
                ),
                target_groups=[
                    aws.codedeploy.DeploymentGroupLoadBalancerInfoTargetGroupPairInfoTargetGroupArgs(
                        name=target_group_names[0],
                    ),
                    aws.codedeploy.DeploymentGroupLoadBalancerInfoTargetGroupPairInfoTargetGroupArgs(
                        name=target_group_names[1],
                    ),
                ],
            ),
        ),
        auto_rollback_configuration=aws.codedeploy.DeploymentGroupAutoRollbackConfigurationArgs(
            enabled=True,
            events=["DEPLOYMENT_FAILURE", "DEPLOYMENT_STOP_ON_ALARM"],
        ),
        tags=resource_tags,
    )

    return {
        "application": application,
        "deployment_group": deployment_group,
        "codedeploy_role": codedeploy_role,
    }


def create_green_target_group(
    name: str,
    vpc_id: pulumi.Input[str],
    container_port: int,
    health_check_path: str = "/health",
    tags: dict[str, str] | None = None,
) -> aws.lb.TargetGroup:
    """
    Create a secondary (green) target group for blue-green deployments.

    Args:
        name: Resource name prefix
        vpc_id: VPC ID
        container_port: Container port for the target group
        health_check_path: Health check endpoint path
        tags: Resource tags

    Returns:
        Green target group resource
    """
    resource_tags = tags or {}

    return aws.lb.TargetGroup(
        f"{name}-tg-green",
        name=f"{name}-tg-green",
        port=container_port,
        protocol="HTTP",
        target_type="ip",
        vpc_id=vpc_id,
        health_check=aws.lb.TargetGroupHealthCheckArgs(
            enabled=True,
            path=health_check_path,
            port="traffic-port",
            protocol="HTTP",
            healthy_threshold=3,
            unhealthy_threshold=3,
            timeout=5,
            interval=30,
            matcher="200-299",
        ),
        tags={
            **resource_tags,
            "Name": f"{name}-tg-green",
        },
    )
