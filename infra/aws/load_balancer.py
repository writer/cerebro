"""
AWS Application Load Balancer.
"""

import pulumi
import pulumi_aws as aws


def create_alb(
    name: str,
    vpc_id: pulumi.Output[str],
    subnet_ids: list[pulumi.Output[str]],
    security_group_id: pulumi.Output[str],
    certificate_domain: str = None,
    internal: bool = True,
    health_check_path: str = "/health",
    container_port: int = 8080,
) -> dict:
    """
    Create Application Load Balancer.

    Args:
        name: ALB name prefix
        vpc_id: VPC ID
        subnet_ids: Subnet IDs for ALB
        security_group_id: Security group ID
        certificate_domain: Domain for ACM certificate (optional)
        internal: Deploy as internal ALB
        health_check_path: Health check endpoint
        container_port: Container port for target group
    """
    alb = aws.lb.LoadBalancer(
        f"{name}-alb",
        name=f"{name}-alb",
        internal=internal,
        load_balancer_type="application",
        security_groups=[security_group_id],
        subnets=subnet_ids,
        enable_deletion_protection=False,
        tags={"Name": f"{name}-alb"},
    )

    target_group = aws.lb.TargetGroup(
        f"{name}-tg",
        name=f"{name}-tg",
        port=container_port,
        protocol="HTTP",
        vpc_id=vpc_id,
        target_type="ip",
        health_check=aws.lb.TargetGroupHealthCheckArgs(
            enabled=True,
            healthy_threshold=2,
            interval=30,
            matcher="200",
            path=health_check_path,
            port="traffic-port",
            protocol="HTTP",
            timeout=5,
            unhealthy_threshold=3,
        ),
        tags={"Name": f"{name}-tg"},
    )

    # HTTPS listener if certificate provided
    if certificate_domain:
        cert = aws.acm.get_certificate(
            domain=certificate_domain,
            statuses=["ISSUED"],
        )
        listener = aws.lb.Listener(
            f"{name}-https-listener",
            load_balancer_arn=alb.arn,
            port=443,
            protocol="HTTPS",
            ssl_policy="ELBSecurityPolicy-TLS13-1-2-2021-06",
            certificate_arn=cert.arn,
            default_actions=[
                aws.lb.ListenerDefaultActionArgs(
                    type="forward",
                    target_group_arn=target_group.arn,
                )
            ],
        )

        # HTTP to HTTPS redirect
        aws.lb.Listener(
            f"{name}-http-redirect",
            load_balancer_arn=alb.arn,
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
        )
    else:
        # HTTP only
        listener = aws.lb.Listener(
            f"{name}-http-listener",
            load_balancer_arn=alb.arn,
            port=80,
            protocol="HTTP",
            default_actions=[
                aws.lb.ListenerDefaultActionArgs(
                    type="forward",
                    target_group_arn=target_group.arn,
                )
            ],
        )

    return {
        "alb": alb,
        "target_group": target_group,
        "listener": listener,
    }
