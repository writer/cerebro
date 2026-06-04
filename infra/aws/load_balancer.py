"""
AWS Application Load Balancer.
"""

import json

import pulumi
import pulumi_aws as aws


def create_alb(
    name: str,
    vpc_id: pulumi.Output[str],
    subnet_ids: list[pulumi.Output[str]],
    security_group_id: pulumi.Output[str],
    certificate_domain: str = None,
    certificate_arn: pulumi.Input[str] = None,
    internal: bool = True,
    health_check_path: str = "/health",
    container_port: int = 8080,
    enable_deletion_protection: bool = False,
    enable_access_logs: bool = False,
    access_logs_retention_days: int = 90,
    idle_timeout_seconds: int = 300,
    allowed_hostnames: list[str] = None,
    oidc_auth: dict = None,
) -> dict:
    """
    Create Application Load Balancer.

    Args:
        name: ALB name prefix
        vpc_id: VPC ID
        subnet_ids: Subnet IDs for ALB
        security_group_id: Security group ID
        certificate_domain: Domain for ACM certificate (optional)
        certificate_arn: ACM certificate ARN to attach (optional)
        internal: Deploy as internal ALB
        health_check_path: Health check endpoint
        container_port: Container port for target group
        enable_deletion_protection: Prevent accidental ALB deletion
        enable_access_logs: Enable ALB access logs to S3
        access_logs_retention_days: Days to retain access logs
        idle_timeout_seconds: ALB idle timeout for long-lived HTTP/SSE streams
        allowed_hostnames: Host headers allowed to reach the target group
        oidc_auth: Optional ALB OIDC authentication settings
    """
    def oidc_default_action(order: int):
        return aws.lb.ListenerDefaultActionArgs(
            type="authenticate-oidc",
            order=order,
            authenticate_oidc=aws.lb.ListenerDefaultActionAuthenticateOidcArgs(
                authorization_endpoint=oidc_auth["authorization_endpoint"],
                client_id=oidc_auth["client_id"],
                client_secret=oidc_auth["client_secret"],
                issuer=oidc_auth["issuer"],
                token_endpoint=oidc_auth["token_endpoint"],
                user_info_endpoint=oidc_auth["user_info_endpoint"],
                on_unauthenticated_request=oidc_auth.get("on_unauthenticated_request", "authenticate"),
                scope=oidc_auth.get("scope", "openid profile email"),
                session_cookie_name=oidc_auth.get("session_cookie_name"),
                session_timeout=oidc_auth.get("session_timeout"),
            ),
        )

    def oidc_rule_action(order: int):
        return aws.lb.ListenerRuleActionArgs(
            type="authenticate-oidc",
            order=order,
            authenticate_oidc=aws.lb.ListenerRuleActionAuthenticateOidcArgs(
                authorization_endpoint=oidc_auth["authorization_endpoint"],
                client_id=oidc_auth["client_id"],
                client_secret=oidc_auth["client_secret"],
                issuer=oidc_auth["issuer"],
                token_endpoint=oidc_auth["token_endpoint"],
                user_info_endpoint=oidc_auth["user_info_endpoint"],
                on_unauthenticated_request=oidc_auth.get("on_unauthenticated_request", "authenticate"),
                scope=oidc_auth.get("scope", "openid profile email"),
                session_cookie_name=oidc_auth.get("session_cookie_name"),
                session_timeout=oidc_auth.get("session_timeout"),
            ),
        )

    def default_forward_actions():
        actions = []
        if oidc_auth:
            actions.append(oidc_default_action(1))
        actions.append(
            aws.lb.ListenerDefaultActionArgs(
                type="forward",
                target_group_arn=target_group.arn,
                order=2 if oidc_auth else None,
            )
        )
        return actions

    def rule_forward_actions():
        actions = []
        if oidc_auth:
            actions.append(oidc_rule_action(1))
        actions.append(
            aws.lb.ListenerRuleActionArgs(
                type="forward",
                target_group_arn=target_group.arn,
                order=2 if oidc_auth else None,
            )
        )
        return actions

    def fixed_response_default_actions():
        return [
            aws.lb.ListenerDefaultActionArgs(
                type="fixed-response",
                fixed_response=aws.lb.ListenerDefaultActionFixedResponseArgs(
                    content_type="text/plain",
                    message_body="host not allowed",
                    status_code="404",
                ),
            )
        ]

    # Create ALB access logs bucket if enabled
    access_logs_bucket = None
    access_logs_bucket_policy = None
    if enable_access_logs:
        caller = aws.get_caller_identity()
        region = aws.get_region()

        access_logs_bucket = aws.s3.Bucket(
            f"{name}-alb-logs",
            bucket=f"writer-{name}-alb-access-logs",
            force_destroy=False,
            tags={"Name": f"writer-{name}-alb-access-logs"},
        )

        aws.s3.BucketPublicAccessBlock(
            f"{name}-alb-logs-public-access",
            bucket=access_logs_bucket.id,
            block_public_acls=True,
            block_public_policy=True,
            ignore_public_acls=True,
            restrict_public_buckets=True,
        )

        # ALB access logs bucket policy
        access_logs_bucket_policy = aws.s3.BucketPolicy(
            f"{name}-alb-logs-policy",
            bucket=access_logs_bucket.id,
            policy=access_logs_bucket.arn.apply(
                lambda bucket_arn: json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AWSLogDeliveryWrite",
                            "Effect": "Allow",
                            "Principal": {
                                "Service": "logdelivery.elasticloadbalancing.amazonaws.com",
                            },
                            "Action": "s3:PutObject",
                            "Resource": f"{bucket_arn}/{name}/AWSLogs/{caller.account_id}/*",
                            "Condition": {
                                "StringEquals": {
                                    "aws:SourceAccount": caller.account_id,
                                },
                                "ArnLike": {
                                    "aws:SourceArn": f"arn:aws:elasticloadbalancing:{region.region}:{caller.account_id}:loadbalancer/*",
                                },
                            },
                        },
                        {
                            "Sid": "AWSLogDeliveryAclCheck",
                            "Effect": "Allow",
                            "Principal": {
                                "Service": "logdelivery.elasticloadbalancing.amazonaws.com",
                            },
                            "Action": "s3:GetBucketAcl",
                            "Resource": bucket_arn,
                            "Condition": {
                                "StringEquals": {
                                    "aws:SourceAccount": caller.account_id,
                                },
                                "ArnLike": {
                                    "aws:SourceArn": f"arn:aws:elasticloadbalancing:{region.region}:{caller.account_id}:loadbalancer/*",
                                },
                            },
                        },
                        {
                            "Sid": "DenyInsecureTransport",
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:*",
                            "Resource": [bucket_arn, f"{bucket_arn}/*"],
                            "Condition": {
                                "Bool": {
                                    "aws:SecureTransport": "false",
                                },
                            },
                        },
                    ],
                })
            ),
        )

        # Lifecycle rule for log retention
        aws.s3.BucketLifecycleConfiguration(
            f"{name}-alb-logs-lifecycle",
            bucket=access_logs_bucket.id,
            rules=[
                aws.s3.BucketLifecycleConfigurationRuleArgs(
                    id="expire-old-logs",
                    status="Enabled",
                    expiration=aws.s3.BucketLifecycleConfigurationRuleExpirationArgs(
                        days=access_logs_retention_days,
                    ),
                ),
            ],
        )

    alb = aws.lb.LoadBalancer(
        f"{name}-alb",
        name=f"{name}-alb",
        internal=internal,
        load_balancer_type="application",
        security_groups=[security_group_id],
        subnets=subnet_ids,
        enable_deletion_protection=enable_deletion_protection,
        enable_http2=True,
        idle_timeout=idle_timeout_seconds,
        drop_invalid_header_fields=True,
        access_logs=(
            aws.lb.LoadBalancerAccessLogsArgs(
                bucket=access_logs_bucket.bucket,
                prefix=name,
                enabled=True,
            )
            if enable_access_logs and access_logs_bucket
            else None
        ),
        tags={"Name": f"{name}-alb"},
        opts=pulumi.ResourceOptions(depends_on=[access_logs_bucket_policy]) if access_logs_bucket_policy else None,
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
            matcher="200-299",
            path=health_check_path,
            port="traffic-port",
            protocol="HTTP",
            timeout=5,
            unhealthy_threshold=3,
        ),
        tags={"Name": f"{name}-tg"},
    )

    # HTTPS listener if certificate provided
    if certificate_domain or certificate_arn:
        listener_certificate_arn = certificate_arn
        if not listener_certificate_arn:
            cert = aws.acm.get_certificate(
                domain=certificate_domain,
                statuses=["ISSUED"],
            )
            listener_certificate_arn = cert.arn

        listener = aws.lb.Listener(
            f"{name}-https-listener",
            load_balancer_arn=alb.arn,
            port=443,
            protocol="HTTPS",
            ssl_policy="ELBSecurityPolicy-TLS13-1-2-2021-06",
            certificate_arn=listener_certificate_arn,
            default_actions=fixed_response_default_actions() if allowed_hostnames else default_forward_actions(),
        )

        listener_rule = None
        if allowed_hostnames:
            listener_rule = aws.lb.ListenerRule(
                f"{name}-host-forward-rule",
                listener_arn=listener.arn,
                priority=100,
                conditions=[
                    aws.lb.ListenerRuleConditionArgs(
                        host_header=aws.lb.ListenerRuleConditionHostHeaderArgs(
                            values=allowed_hostnames,
                        ),
                    )
                ],
                actions=rule_forward_actions(),
            )

        # HTTP to HTTPS redirect
        aws.lb.Listener(
            f"{name}-http-listener",
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
            default_actions=fixed_response_default_actions() if allowed_hostnames else default_forward_actions(),
        )
        listener_rule = None
        if allowed_hostnames:
            listener_rule = aws.lb.ListenerRule(
                f"{name}-host-forward-rule",
                listener_arn=listener.arn,
                priority=100,
                conditions=[
                    aws.lb.ListenerRuleConditionArgs(
                        host_header=aws.lb.ListenerRuleConditionHostHeaderArgs(
                            values=allowed_hostnames,
                        ),
                    )
                ],
                actions=rule_forward_actions(),
            )

    return {
        "alb": alb,
        "target_group": target_group,
        "listener": listener,
        "listener_rule": listener_rule,
    }
