"""
AWS RDS Proxy module for Cerebro.

Provides connection pooling and IAM authentication for RDS/Aurora databases.
"""

import pulumi
import pulumi_aws as aws


def create_rds_proxy(
    name: str,
    vpc_id: pulumi.Input[str],
    subnet_ids: pulumi.Input[list[str]],
    security_group_id: pulumi.Input[str],
    db_cluster_identifier: pulumi.Input[str],
    cluster_resource_id: pulumi.Input[str],
    db_user: str,
    engine_family: str = "POSTGRESQL",
    max_connections_percent: int = 80,
    max_idle_connections_percent: int = 50,
    idle_client_timeout: int = 1800,
    tags: dict[str, str] | None = None,
) -> dict[str, pulumi.Output]:
    """
    Create an RDS Proxy with IAM authentication.

    Args:
        name: Resource name prefix
        vpc_id: VPC ID
        subnet_ids: List of subnet IDs for the proxy
        security_group_id: Security group ID for the proxy
        db_cluster_identifier: Aurora cluster identifier
        cluster_resource_id: Aurora cluster resource ID (for IAM policy)
        db_user: Database user for IAM authentication
        engine_family: Database engine family (POSTGRESQL or MYSQL)
        max_connections_percent: Max percentage of connections to use
        max_idle_connections_percent: Max percentage of idle connections
        idle_client_timeout: Idle client timeout in seconds
        tags: Resource tags

    Returns:
        Dictionary containing RDS Proxy resources
    """
    resource_tags = tags or {}

    # Get AWS account ID and region
    caller_identity = aws.get_caller_identity()
    region = aws.get_region()

    # IAM role for RDS Proxy with rds-db:connect permission
    proxy_role = aws.iam.Role(
        f"{name}-proxy-role",
        name=f"{name}-rds-proxy-role",
        assume_role_policy=pulumi.Output.from_input(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "rds.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ).apply(lambda p: pulumi.Output.json_dumps(p)),
        tags=resource_tags,
    )

    # Grant rds-db:connect for IAM authentication
    proxy_policy = aws.iam.RolePolicy(
        f"{name}-proxy-policy",
        role=proxy_role.name,
        policy=pulumi.Output.all(
            account_id=caller_identity.account_id,
            region_name=region.name,
            resource_id=cluster_resource_id,
        ).apply(
            lambda args: pulumi.Output.json_dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["rds-db:connect"],
                            "Resource": [
                                f"arn:aws:rds-db:{args['region_name']}:{args['account_id']}:dbuser:{args['resource_id']}/{db_user}",
                            ],
                        }
                    ],
                }
            )
        ),
    )

    # RDS Proxy
    proxy = aws.rds.Proxy(
        f"{name}-proxy",
        name=f"{name}-proxy",
        engine_family=engine_family,
        role_arn=proxy_role.arn,
        vpc_subnet_ids=subnet_ids,
        vpc_security_group_ids=[security_group_id],
        require_tls=True,
        idle_client_timeout=idle_client_timeout,
        debug_logging=False,
        auths=[
            aws.rds.ProxyAuthArgs(
                auth_scheme="SECRETS",
                iam_auth="REQUIRED",
                description="IAM authentication",
            )
        ],
        tags={
            **resource_tags,
            "Name": f"{name}-proxy",
        },
    )

    # Default target group
    target_group = aws.rds.ProxyDefaultTargetGroup(
        f"{name}-proxy-tg",
        db_proxy_name=proxy.name,
        connection_pool_config=aws.rds.ProxyDefaultTargetGroupConnectionPoolConfigArgs(
            max_connections_percent=max_connections_percent,
            max_idle_connections_percent=max_idle_connections_percent,
            connection_borrow_timeout=120,
        ),
    )

    # Proxy target pointing to Aurora cluster
    target = aws.rds.ProxyTarget(
        f"{name}-proxy-target",
        db_proxy_name=proxy.name,
        target_group_name=target_group.name,
        db_cluster_identifier=db_cluster_identifier,
    )

    return {
        "proxy": proxy,
        "proxy_role": proxy_role,
        "proxy_policy": proxy_policy,
        "target_group": target_group,
        "target": target,
        "endpoint": proxy.endpoint,
    }
