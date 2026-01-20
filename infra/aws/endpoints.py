"""
VPC Endpoints for AWS services.

Provides private connectivity to AWS services without traversing the internet,
reducing NAT Gateway costs and improving security.
"""

import pulumi
import pulumi_aws as aws


def create_vpc_endpoints(
    name: str,
    vpc_id: pulumi.Output[str],
    private_subnet_ids: list[pulumi.Output[str]],
    route_table_ids: list[pulumi.Output[str]],
    fargate_security_group_id: pulumi.Output[str],
) -> dict:
    """
    Create VPC endpoints for AWS services.

    Args:
        name: Resource name prefix
        vpc_id: VPC ID
        private_subnet_ids: Private subnet IDs for interface endpoints
        route_table_ids: Route table IDs for gateway endpoints
        fargate_security_group_id: Security group for Fargate tasks (to restrict access)
    """
    region = aws.get_region().region

    # Security group for interface endpoints
    endpoint_sg = aws.ec2.SecurityGroup(
        f"{name}-endpoint-sg",
        vpc_id=vpc_id,
        description="Security group for VPC endpoints",
        ingress=[
            aws.ec2.SecurityGroupIngressArgs(
                protocol="tcp",
                from_port=443,
                to_port=443,
                security_groups=[fargate_security_group_id],
                description="HTTPS from Fargate tasks",
            ),
        ],
        egress=[
            aws.ec2.SecurityGroupEgressArgs(
                protocol="-1",
                from_port=0,
                to_port=0,
                cidr_blocks=["0.0.0.0/0"],
                description="Allow all outbound",
            ),
        ],
        tags={"Name": f"{name}-endpoint-sg"},
    )

    # S3 Gateway Endpoint (free)
    s3_endpoint = aws.ec2.VpcEndpoint(
        f"{name}-s3-endpoint",
        vpc_id=vpc_id,
        service_name=f"com.amazonaws.{region}.s3",
        vpc_endpoint_type="Gateway",
        route_table_ids=route_table_ids,
        tags={"Name": f"{name}-s3-endpoint"},
    )

    # DynamoDB Gateway Endpoint (free)
    dynamodb_endpoint = aws.ec2.VpcEndpoint(
        f"{name}-dynamodb-endpoint",
        vpc_id=vpc_id,
        service_name=f"com.amazonaws.{region}.dynamodb",
        vpc_endpoint_type="Gateway",
        route_table_ids=route_table_ids,
        tags={"Name": f"{name}-dynamodb-endpoint"},
    )

    # ECR API Endpoint (interface)
    ecr_api_endpoint = aws.ec2.VpcEndpoint(
        f"{name}-ecr-api-endpoint",
        vpc_id=vpc_id,
        service_name=f"com.amazonaws.{region}.ecr.api",
        vpc_endpoint_type="Interface",
        subnet_ids=private_subnet_ids,
        security_group_ids=[endpoint_sg.id],
        private_dns_enabled=True,
        tags={"Name": f"{name}-ecr-api-endpoint"},
    )

    # ECR DKR Endpoint (interface)
    ecr_dkr_endpoint = aws.ec2.VpcEndpoint(
        f"{name}-ecr-dkr-endpoint",
        vpc_id=vpc_id,
        service_name=f"com.amazonaws.{region}.ecr.dkr",
        vpc_endpoint_type="Interface",
        subnet_ids=private_subnet_ids,
        security_group_ids=[endpoint_sg.id],
        private_dns_enabled=True,
        tags={"Name": f"{name}-ecr-dkr-endpoint"},
    )

    # CloudWatch Logs Endpoint (interface)
    logs_endpoint = aws.ec2.VpcEndpoint(
        f"{name}-logs-endpoint",
        vpc_id=vpc_id,
        service_name=f"com.amazonaws.{region}.logs",
        vpc_endpoint_type="Interface",
        subnet_ids=private_subnet_ids,
        security_group_ids=[endpoint_sg.id],
        private_dns_enabled=True,
        tags={"Name": f"{name}-logs-endpoint"},
    )

    # Secrets Manager Endpoint (interface)
    secretsmanager_endpoint = aws.ec2.VpcEndpoint(
        f"{name}-secretsmanager-endpoint",
        vpc_id=vpc_id,
        service_name=f"com.amazonaws.{region}.secretsmanager",
        vpc_endpoint_type="Interface",
        subnet_ids=private_subnet_ids,
        security_group_ids=[endpoint_sg.id],
        private_dns_enabled=True,
        tags={"Name": f"{name}-secretsmanager-endpoint"},
    )

    # STS Endpoint (interface) - required for IAM authentication
    sts_endpoint = aws.ec2.VpcEndpoint(
        f"{name}-sts-endpoint",
        vpc_id=vpc_id,
        service_name=f"com.amazonaws.{region}.sts",
        vpc_endpoint_type="Interface",
        subnet_ids=private_subnet_ids,
        security_group_ids=[endpoint_sg.id],
        private_dns_enabled=True,
        tags={"Name": f"{name}-sts-endpoint"},
    )

    # KMS Endpoint (interface) - required for encryption operations
    kms_endpoint = aws.ec2.VpcEndpoint(
        f"{name}-kms-endpoint",
        vpc_id=vpc_id,
        service_name=f"com.amazonaws.{region}.kms",
        vpc_endpoint_type="Interface",
        subnet_ids=private_subnet_ids,
        security_group_ids=[endpoint_sg.id],
        private_dns_enabled=True,
        tags={"Name": f"{name}-kms-endpoint"},
    )

    # CloudWatch Metrics Endpoint (interface) - for monitoring
    monitoring_endpoint = aws.ec2.VpcEndpoint(
        f"{name}-monitoring-endpoint",
        vpc_id=vpc_id,
        service_name=f"com.amazonaws.{region}.monitoring",
        vpc_endpoint_type="Interface",
        subnet_ids=private_subnet_ids,
        security_group_ids=[endpoint_sg.id],
        private_dns_enabled=True,
        tags={"Name": f"{name}-monitoring-endpoint"},
    )

    # SQS Endpoint (interface) - for job queue
    sqs_endpoint = aws.ec2.VpcEndpoint(
        f"{name}-sqs-endpoint",
        vpc_id=vpc_id,
        service_name=f"com.amazonaws.{region}.sqs",
        vpc_endpoint_type="Interface",
        subnet_ids=private_subnet_ids,
        security_group_ids=[endpoint_sg.id],
        private_dns_enabled=True,
        tags={"Name": f"{name}-sqs-endpoint"},
    )

    # SSM Endpoints (interface) - for ECS Exec and parameter store
    ssm_endpoint = aws.ec2.VpcEndpoint(
        f"{name}-ssm-endpoint",
        vpc_id=vpc_id,
        service_name=f"com.amazonaws.{region}.ssm",
        vpc_endpoint_type="Interface",
        subnet_ids=private_subnet_ids,
        security_group_ids=[endpoint_sg.id],
        private_dns_enabled=True,
        tags={"Name": f"{name}-ssm-endpoint"},
    )

    ssm_messages_endpoint = aws.ec2.VpcEndpoint(
        f"{name}-ssmmessages-endpoint",
        vpc_id=vpc_id,
        service_name=f"com.amazonaws.{region}.ssmmessages",
        vpc_endpoint_type="Interface",
        subnet_ids=private_subnet_ids,
        security_group_ids=[endpoint_sg.id],
        private_dns_enabled=True,
        tags={"Name": f"{name}-ssmmessages-endpoint"},
    )

    ec2_messages_endpoint = aws.ec2.VpcEndpoint(
        f"{name}-ec2messages-endpoint",
        vpc_id=vpc_id,
        service_name=f"com.amazonaws.{region}.ec2messages",
        vpc_endpoint_type="Interface",
        subnet_ids=private_subnet_ids,
        security_group_ids=[endpoint_sg.id],
        private_dns_enabled=True,
        tags={"Name": f"{name}-ec2messages-endpoint"},
    )

    return {
        "endpoint_sg": endpoint_sg,
        "s3_endpoint": s3_endpoint,
        "dynamodb_endpoint": dynamodb_endpoint,
        "ecr_api_endpoint": ecr_api_endpoint,
        "ecr_dkr_endpoint": ecr_dkr_endpoint,
        "logs_endpoint": logs_endpoint,
        "secretsmanager_endpoint": secretsmanager_endpoint,
        "sts_endpoint": sts_endpoint,
        "kms_endpoint": kms_endpoint,
        "monitoring_endpoint": monitoring_endpoint,
        "sqs_endpoint": sqs_endpoint,
        "ssm_endpoint": ssm_endpoint,
        "ssm_messages_endpoint": ssm_messages_endpoint,
        "ec2_messages_endpoint": ec2_messages_endpoint,
    }
