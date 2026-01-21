"""
AWS VPC and networking infrastructure.
"""

import json

import pulumi
import pulumi_aws as aws


def create_vpc(
    name: str,
    cidr_block: str = "10.0.0.0/16",
    availability_zones: int = 2,
    enable_nat_gateway: bool = True,
    nat_gateway_per_az: bool = True,
    alb_ingress_cidrs: list[str] = None,
    enable_ssh_blocking_nacl: bool = True,
    enable_flow_logs: bool = True,
    flow_logs_retention_days: int = 30,
    flow_logs_kms_key_arn: pulumi.Output[str] = None,
) -> dict:
    """
    Create VPC with public and private subnets.

    Args:
        name: VPC name prefix
        cidr_block: VPC CIDR block
        availability_zones: Number of AZs to use
        enable_nat_gateway: Enable NAT gateway for private subnets
        nat_gateway_per_az: Create one NAT per AZ for HA (True) or single NAT for cost (False)
        alb_ingress_cidrs: CIDRs allowed to access ALB (None = 0.0.0.0/0)
        enable_ssh_blocking_nacl: Create custom NACL that blocks SSH (TCP/22)
        enable_flow_logs: Enable VPC Flow Logs to CloudWatch
        flow_logs_retention_days: Days to retain flow logs
        flow_logs_kms_key_arn: Optional KMS key ARN for flow logs encryption
    """
    # Get available AZs
    azs = aws.get_availability_zones(state="available")
    az_names = azs.names[:availability_zones]

    # Create VPC
    vpc = aws.ec2.Vpc(
        f"{name}-vpc",
        cidr_block=cidr_block,
        enable_dns_hostnames=True,
        enable_dns_support=True,
        tags={"Name": f"{name}-vpc"},
    )

    # Internet Gateway
    igw = aws.ec2.InternetGateway(
        f"{name}-igw",
        vpc_id=vpc.id,
        tags={"Name": f"{name}-igw"},
    )

    # Public subnets
    public_subnets = []
    for i, az in enumerate(az_names):
        subnet = aws.ec2.Subnet(
            f"{name}-public-{i}",
            vpc_id=vpc.id,
            cidr_block=f"10.0.{i}.0/24",
            availability_zone=az,
            map_public_ip_on_launch=True,
            tags={"Name": f"{name}-public-{i}"},
        )
        public_subnets.append(subnet)

    # Public route table
    public_rt = aws.ec2.RouteTable(
        f"{name}-public-rt",
        vpc_id=vpc.id,
        routes=[
            aws.ec2.RouteTableRouteArgs(
                cidr_block="0.0.0.0/0",
                gateway_id=igw.id,
            )
        ],
        tags={"Name": f"{name}-public-rt"},
    )

    for i, subnet in enumerate(public_subnets):
        aws.ec2.RouteTableAssociation(
            f"{name}-public-rta-{i}",
            subnet_id=subnet.id,
            route_table_id=public_rt.id,
        )

    # Private subnets
    private_subnets = []
    for i, az in enumerate(az_names):
        subnet = aws.ec2.Subnet(
            f"{name}-private-{i}",
            vpc_id=vpc.id,
            cidr_block=f"10.0.{i + 10}.0/24",
            availability_zone=az,
            tags={"Name": f"{name}-private-{i}"},
        )
        private_subnets.append(subnet)

    # NAT Gateway - one per AZ for HA, or single for cost savings
    nat_gateways = []
    private_route_tables = []
    if enable_nat_gateway:
        # Determine how many NATs to create
        nat_subnets = public_subnets if nat_gateway_per_az else public_subnets[:1]
        for i, public_subnet in enumerate(nat_subnets):
            eip = aws.ec2.Eip(
                f"{name}-nat-eip-{i}",
                domain="vpc",
                tags={"Name": f"{name}-nat-eip-{i}"},
            )
            nat = aws.ec2.NatGateway(
                f"{name}-nat-{i}",
                allocation_id=eip.id,
                subnet_id=public_subnet.id,
                tags={"Name": f"{name}-nat-{i}"},
            )
            nat_gateways.append(nat)

    # Private route tables - each routes to its same-AZ NAT (or single NAT if not per-AZ)
    for i, subnet in enumerate(private_subnets):
        routes = []
        if nat_gateways:
            # Use same-AZ NAT if available, otherwise fall back to first NAT
            nat_index = i if nat_gateway_per_az and i < len(nat_gateways) else 0
            routes.append(
                aws.ec2.RouteTableRouteArgs(
                    cidr_block="0.0.0.0/0",
                    nat_gateway_id=nat_gateways[nat_index].id,
                )
            )

        rt = aws.ec2.RouteTable(
            f"{name}-private-rt-{i}",
            vpc_id=vpc.id,
            routes=routes,
            tags={"Name": f"{name}-private-rt-{i}"},
        )
        private_route_tables.append(rt)
        aws.ec2.RouteTableAssociation(
            f"{name}-private-rta-{i}",
            subnet_id=subnet.id,
            route_table_id=rt.id,
        )

    # Custom NACL that blocks SSH (TCP/22) for security compliance
    nacl = None
    if enable_ssh_blocking_nacl:
        nacl = aws.ec2.NetworkAcl(
            f"{name}-nacl",
            vpc_id=vpc.id,
            tags={"Name": f"{name}-nacl-no-ssh"},
        )

        # Ingress rules - allow all traffic EXCEPT TCP/22 (SSH)
        aws.ec2.NetworkAclRule(
            f"{name}-nacl-ingress-tcp-0-21",
            network_acl_id=nacl.id,
            rule_number=100,
            egress=False,
            protocol="tcp",
            rule_action="allow",
            cidr_block="0.0.0.0/0",
            from_port=0,
            to_port=21,
        )

        aws.ec2.NetworkAclRule(
            f"{name}-nacl-ingress-tcp-23-65535",
            network_acl_id=nacl.id,
            rule_number=110,
            egress=False,
            protocol="tcp",
            rule_action="allow",
            cidr_block="0.0.0.0/0",
            from_port=23,
            to_port=65535,
        )

        aws.ec2.NetworkAclRule(
            f"{name}-nacl-ingress-udp",
            network_acl_id=nacl.id,
            rule_number=120,
            egress=False,
            protocol="udp",
            rule_action="allow",
            cidr_block="0.0.0.0/0",
            from_port=0,
            to_port=65535,
        )

        aws.ec2.NetworkAclRule(
            f"{name}-nacl-ingress-icmp",
            network_acl_id=nacl.id,
            rule_number=130,
            egress=False,
            protocol="icmp",
            rule_action="allow",
            cidr_block="0.0.0.0/0",
            icmp_type=-1,
            icmp_code=-1,
        )

        # Egress rules - also block outbound SSH
        aws.ec2.NetworkAclRule(
            f"{name}-nacl-egress-tcp-0-21",
            network_acl_id=nacl.id,
            rule_number=100,
            egress=True,
            protocol="tcp",
            rule_action="allow",
            cidr_block="0.0.0.0/0",
            from_port=0,
            to_port=21,
        )

        aws.ec2.NetworkAclRule(
            f"{name}-nacl-egress-tcp-23-65535",
            network_acl_id=nacl.id,
            rule_number=110,
            egress=True,
            protocol="tcp",
            rule_action="allow",
            cidr_block="0.0.0.0/0",
            from_port=23,
            to_port=65535,
        )

        aws.ec2.NetworkAclRule(
            f"{name}-nacl-egress-udp",
            network_acl_id=nacl.id,
            rule_number=120,
            egress=True,
            protocol="udp",
            rule_action="allow",
            cidr_block="0.0.0.0/0",
            from_port=0,
            to_port=65535,
        )

        aws.ec2.NetworkAclRule(
            f"{name}-nacl-egress-icmp",
            network_acl_id=nacl.id,
            rule_number=130,
            egress=True,
            protocol="icmp",
            rule_action="allow",
            cidr_block="0.0.0.0/0",
            icmp_type=-1,
            icmp_code=-1,
        )

        # Associate NACL with all subnets
        for i, subnet in enumerate(public_subnets):
            aws.ec2.NetworkAclAssociation(
                f"{name}-nacl-assoc-public-{i}",
                network_acl_id=nacl.id,
                subnet_id=subnet.id,
                opts=pulumi.ResourceOptions(depends_on=[nacl]),
            )

        for i, subnet in enumerate(private_subnets):
            aws.ec2.NetworkAclAssociation(
                f"{name}-nacl-assoc-private-{i}",
                network_acl_id=nacl.id,
                subnet_id=subnet.id,
                opts=pulumi.ResourceOptions(depends_on=[nacl]),
            )

    # VPC Flow Logs
    flow_log = None
    flow_log_group = None
    if enable_flow_logs:
        # IAM role for VPC Flow Logs
        flow_logs_role = aws.iam.Role(
            f"{name}-flow-logs-role",
            assume_role_policy=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }],
            }),
            tags={"Name": f"{name}-flow-logs-role"},
        )

        # IAM policy for writing to CloudWatch Logs
        aws.iam.RolePolicy(
            f"{name}-flow-logs-policy",
            role=flow_logs_role.name,
            policy=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                        "logs:DescribeLogGroups",
                        "logs:DescribeLogStreams",
                    ],
                    "Resource": "*",
                }],
            }),
        )

        # CloudWatch Log Group for flow logs
        flow_log_group = aws.cloudwatch.LogGroup(
            f"{name}-flow-logs",
            name=f"/vpc/{name}/flow-logs",
            retention_in_days=flow_logs_retention_days,
            kms_key_id=flow_logs_kms_key_arn,
            tags={"Name": f"{name}-flow-logs"},
        )

        # VPC Flow Log
        flow_log = aws.ec2.FlowLog(
            f"{name}-flow-log",
            vpc_id=vpc.id,
            traffic_type="ALL",
            log_destination_type="cloud-watch-logs",
            log_destination=flow_log_group.arn,
            iam_role_arn=flow_logs_role.arn,
            tags={"Name": f"{name}-flow-log"},
        )

    # Security Groups
    alb_sg = aws.ec2.SecurityGroup(
        f"{name}-alb-sg",
        vpc_id=vpc.id,
        description="ALB security group",
        ingress=[
            aws.ec2.SecurityGroupIngressArgs(
                protocol="tcp",
                from_port=80,
                to_port=80,
                cidr_blocks=alb_ingress_cidrs or ["0.0.0.0/0"],
            ),
            aws.ec2.SecurityGroupIngressArgs(
                protocol="tcp",
                from_port=443,
                to_port=443,
                cidr_blocks=alb_ingress_cidrs or ["0.0.0.0/0"],
            ),
        ],
        egress=[
            aws.ec2.SecurityGroupEgressArgs(
                protocol="-1",
                from_port=0,
                to_port=0,
                cidr_blocks=["0.0.0.0/0"],
            )
        ],
        tags={"Name": f"{name}-alb-sg"},
    )

    app_sg = aws.ec2.SecurityGroup(
        f"{name}-app-sg",
        vpc_id=vpc.id,
        description="Application security group",
        ingress=[
            aws.ec2.SecurityGroupIngressArgs(
                protocol="tcp",
                from_port=8080,
                to_port=8080,
                security_groups=[alb_sg.id],
            ),
        ],
        egress=[
            aws.ec2.SecurityGroupEgressArgs(
                protocol="-1",
                from_port=0,
                to_port=0,
                cidr_blocks=["0.0.0.0/0"],
            )
        ],
        tags={"Name": f"{name}-app-sg"},
    )

    return {
        "vpc_id": vpc.id,
        "public_subnet_ids": [s.id for s in public_subnets],
        "private_subnet_ids": [s.id for s in private_subnets],
        "private_subnet_cidrs": [s.cidr_block for s in private_subnets],
        "private_route_table_ids": [rt.id for rt in private_route_tables],
        "public_route_table_id": public_rt.id,
        "alb_security_group_id": alb_sg.id,
        "app_security_group_id": app_sg.id,
        "nacl": nacl,
        "flow_log": flow_log,
        "flow_log_group": flow_log_group,
    }
