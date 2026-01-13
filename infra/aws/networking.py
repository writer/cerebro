"""
AWS VPC and networking infrastructure.
"""

import pulumi
import pulumi_aws as aws


def create_vpc(
    name: str,
    cidr_block: str = "10.0.0.0/16",
    availability_zones: int = 2,
    enable_nat_gateway: bool = True,
    alb_ingress_cidrs: list[str] = None,
) -> dict:
    """
    Create VPC with public and private subnets.

    Args:
        name: VPC name prefix
        cidr_block: VPC CIDR block
        availability_zones: Number of AZs to use
        enable_nat_gateway: Enable NAT gateway for private subnets
        alb_ingress_cidrs: CIDRs allowed to access ALB (None = 0.0.0.0/0)
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

    # NAT Gateway (one per AZ for HA, or single for cost savings)
    nat_gateways = []
    if enable_nat_gateway:
        for i, public_subnet in enumerate(public_subnets[:1]):  # Single NAT for cost
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

    # Private route tables
    for i, subnet in enumerate(private_subnets):
        routes = []
        if nat_gateways:
            routes.append(
                aws.ec2.RouteTableRouteArgs(
                    cidr_block="0.0.0.0/0",
                    nat_gateway_id=nat_gateways[0].id,  # Use single NAT
                )
            )

        rt = aws.ec2.RouteTable(
            f"{name}-private-rt-{i}",
            vpc_id=vpc.id,
            routes=routes,
            tags={"Name": f"{name}-private-rt-{i}"},
        )
        aws.ec2.RouteTableAssociation(
            f"{name}-private-rta-{i}",
            subnet_id=subnet.id,
            route_table_id=rt.id,
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
        "alb_security_group_id": alb_sg.id,
        "app_security_group_id": app_sg.id,
    }
