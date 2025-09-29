"""
AWS VPC and networking infrastructure.

Creates:
- VPC with public and private subnets across multiple AZs
- Internet Gateway
- NAT Gateways (one per AZ)
- Route tables
- Security groups
"""
import pulumi
import pulumi_aws as aws
from typing import List


def create_vpc(
    name: str,
    cidr_block: str = "10.0.0.0/16",
    availability_zones: int = 2,
    enable_nat_gateway: bool = True,
    enable_vpn_gateway: bool = False,
) -> dict:
    """
    Create VPC with public and private subnets.

    Args:
        name: VPC name prefix
        cidr_block: VPC CIDR block
        availability_zones: Number of AZs to span
        enable_nat_gateway: Create NAT gateways for private subnets
        enable_vpn_gateway: Create VPN gateway

    Returns:
        Dictionary with VPC resources
    """
    # Get available AZs
    azs = aws.get_availability_zones(state="available")
    selected_azs = azs.names[:availability_zones]

    # Create VPC
    vpc = aws.ec2.Vpc(
        f"{name}-vpc",
        cidr_block=cidr_block,
        enable_dns_hostnames=True,
        enable_dns_support=True,
        tags={
            "Name": f"{name}-vpc",
            "Environment": name.split("-")[1] if "-" in name else "production",
        },
    )

    # Create Internet Gateway
    igw = aws.ec2.InternetGateway(
        f"{name}-igw",
        vpc_id=vpc.id,
        tags={"Name": f"{name}-igw"},
    )

    # Calculate subnet CIDRs
    # Public subnets: 10.0.0.0/24, 10.0.1.0/24, ...
    # Private subnets: 10.0.10.0/24, 10.0.11.0/24, ...
    # Database subnets: 10.0.20.0/24, 10.0.21.0/24, ...
    base_cidr = cidr_block.split("/")[0].rsplit(".", 1)[0]  # "10.0.0"

    # Create public subnets
    public_subnets = []
    for i, az in enumerate(selected_azs):
        subnet = aws.ec2.Subnet(
            f"{name}-public-subnet-{i+1}",
            vpc_id=vpc.id,
            cidr_block=f"{base_cidr}.{i}.0/24",
            availability_zone=az,
            map_public_ip_on_launch=True,
            tags={
                "Name": f"{name}-public-subnet-{i+1}",
                "Type": "public",
            },
        )
        public_subnets.append(subnet)

    # Create private subnets (for application tier)
    private_subnets = []
    for i, az in enumerate(selected_azs):
        subnet = aws.ec2.Subnet(
            f"{name}-private-subnet-{i+1}",
            vpc_id=vpc.id,
            cidr_block=f"{base_cidr}.{10 + i}.0/24",
            availability_zone=az,
            tags={
                "Name": f"{name}-private-subnet-{i+1}",
                "Type": "private",
            },
        )
        private_subnets.append(subnet)

    # Create database subnets (isolated tier)
    database_subnets = []
    for i, az in enumerate(selected_azs):
        subnet = aws.ec2.Subnet(
            f"{name}-database-subnet-{i+1}",
            vpc_id=vpc.id,
            cidr_block=f"{base_cidr}.{20 + i}.0/24",
            availability_zone=az,
            tags={
                "Name": f"{name}-database-subnet-{i+1}",
                "Type": "database",
            },
        )
        database_subnets.append(subnet)

    # Create NAT Gateways (one per AZ for HA)
    nat_gateways = []
    if enable_nat_gateway:
        for i, subnet in enumerate(public_subnets):
            # Allocate Elastic IP
            eip = aws.ec2.Eip(
                f"{name}-nat-eip-{i+1}",
                vpc=True,
                tags={"Name": f"{name}-nat-eip-{i+1}"},
            )

            # Create NAT Gateway
            nat = aws.ec2.NatGateway(
                f"{name}-nat-{i+1}",
                subnet_id=subnet.id,
                allocation_id=eip.id,
                tags={"Name": f"{name}-nat-{i+1}"},
            )
            nat_gateways.append(nat)

    # Create route table for public subnets
    public_route_table = aws.ec2.RouteTable(
        f"{name}-public-rt",
        vpc_id=vpc.id,
        tags={"Name": f"{name}-public-rt"},
    )

    # Add route to Internet Gateway
    aws.ec2.Route(
        f"{name}-public-route",
        route_table_id=public_route_table.id,
        destination_cidr_block="0.0.0.0/0",
        gateway_id=igw.id,
    )

    # Associate public subnets with public route table
    for i, subnet in enumerate(public_subnets):
        aws.ec2.RouteTableAssociation(
            f"{name}-public-rta-{i+1}",
            subnet_id=subnet.id,
            route_table_id=public_route_table.id,
        )

    # Create route tables for private subnets (one per AZ)
    private_route_tables = []
    for i, subnet in enumerate(private_subnets):
        rt = aws.ec2.RouteTable(
            f"{name}-private-rt-{i+1}",
            vpc_id=vpc.id,
            tags={"Name": f"{name}-private-rt-{i+1}"},
        )
        private_route_tables.append(rt)

        # Add route to NAT Gateway
        if enable_nat_gateway and len(nat_gateways) > 0:
            aws.ec2.Route(
                f"{name}-private-route-{i+1}",
                route_table_id=rt.id,
                destination_cidr_block="0.0.0.0/0",
                nat_gateway_id=nat_gateways[i].id,
            )

        # Associate private subnet with route table
        aws.ec2.RouteTableAssociation(
            f"{name}-private-rta-{i+1}",
            subnet_id=subnet.id,
            route_table_id=rt.id,
        )

    # Create route table for database subnets (no internet access)
    database_route_table = aws.ec2.RouteTable(
        f"{name}-database-rt",
        vpc_id=vpc.id,
        tags={"Name": f"{name}-database-rt"},
    )

    # Associate database subnets
    for i, subnet in enumerate(database_subnets):
        aws.ec2.RouteTableAssociation(
            f"{name}-database-rta-{i+1}",
            subnet_id=subnet.id,
            route_table_id=database_route_table.id,
        )

    # Create security groups

    # ALB Security Group (public-facing)
    alb_sg = aws.ec2.SecurityGroup(
        f"{name}-alb-sg",
        vpc_id=vpc.id,
        description="Security group for Application Load Balancer",
        ingress=[
            aws.ec2.SecurityGroupIngressArgs(
                protocol="tcp",
                from_port=80,
                to_port=80,
                cidr_blocks=["0.0.0.0/0"],
                description="HTTP from internet",
            ),
            aws.ec2.SecurityGroupIngressArgs(
                protocol="tcp",
                from_port=443,
                to_port=443,
                cidr_blocks=["0.0.0.0/0"],
                description="HTTPS from internet",
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
        tags={"Name": f"{name}-alb-sg"},
    )

    # Application Security Group (ECS tasks)
    app_sg = aws.ec2.SecurityGroup(
        f"{name}-app-sg",
        vpc_id=vpc.id,
        description="Security group for application tier",
        tags={"Name": f"{name}-app-sg"},
    )

    # Allow traffic from ALB to app
    aws.ec2.SecurityGroupRule(
        f"{name}-app-from-alb-rule",
        type="ingress",
        security_group_id=app_sg.id,
        source_security_group_id=alb_sg.id,
        protocol="tcp",
        from_port=8000,
        to_port=8000,
        description="HTTP from ALB",
    )

    # Allow app to reach internet (for AWS API calls)
    aws.ec2.SecurityGroupRule(
        f"{name}-app-egress-rule",
        type="egress",
        security_group_id=app_sg.id,
        protocol="-1",
        from_port=0,
        to_port=0,
        cidr_blocks=["0.0.0.0/0"],
        description="Allow all outbound",
    )

    # Database Security Group
    db_sg = aws.ec2.SecurityGroup(
        f"{name}-db-sg",
        vpc_id=vpc.id,
        description="Security group for database tier",
        tags={"Name": f"{name}-db-sg"},
    )

    # Allow PostgreSQL from app tier
    aws.ec2.SecurityGroupRule(
        f"{name}-db-from-app-rule",
        type="ingress",
        security_group_id=db_sg.id,
        source_security_group_id=app_sg.id,
        protocol="tcp",
        from_port=5432,
        to_port=5432,
        description="PostgreSQL from app tier",
    )

    # Redis Security Group
    redis_sg = aws.ec2.SecurityGroup(
        f"{name}-redis-sg",
        vpc_id=vpc.id,
        description="Security group for Redis",
        tags={"Name": f"{name}-redis-sg"},
    )

    # Allow Redis from app tier
    aws.ec2.SecurityGroupRule(
        f"{name}-redis-from-app-rule",
        type="ingress",
        security_group_id=redis_sg.id,
        source_security_group_id=app_sg.id,
        protocol="tcp",
        from_port=6379,
        to_port=6379,
        description="Redis from app tier",
    )

    # VPN Gateway (optional)
    vpn_gateway = None
    if enable_vpn_gateway:
        vpn_gateway = aws.ec2.VpnGateway(
            f"{name}-vgw",
            vpc_id=vpc.id,
            tags={"Name": f"{name}-vgw"},
        )

    return {
        "vpc": vpc,
        "vpc_id": vpc.id,
        "public_subnets": public_subnets,
        "public_subnet_ids": [s.id for s in public_subnets],
        "private_subnets": private_subnets,
        "private_subnet_ids": [s.id for s in private_subnets],
        "database_subnets": database_subnets,
        "database_subnet_ids": [s.id for s in database_subnets],
        "internet_gateway": igw,
        "nat_gateways": nat_gateways,
        "alb_security_group": alb_sg,
        "alb_security_group_id": alb_sg.id,
        "app_security_group": app_sg,
        "app_security_group_id": app_sg.id,
        "db_security_group": db_sg,
        "db_security_group_id": db_sg.id,
        "redis_security_group": redis_sg,
        "redis_security_group_id": redis_sg.id,
        "vpn_gateway": vpn_gateway,
    }