"""
GCP VPC and networking infrastructure.

Creates:
- VPC with auto mode disabled (custom subnets)
- Regional subnets across multiple regions
- Cloud NAT for private instances
- Firewall rules for ingress/egress
- Cloud Router for NAT
"""

import pulumi
import pulumi_gcp as gcp


def create_vpc(
    name: str,
    project: str,
    region: str = "us-central1",
    enable_cloud_nat: bool = True,
) -> dict:
    """
    Create VPC with regional subnets and firewall rules.

    Args:
        name: VPC name prefix
        project: GCP project ID
        region: Primary region for resources
        enable_cloud_nat: Create Cloud NAT for private instances

    Returns:
        Dictionary with VPC resources
    """
    # Create VPC (global resource)
    network = gcp.compute.Network(
        f"{name}-network",
        name=f"{name}-network",
        project=project,
        auto_create_subnetworks=False,  # Custom subnets
        routing_mode="REGIONAL",
        description=f"VPC for {name}",
    )

    # Create public subnet (for load balancer)
    public_subnet = gcp.compute.Subnetwork(
        f"{name}-public-subnet",
        name=f"{name}-public-subnet",
        project=project,
        region=region,
        network=network.id,
        ip_cidr_range="10.0.0.0/24",
        private_ip_google_access=True,  # Access Google APIs
        description="Public subnet for load balancers",
    )

    # Create private subnet (for application tier)
    private_subnet = gcp.compute.Subnetwork(
        f"{name}-private-subnet",
        name=f"{name}-private-subnet",
        project=project,
        region=region,
        network=network.id,
        ip_cidr_range="10.0.10.0/24",
        private_ip_google_access=True,
        description="Private subnet for application tier",
    )

    # Create database subnet (isolated tier)
    database_subnet = gcp.compute.Subnetwork(
        f"{name}-database-subnet",
        name=f"{name}-database-subnet",
        project=project,
        region=region,
        network=network.id,
        ip_cidr_range="10.0.20.0/24",
        private_ip_google_access=True,
        description="Database subnet for data tier",
    )

    # Create Cloud Router for Cloud NAT
    router = None
    cloud_nat = None
    if enable_cloud_nat:
        router = gcp.compute.Router(
            f"{name}-router",
            name=f"{name}-router",
            project=project,
            region=region,
            network=network.id,
            description="Router for Cloud NAT",
        )

        # Create Cloud NAT
        cloud_nat = gcp.compute.RouterNat(
            f"{name}-nat",
            name=f"{name}-nat",
            project=project,
            region=region,
            router=router.name,
            nat_ip_allocate_option="AUTO_ONLY",
            source_subnetwork_ip_ranges_to_nat="ALL_SUBNETWORKS_ALL_IP_RANGES",
            log_config=gcp.compute.RouterNatLogConfigArgs(
                enable=True,
                filter="ERRORS_ONLY",
            ),
        )

    # Create firewall rules

    # Allow internal traffic within VPC
    gcp.compute.Firewall(
        f"{name}-allow-internal",
        name=f"{name}-allow-internal",
        project=project,
        network=network.id,
        direction="INGRESS",
        priority=1000,
        source_ranges=["10.0.0.0/8"],
        allows=[
            gcp.compute.FirewallAllowArgs(
                protocol="tcp",
                ports=["0-65535"],
            ),
            gcp.compute.FirewallAllowArgs(
                protocol="udp",
                ports=["0-65535"],
            ),
            gcp.compute.FirewallAllowArgs(
                protocol="icmp",
            ),
        ],
        description="Allow all internal traffic",
    )

    # Allow HTTP/HTTPS from internet to load balancer
    lb_firewall = gcp.compute.Firewall(
        f"{name}-allow-lb-http-https",
        name=f"{name}-allow-lb-http-https",
        project=project,
        network=network.id,
        direction="INGRESS",
        priority=1000,
        source_ranges=["0.0.0.0/0"],
        target_tags=["http-server", "https-server"],
        allows=[
            gcp.compute.FirewallAllowArgs(
                protocol="tcp",
                ports=["80", "443"],
            ),
        ],
        description="Allow HTTP/HTTPS from internet to load balancer",
    )

    # Allow health checks from Google Cloud
    gcp.compute.Firewall(
        f"{name}-allow-health-checks",
        name=f"{name}-allow-health-checks",
        project=project,
        network=network.id,
        direction="INGRESS",
        priority=1000,
        source_ranges=[
            "35.191.0.0/16",  # Google Cloud health check ranges
            "130.211.0.0/22",
        ],
        allows=[
            gcp.compute.FirewallAllowArgs(
                protocol="tcp",
                ports=["8000", "8080"],
            ),
        ],
        description="Allow health checks from Google Cloud",
    )

    # Deny all other ingress by default (implicit, but explicit for clarity)
    gcp.compute.Firewall(
        f"{name}-deny-all-ingress",
        name=f"{name}-deny-all-ingress",
        project=project,
        network=network.id,
        direction="INGRESS",
        priority=65534,
        source_ranges=["0.0.0.0/0"],
        denies=[
            gcp.compute.FirewallDenyArgs(
                protocol="all",
            ),
        ],
        description="Deny all other ingress traffic",
    )

    # Allow all egress (default, but explicit)
    gcp.compute.Firewall(
        f"{name}-allow-all-egress",
        name=f"{name}-allow-all-egress",
        project=project,
        network=network.id,
        direction="EGRESS",
        priority=1000,
        destination_ranges=["0.0.0.0/0"],
        allows=[
            gcp.compute.FirewallAllowArgs(
                protocol="all",
            ),
        ],
        description="Allow all egress traffic",
    )

    return {
        "network": network,
        "network_id": network.id,
        "network_name": network.name,
        "public_subnet": public_subnet,
        "public_subnet_id": public_subnet.id,
        "private_subnet": private_subnet,
        "private_subnet_id": private_subnet.id,
        "database_subnet": database_subnet,
        "database_subnet_id": database_subnet.id,
        "router": router,
        "cloud_nat": cloud_nat,
        "lb_firewall": lb_firewall,
    }


def create_vpc_peering(
    name: str,
    project: str,
    network: pulumi.Output[str],
    peer_network: str,
) -> gcp.compute.NetworkPeering:
    """
    Create VPC peering connection.

    Args:
        name: Peering name
        project: GCP project ID
        network: Local network name
        peer_network: Peer network self link

    Returns:
        NetworkPeering resource
    """
    return gcp.compute.NetworkPeering(
        f"{name}-peering",
        name=f"{name}-peering",
        network=network,
        peer_network=peer_network,
        export_custom_routes=False,
        import_custom_routes=False,
    )
