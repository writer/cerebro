"""
AWS Application Load Balancer infrastructure.

Creates:
- Application Load Balancer (ALB)
- Target groups for ECS services
- Listeners for HTTP/HTTPS
- ACM certificates for TLS
"""
import pulumi
import pulumi_aws as aws


def create_application_load_balancer(
    name: str,
    vpc_id: pulumi.Output[str],
    subnet_ids: list[pulumi.Output[str]],
    security_group_id: pulumi.Output[str],
    certificate_domain: str = None,
    internal: bool = True,
    enable_deletion_protection: bool = True,
    enable_http2: bool = True,
    idle_timeout: int = 60,
) -> dict:
    """
    Create Application Load Balancer with HTTPS support.

    Args:
        name: ALB name prefix
        vpc_id: VPC ID
        subnet_ids: Subnets for ALB placement
        security_group_id: Security group ID for ALB
        certificate_domain: Domain for ACM certificate (optional)
        internal: Create an internal (private) ALB when True
        enable_deletion_protection: Prevent accidental deletion
        enable_http2: Enable HTTP/2
        idle_timeout: Idle timeout in seconds

    Returns:
        Dictionary with ALB resources
    """
    # Create ALB
    alb = aws.lb.LoadBalancer(
        f"{name}-alb",
        name=f"{name}-alb",
        load_balancer_type="application",
        subnets=subnet_ids,
        security_groups=[security_group_id],
        internal=internal,
        enable_deletion_protection=enable_deletion_protection,
        enable_http2=enable_http2,
        idle_timeout=idle_timeout,
        tags={
            "Name": f"{name}-alb",
            "ManagedBy": "Pulumi",
        },
    )

    # Create target group for API service
    target_group = aws.lb.TargetGroup(
        f"{name}-api-tg",
        name=f"{name}-api",
        port=8000,
        protocol="HTTP",
        vpc_id=vpc_id,
        target_type="ip",
        deregistration_delay=30,
        health_check=aws.lb.TargetGroupHealthCheckArgs(
            enabled=True,
            path="/health",
            protocol="HTTP",
            matcher="200",
            interval=30,
            timeout=5,
            healthy_threshold=2,
            unhealthy_threshold=3,
        ),
        tags={
            "Name": f"{name}-api-tg",
        },
    )

    # Create HTTP listener (redirect to HTTPS if certificate exists)
    if certificate_domain:
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
        aws.lb.Listener(
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

    result = {
        "alb": alb,
        "target_group": target_group,
        "dns_name": alb.dns_name,
        "zone_id": alb.zone_id,
    }

    # Create HTTPS listener if certificate domain is provided
    if certificate_domain:
        # Look up or create ACM certificate
        certificate = _get_or_create_certificate(name, certificate_domain)

        https_listener = aws.lb.Listener(
            f"{name}-https-listener",
            load_balancer_arn=alb.arn,
            port=443,
            protocol="HTTPS",
            ssl_policy="ELBSecurityPolicy-TLS13-1-2-2021-06",  # TLS 1.3
            certificate_arn=certificate.arn,
            default_actions=[
                aws.lb.ListenerDefaultActionArgs(
                    type="forward",
                    target_group_arn=target_group.arn,
                )
            ],
        )

        result["https_listener"] = https_listener
        result["certificate"] = certificate

    return result


def _get_or_create_certificate(name: str, domain: str) -> aws.acm.Certificate:
    """
    Get existing or create new ACM certificate for domain.

    Note: This creates a certificate but doesn't handle DNS validation.
    You'll need to manually validate the certificate or use Route53.
    """
    # Try to find existing certificate
    try:
        # This will fail if no certificate exists, which is expected
        existing_cert = aws.acm.get_certificate(
            domain=domain,
            statuses=["ISSUED"],
        )
        return existing_cert
    except Exception:
        pass

    # Create new certificate
    cert = aws.acm.Certificate(
        f"{name}-cert",
        domain_name=domain,
        validation_method="DNS",
        tags={
            "Name": f"{name}-cert",
            "Domain": domain,
        },
    )

    # Note: Certificate validation must be done manually or via Route53
    # Export validation records for manual DNS configuration

    return cert


def create_route53_alias(
    name: str,
    zone_id: str,
    domain_name: str,
    alb_dns_name: pulumi.Output[str],
    alb_zone_id: pulumi.Output[str],
) -> aws.route53.Record:
    """
    Create Route53 alias record for ALB.

    Args:
        name: Record name
        zone_id: Route53 hosted zone ID
        domain_name: Domain name for the record
        alb_dns_name: ALB DNS name
        alb_zone_id: ALB hosted zone ID

    Returns:
        Route53 record
    """
    return aws.route53.Record(
        f"{name}-alias",
        zone_id=zone_id,
        name=domain_name,
        type="A",
        aliases=[
            aws.route53.RecordAliasArgs(
                name=alb_dns_name,
                zone_id=alb_zone_id,
                evaluate_target_health=True,
            )
        ],
    )