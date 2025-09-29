"""
GCP Cloud Load Balancing infrastructure.

Creates:
- Global HTTPS load balancer
- SSL certificates (Google-managed or self-managed)
- Backend services
- URL maps and forwarding rules
- Cloud CDN integration
"""
import pulumi
import pulumi_gcp as gcp


def create_https_load_balancer(
    name: str,
    project: str,
    cloud_run_service_url: pulumi.Output[str],
    domain: str,
    enable_cdn: bool = False,
    enable_iap: bool = False,
) -> dict:
    """
    Create HTTPS load balancer for Cloud Run service.

    Args:
        name: Load balancer name prefix
        project: GCP project ID
        cloud_run_service_url: Cloud Run service URL
        domain: Domain name for SSL certificate
        enable_cdn: Enable Cloud CDN
        enable_iap: Enable Identity-Aware Proxy

    Returns:
        Dictionary with load balancer resources
    """
    # Create serverless NEG (Network Endpoint Group) for Cloud Run
    neg = gcp.compute.RegionNetworkEndpointGroup(
        f"{name}-neg",
        name=f"{name}-neg",
        project=project,
        region=cloud_run_service_url.apply(
            lambda url: _extract_region_from_url(url)
        ),
        network_endpoint_type="SERVERLESS",
        cloud_run=gcp.compute.RegionNetworkEndpointGroupCloudRunArgs(
            service=cloud_run_service_url.apply(
                lambda url: _extract_service_name_from_url(url)
            ),
        ),
    )

    # Create backend service
    backend_service_args = {
        "name": f"{name}-backend",
        "project": project,
        "protocol": "HTTPS",
        "port_name": "http",
        "timeout_sec": 30,
        "backends": [
            gcp.compute.BackendServiceBackendArgs(
                group=neg.id,
            )
        ],
        "log_config": gcp.compute.BackendServiceLogConfigArgs(
            enable=True,
            sample_rate=1.0,
        ),
    }

    # Add CDN policy if enabled
    if enable_cdn:
        backend_service_args["cdn_policy"] = (
            gcp.compute.BackendServiceCdnPolicyArgs(
                cache_mode="CACHE_ALL_STATIC",
                client_ttl=3600,
                default_ttl=3600,
                max_ttl=86400,
                negative_caching=True,
                serve_while_stale=86400,
            )
        )
        backend_service_args["enable_cdn"] = True

    # Add IAP if enabled
    if enable_iap:
        backend_service_args["iap"] = gcp.compute.BackendServiceIapArgs(
            oauth2_client_id="YOUR_OAUTH2_CLIENT_ID",
            oauth2_client_secret="YOUR_OAUTH2_CLIENT_SECRET",
        )

    backend_service = gcp.compute.BackendService(
        f"{name}-backend",
        **backend_service_args,
    )

    # Create URL map
    url_map = gcp.compute.URLMap(
        f"{name}-url-map",
        name=f"{name}-url-map",
        project=project,
        default_service=backend_service.id,
    )

    # Create managed SSL certificate
    ssl_cert = gcp.compute.ManagedSslCertificate(
        f"{name}-ssl-cert",
        name=f"{name}-ssl-cert",
        project=project,
        managed=gcp.compute.ManagedSslCertificateManagedArgs(
            domains=[domain],
        ),
    )

    # Create HTTPS proxy
    https_proxy = gcp.compute.TargetHttpsProxy(
        f"{name}-https-proxy",
        name=f"{name}-https-proxy",
        project=project,
        url_map=url_map.id,
        ssl_certificates=[ssl_cert.id],
    )

    # Reserve global IP address
    global_ip = gcp.compute.GlobalAddress(
        f"{name}-global-ip",
        name=f"{name}-global-ip",
        project=project,
        ip_version="IPV4",
    )

    # Create forwarding rule (HTTPS)
    https_forwarding_rule = gcp.compute.GlobalForwardingRule(
        f"{name}-https-rule",
        name=f"{name}-https-rule",
        project=project,
        target=https_proxy.id,
        port_range="443",
        ip_address=global_ip.address,
        load_balancing_scheme="EXTERNAL",
    )

    # Create HTTP to HTTPS redirect
    http_to_https_redirect = _create_http_redirect(
        name=name,
        project=project,
        global_ip=global_ip.address,
    )

    return {
        "backend_service": backend_service,
        "url_map": url_map,
        "ssl_certificate": ssl_cert,
        "https_proxy": https_proxy,
        "global_ip": global_ip,
        "ip_address": global_ip.address,
        "https_forwarding_rule": https_forwarding_rule,
        "http_forwarding_rule": http_to_https_redirect,
    }


def _create_http_redirect(
    name: str,
    project: str,
    global_ip: pulumi.Output[str],
) -> gcp.compute.GlobalForwardingRule:
    """Create HTTP to HTTPS redirect."""
    # Create URL map for redirect
    redirect_url_map = gcp.compute.URLMap(
        f"{name}-http-redirect",
        name=f"{name}-http-redirect",
        project=project,
        default_url_redirect=gcp.compute.URLMapDefaultUrlRedirectArgs(
            https_redirect=True,
            strip_query=False,
        ),
    )

    # Create HTTP proxy
    http_proxy = gcp.compute.TargetHttpProxy(
        f"{name}-http-proxy",
        name=f"{name}-http-proxy",
        project=project,
        url_map=redirect_url_map.id,
    )

    # Create forwarding rule (HTTP)
    return gcp.compute.GlobalForwardingRule(
        f"{name}-http-rule",
        name=f"{name}-http-rule",
        project=project,
        target=http_proxy.id,
        port_range="80",
        ip_address=global_ip,
        load_balancing_scheme="EXTERNAL",
    )


def _extract_region_from_url(url: str) -> str:
    """Extract region from Cloud Run URL."""
    # URL format: https://SERVICE-PROJECT.REGION.run.app
    parts = url.split(".")
    if len(parts) >= 3:
        return parts[1]
    return "us-central1"  # default


def _extract_service_name_from_url(url: str) -> str:
    """Extract service name from Cloud Run URL."""
    # URL format: https://SERVICE-PROJECT.REGION.run.app
    hostname = url.replace("https://", "").split(".")[0]
    # Service name is everything before the last dash and project ID
    return hostname


def create_cloud_armor_policy(
    name: str,
    project: str,
    backend_service_id: pulumi.Output[str],
    rate_limit_threshold: int = 1000,
) -> gcp.compute.SecurityPolicy:
    """
    Create Cloud Armor security policy with rate limiting and DDoS protection.

    Args:
        name: Policy name
        project: GCP project ID
        backend_service_id: Backend service to attach policy
        rate_limit_threshold: Max requests per minute per IP

    Returns:
        Security policy resource
    """
    policy = gcp.compute.SecurityPolicy(
        f"{name}-armor-policy",
        name=f"{name}-armor-policy",
        project=project,
        rules=[
            # Rate limiting rule
            gcp.compute.SecurityPolicyRuleArgs(
                action="rate_based_ban",
                priority=1000,
                match=gcp.compute.SecurityPolicyRuleMatchArgs(
                    versioned_expr="SRC_IPS_V1",
                    config=gcp.compute.SecurityPolicyRuleMatchConfigArgs(
                        src_ip_ranges=["*"],
                    ),
                ),
                rate_limit_options=gcp.compute.SecurityPolicyRuleRateLimitOptionsArgs(
                    conform_action="allow",
                    exceed_action="deny(429)",
                    enforce_on_key="IP",
                    rate_limit_threshold=gcp.compute.SecurityPolicyRuleRateLimitOptionsRateLimitThresholdArgs(
                        count=rate_limit_threshold,
                        interval_sec=60,
                    ),
                    ban_duration_sec=600,  # 10 minute ban
                ),
            ),
            # Default allow rule
            gcp.compute.SecurityPolicyRuleArgs(
                action="allow",
                priority=2147483647,
                match=gcp.compute.SecurityPolicyRuleMatchArgs(
                    versioned_expr="SRC_IPS_V1",
                    config=gcp.compute.SecurityPolicyRuleMatchConfigArgs(
                        src_ip_ranges=["*"],
                    ),
                ),
                description="Default allow rule",
            ),
        ],
        adaptive_protection_config=gcp.compute.SecurityPolicyAdaptiveProtectionConfigArgs(
            layer7_ddos_defense_config=gcp.compute.SecurityPolicyAdaptiveProtectionConfigLayer7DdosDefenseConfigArgs(
                enable=True,
            ),
        ),
    )

    # Attach policy to backend service
    gcp.compute.BackendServiceSecurityPolicyAttachment(
        f"{name}-policy-attachment",
        backend_service=backend_service_id,
        security_policy=policy.id,
    )

    return policy