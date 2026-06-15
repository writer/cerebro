"""
ElastiCache backing store for low-latency Cerebro query caches.
"""

import pulumi
import pulumi_aws as aws


def create_query_cache(
    name: str,
    vpc_id: pulumi.Input[str],
    subnet_ids: list[pulumi.Input[str]],
    app_security_group_id: pulumi.Input[str],
    kms_key_arn: pulumi.Input[str],
    secret_name: str,
    engine: str = "valkey",
    major_engine_version: str | None = None,
) -> dict:
    """Create a private ElastiCache Serverless cache and publish its URL."""
    normalized_engine = _normalize_engine(engine)
    security_group = aws.ec2.SecurityGroup(
        f"{name}-cache-sg",
        vpc_id=vpc_id,
        description=f"Cache access for {name}",
        ingress=[
            aws.ec2.SecurityGroupIngressArgs(
                protocol="tcp",
                from_port=6379,
                to_port=6379,
                security_groups=[app_security_group_id],
            )
        ],
        egress=[
            aws.ec2.SecurityGroupEgressArgs(
                protocol="-1",
                from_port=0,
                to_port=0,
                cidr_blocks=["0.0.0.0/0"],
            )
        ],
        tags={"Name": f"{name}-cache-sg"},
    )

    cache_args = {
        "name": f"{name}-query-cache",
        "engine": normalized_engine,
        "description": f"Cerebro query cache for {name}",
        "kms_key_id": kms_key_arn,
        "security_group_ids": [security_group.id],
        "subnet_ids": subnet_ids,
        "tags": {"Name": f"{name}-query-cache"},
    }
    if major_engine_version:
        cache_args["major_engine_version"] = major_engine_version

    serverless_cache = aws.elasticache.ServerlessCache(
        f"{name}-query-cache",
        **cache_args,
    )

    secret = aws.secretsmanager.Secret(
        f"{name}-cache-url",
        name=secret_name,
        kms_key_id=kms_key_arn,
        tags={"Name": secret_name},
    )

    cache_url = serverless_cache.endpoints.apply(_cache_url)
    secret_version = aws.secretsmanager.SecretVersion(
        f"{name}-cache-url-version",
        secret_id=secret.id,
        secret_string=cache_url,
    )

    return {
        "cache": serverless_cache,
        "security_group": security_group,
        "secret": secret,
        "secret_version": secret_version,
        "url": cache_url,
    }


def _normalize_engine(engine: str) -> str:
    normalized = str(engine or "valkey").strip().lower()
    if normalized not in {"redis", "valkey"}:
        raise ValueError("cache engine must be redis or valkey")
    return normalized


def _cache_url(endpoints) -> str:
    if not endpoints:
        return ""
    endpoint = endpoints[0]
    address = endpoint.get("address") if isinstance(endpoint, dict) else endpoint.address
    port = endpoint.get("port") if isinstance(endpoint, dict) else endpoint.port
    return f"rediss://{address}:{port or 6379}"
