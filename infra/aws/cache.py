"""
AWS ElastiCache Redis infrastructure.

Creates:
- Redis replication groups with cluster mode
- Cache subnet groups
- Parameter groups for Redis tuning
- Automatic failover and Multi-AZ
"""
import pulumi
import pulumi_aws as aws


def create_elasticache_redis(
    name: str,
    vpc_id: pulumi.Output[str],
    subnet_ids: list[pulumi.Output[str]],
    security_group_id: pulumi.Output[str],
    node_type: str = "cache.r6g.large",
    num_cache_nodes: int = 2,
    redis_version: str = "7.0",
    port: int = 6379,
    auth_token: pulumi.Output[str] = None,
    at_rest_encryption_enabled: bool = True,
    transit_encryption_enabled: bool = True,
    kms_key_id: pulumi.Output[str] = None,
    automatic_failover_enabled: bool = True,
    multi_az_enabled: bool = True,
    snapshot_retention_limit: int = 5,
    snapshot_window: str = "03:00-05:00",
    maintenance_window: str = "sun:05:00-sun:07:00",
    parameter_group_name: Optional[str] = None,
    subnet_group_name: Optional[str] = None,
    existing_replication_group_id: Optional[str] = None,
    protect_existing: bool = True,
) -> dict:
    """
    Create ElastiCache Redis cluster with replication.

    Args:
        name: Redis cluster name prefix
        vpc_id: VPC ID
        subnet_ids: List of subnet IDs for cache subnet group
        security_group_id: Security group ID for Redis access
        node_type: Cache node type
        num_cache_nodes: Number of cache nodes (including replicas)
        redis_version: Redis version
        port: Redis port
        auth_token: Redis AUTH token for security
        at_rest_encryption_enabled: Enable encryption at rest
        transit_encryption_enabled: Enable encryption in transit (TLS)
        kms_key_id: KMS key for encryption at rest
        automatic_failover_enabled: Enable automatic failover
        multi_az_enabled: Enable Multi-AZ for HA
        snapshot_retention_limit: Number of daily snapshots to retain
        snapshot_window: Daily snapshot window (UTC)
        maintenance_window: Weekly maintenance window (UTC)

    Returns:
        Dictionary with cache resources
    """
    # Generate auth token if not provided and transit encryption is enabled
    if auth_token is None and transit_encryption_enabled:
        import pulumi_random as random

        auth_token = random.RandomPassword(
            f"{name}-redis-auth",
            length=32,
            special=False,  # Redis AUTH token doesn't support special chars
        ).result

    # Create cache subnet group
    subnet_group_opts = None
    effective_subnet_group_name = subnet_group_name or f"{name}-redis-subnet-group"
    if subnet_group_name:
        subnet_group_opts = pulumi.ResourceOptions(import_=subnet_group_name, protect=protect_existing)

    subnet_group = aws.elasticache.SubnetGroup(
        f"{name}-redis-subnet-group",
        name=effective_subnet_group_name,
        subnet_ids=subnet_ids,
        description=f"Subnet group for {name} Redis cluster",
        tags={
            "Name": f"{name}-redis-subnet-group",
        },
        opts=subnet_group_opts,
    )

    # Create parameter group for Redis 7.x
    parameter_group_opts = None
    effective_parameter_group_name = parameter_group_name or f"{name}-redis-params"
    if parameter_group_name:
        parameter_group_opts = pulumi.ResourceOptions(import_=parameter_group_name, protect=protect_existing)

    parameter_group = aws.elasticache.ParameterGroup(
        f"{name}-redis-params",
        name=effective_parameter_group_name,
        family="redis7",
        description=f"Parameter group for {name} Redis",
        parameters=[
            # Memory management
            aws.elasticache.ParameterGroupParameterArgs(
                name="maxmemory-policy",
                value="allkeys-lru",  # Evict least recently used keys
            ),
            # Persistence (AOF for durability)
            aws.elasticache.ParameterGroupParameterArgs(
                name="appendonly",
                value="yes",
            ),
            aws.elasticache.ParameterGroupParameterArgs(
                name="appendfsync",
                value="everysec",
            ),
            # Connection timeout
            aws.elasticache.ParameterGroupParameterArgs(
                name="timeout",
                value="300",  # 5 minutes
            ),
            # Slow log
            aws.elasticache.ParameterGroupParameterArgs(
                name="slowlog-log-slower-than",
                value="10000",  # 10ms
            ),
            aws.elasticache.ParameterGroupParameterArgs(
                name="slowlog-max-len",
                value="128",
            ),
        ],
        tags={
            "Name": f"{name}-redis-params",
        },
    )

    # Create replication group (cluster)
    replication_group_kwargs = {
        "replication_group_id": existing_replication_group_id or name,
        "description": f"Redis cluster for {name}",
        "engine": "redis",
        "engine_version": redis_version,
        "node_type": node_type,
        "num_cache_clusters": num_cache_nodes,
        "port": port,
        "parameter_group_name": parameter_group.name,
        "subnet_group_name": subnet_group.name,
        "security_group_ids": [security_group_id],
        "automatic_failover_enabled": automatic_failover_enabled,
        "multi_az_enabled": multi_az_enabled,
        "at_rest_encryption_enabled": at_rest_encryption_enabled,
        "transit_encryption_enabled": transit_encryption_enabled,
        "snapshot_retention_limit": snapshot_retention_limit,
        "snapshot_window": snapshot_window,
        "maintenance_window": maintenance_window,
        "auto_minor_version_upgrade": True,
        "apply_immediately": False,  # Apply changes during maintenance window
        "tags": {
            "Name": name,
            "ManagedBy": "Pulumi",
        },
    }

    # Add auth token if transit encryption is enabled
    if transit_encryption_enabled and auth_token and not existing_replication_group_id:
        def _sanitize(token: str) -> str:
            # ElastiCache AUTH token allows alphanumeric and these symbols: !#$%&()*+,-.:;<=>?@[]^_{|}~
            allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,-.:;<=>?@[]^_{|}~")
            sanitized = ''.join(ch for ch in token if ch in allowed)
            if len(sanitized) < 16:
                raise ValueError("Redis auth token must be at least 16 characters of allowed charset")
            return sanitized

        replication_group_kwargs["auth_token"] = auth_token.apply(_sanitize) if isinstance(auth_token, pulumi.Output) else _sanitize(auth_token)

    # Add KMS encryption if provided
    if kms_key_id and at_rest_encryption_enabled:
        replication_group_kwargs["kms_key_id"] = kms_key_id

    # Add log delivery configuration
    replication_group_kwargs["log_delivery_configurations"] = [
        aws.elasticache.ReplicationGroupLogDeliveryConfigurationArgs(
            destination="/aws/elasticache/redis/slow-log",
            destination_type="cloudwatch-logs",
            log_format="json",
            log_type="slow-log",
        ),
        aws.elasticache.ReplicationGroupLogDeliveryConfigurationArgs(
            destination="/aws/elasticache/redis/engine-log",
            destination_type="cloudwatch-logs",
            log_format="json",
            log_type="engine-log",
        ),
    ]

    replication_group_opts = None
    if existing_replication_group_id:
        replication_group_opts = pulumi.ResourceOptions(import_=existing_replication_group_id, protect=protect_existing)

    replication_group = aws.elasticache.ReplicationGroup(
        f"{name}-redis",
        opts=replication_group_opts,
        **replication_group_kwargs,
    )

    return {
        "replication_group": replication_group,
        "redis_cluster": replication_group,  # Alias for backward compatibility
        "subnet_group": subnet_group,
        "parameter_group": parameter_group,
        "primary_endpoint": replication_group.primary_endpoint_address,
        "reader_endpoint": replication_group.reader_endpoint_address,
        "configuration_endpoint": replication_group.configuration_endpoint_address,
    }