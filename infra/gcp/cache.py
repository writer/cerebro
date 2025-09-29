"""
GCP Memorystore Redis infrastructure.

Creates:
- Memorystore Redis instances with HA
- Redis with persistence (RDB snapshots)
- Private VPC connections
- Auth and TLS encryption
"""
import pulumi
import pulumi_gcp as gcp
import pulumi_random as random


def create_memorystore_redis(
    name: str,
    project: str,
    region: str = "us-central1",
    network_id: pulumi.Output[str] = None,
    tier: str = "STANDARD_HA",  # STANDARD_HA or BASIC
    memory_size_gb: int = 5,
    redis_version: str = "REDIS_7_0",
    auth_enabled: bool = True,
    auth_string: pulumi.Output[str] = None,
    transit_encryption_mode: str = "SERVER_AUTHENTICATION",
    persistence_mode: str = "RDB",  # RDB or AOF
    rdb_snapshot_period: str = "TWELVE_HOURS",
    rdb_snapshot_start_time: str = "03:00",
    maintenance_window_day: str = "SUNDAY",
    maintenance_window_hour: int = 4,
) -> dict:
    """
    Create Memorystore Redis instance with production settings.

    Args:
        name: Instance name
        project: GCP project ID
        region: GCP region
        network_id: VPC network ID (required for private connection)
        tier: STANDARD_HA (HA with replica) or BASIC (single node)
        memory_size_gb: Memory size in GB
        redis_version: Redis version
        auth_enabled: Enable Redis AUTH
        auth_string: AUTH string (auto-generated if not provided)
        transit_encryption_mode: SERVER_AUTHENTICATION or DISABLED
        persistence_mode: RDB (snapshots) or AOF (append-only file)
        rdb_snapshot_period: Snapshot frequency (SIX_HOURS, TWELVE_HOURS, etc.)
        rdb_snapshot_start_time: Snapshot start time (HH:MM UTC)
        maintenance_window_day: Maintenance day
        maintenance_window_hour: Maintenance hour (0-23 UTC)

    Returns:
        Dictionary with Redis resources
    """
    # Generate auth string if not provided and auth is enabled
    if auth_enabled and auth_string is None:
        auth_string = random.RandomPassword(
            f"{name}-redis-auth",
            length=32,
            special=False,  # Redis AUTH doesn't support special chars well
        ).result

    # Build Redis instance config
    redis_config = {
        "maxmemory-policy": "allkeys-lru",
        "timeout": "300",
        "notify-keyspace-events": "Ex",  # Keyspace notifications
    }

    # Persistence configuration
    persistence_config = None
    if persistence_mode == "RDB":
        persistence_config = gcp.redis.InstancePersistenceConfigArgs(
            persistence_mode="RDB",
            rdb_snapshot_period=rdb_snapshot_period,
            rdb_snapshot_start_time=rdb_snapshot_start_time,
        )
    elif persistence_mode == "AOF":
        persistence_config = gcp.redis.InstancePersistenceConfigArgs(
            persistence_mode="AOF",
        )

    # Maintenance policy
    maintenance_policy = gcp.redis.InstanceMaintenancePolicyArgs(
        weekly_maintenance_windows=[
            gcp.redis.InstanceMaintenancePolicyWeeklyMaintenanceWindowArgs(
                day=maintenance_window_day,
                start_time=gcp.redis.InstanceMaintenancePolicyWeeklyMaintenanceWindowStartTimeArgs(
                    hours=maintenance_window_hour,
                    minutes=0,
                    seconds=0,
                    nanos=0,
                ),
                duration="14400s",  # 4 hours
            )
        ]
    )

    # Create Memorystore Redis instance
    redis_instance = gcp.redis.Instance(
        f"{name}-redis",
        name=f"{name}-redis",
        project=project,
        region=region,
        tier=tier,
        memory_size_gb=memory_size_gb,
        redis_version=redis_version,
        authorized_network=network_id,
        auth_enabled=auth_enabled,
        transit_encryption_mode=transit_encryption_mode,
        redis_configs=redis_config,
        persistence_config=persistence_config,
        maintenance_policy=maintenance_policy,
        display_name=f"{name} Redis",
        labels={
            "managed-by": "pulumi",
            "environment": name.split("-")[1] if "-" in name else "production",
        },
        # Connect mode: DIRECT_PEERING (private IP only)
        connect_mode="DIRECT_PEERING",
    )

    # Store auth string if provided
    auth_secret = None
    if auth_enabled and auth_string:
        # Note: In practice, you'd store this in Secret Manager
        # For now, we'll return it in the dict
        auth_secret = auth_string

    return {
        "redis_instance": redis_instance,
        "host": redis_instance.host,
        "port": redis_instance.port,
        "current_location_id": redis_instance.current_location_id,
        "auth_string": auth_secret,
        "persistence_iam_identity": redis_instance.persistence_iam_identity,
        "read_endpoint": redis_instance.read_endpoint,
        "read_endpoint_port": redis_instance.read_endpoint_port,
    }


def create_basic_redis(
    name: str,
    project: str,
    region: str,
    network_id: pulumi.Output[str],
    memory_size_gb: int = 1,
) -> dict:
    """
    Create a basic (non-HA) Redis instance for dev/test.

    Args:
        name: Instance name
        project: GCP project ID
        region: GCP region
        network_id: VPC network ID
        memory_size_gb: Memory size in GB

    Returns:
        Dictionary with Redis resources
    """
    redis_instance = gcp.redis.Instance(
        f"{name}-redis-basic",
        name=f"{name}-redis-basic",
        project=project,
        region=region,
        tier="BASIC",
        memory_size_gb=memory_size_gb,
        redis_version="REDIS_7_0",
        authorized_network=network_id,
        display_name=f"{name} Redis (Basic)",
        labels={
            "managed-by": "pulumi",
            "tier": "basic",
        },
    )

    return {
        "redis_instance": redis_instance,
        "host": redis_instance.host,
        "port": redis_instance.port,
    }