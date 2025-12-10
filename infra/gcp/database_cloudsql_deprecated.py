"""
GCP Cloud SQL PostgreSQL database infrastructure.

Creates:
- Cloud SQL PostgreSQL instances with HA
- Database users and passwords
- Private IP connections
- Automated backups and maintenance
- Read replicas for scaling
"""
import pulumi
import pulumi_gcp as gcp
import pulumi_random as random


def create_cloud_sql_postgres(
    name: str,
    project: str,
    region: str = "us-central1",
    network_id: pulumi.Output[str] = None,
    tier: str = "db-custom-4-16384",  # 4 vCPU, 16GB RAM
    disk_size: int = 100,  # GB
    database_version: str = "POSTGRES_15",
    master_password: pulumi.Output[str] = None,
    availability_type: str = "REGIONAL",  # REGIONAL or ZONAL
    backup_enabled: bool = True,
    backup_start_time: str = "03:00",
    maintenance_window_day: int = 7,  # Sunday
    maintenance_window_hour: int = 4,  # 4 AM
    kms_key_name: pulumi.Output[str] = None,
    enable_insights: bool = True,
) -> dict:
    """
    Create Cloud SQL PostgreSQL instance with production settings.

    Args:
        name: Instance name
        project: GCP project ID
        region: GCP region
        network_id: VPC network ID for private IP
        tier: Machine tier (db-custom-CPU-MEM or predefined)
        disk_size: Disk size in GB
        database_version: PostgreSQL version
        master_password: Master password (auto-generated if not provided)
        availability_type: REGIONAL (HA) or ZONAL (single zone)
        backup_enabled: Enable automated backups
        backup_start_time: Backup start time (HH:MM UTC)
        maintenance_window_day: Maintenance day (1=Mon, 7=Sun)
        maintenance_window_hour: Maintenance hour (0-23 UTC)
        kms_key_name: KMS key name for encryption
        enable_insights: Enable Query Insights

    Returns:
        Dictionary with database resources
    """
    # Generate password if not provided
    if master_password is None:
        master_password = random.RandomPassword(
            f"{name}-db-password",
            length=32,
            special=True,
            override_special="!#$%&*()-_=+[]{}<>:?",
        ).result

    # Create private service connection if network provided
    if network_id:
        # Allocate IP range for private services
        private_ip_range = gcp.compute.GlobalAddress(
            f"{name}-private-ip-range",
            name=f"{name}-private-ip-range",
            project=project,
            purpose="VPC_PEERING",
            address_type="INTERNAL",
            prefix_length=16,
            network=network_id,
        )

        # Create private VPC connection
        gcp.servicenetworking.Connection(
            f"{name}-private-vpc-connection",
            network=network_id,
            service="servicenetworking.googleapis.com",
            reserved_peering_ranges=[private_ip_range.name],
        )

    # Build settings
    settings_args = {
        "tier": tier,
        "disk_size": disk_size,
        "disk_type": "PD_SSD",
        "disk_autoresize": True,
        "disk_autoresize_limit": disk_size * 10,  # Max 10x initial size
        "availability_type": availability_type,
        "ip_configuration": gcp.sql.DatabaseInstanceSettingsIpConfigurationArgs(
            ipv4_enabled=False if network_id else True,
            private_network=network_id,
            require_ssl=True,
        ),
        "backup_configuration": gcp.sql.DatabaseInstanceSettingsBackupConfigurationArgs(
            enabled=backup_enabled,
            start_time=backup_start_time,
            point_in_time_recovery_enabled=True,
            transaction_log_retention_days=7,
            backup_retention_settings=gcp.sql.DatabaseInstanceSettingsBackupConfigurationBackupRetentionSettingsArgs(
                retained_backups=30,
                retention_unit="COUNT",
            ),
        ),
        "maintenance_window": gcp.sql.DatabaseInstanceSettingMaintenanceWindowArgs(
            day=maintenance_window_day,
            hour=maintenance_window_hour,
            update_track="stable",
        ),
        "database_flags": [
            gcp.sql.DatabaseInstanceSettingsDatabaseFlagArgs(
                name="max_connections",
                value="500",
            ),
            gcp.sql.DatabaseInstanceSettingsDatabaseFlagArgs(
                name="shared_buffers",
                value="4194304",  # 4GB in 8kB pages
            ),
            gcp.sql.DatabaseInstanceSettingsDatabaseFlagArgs(
                name="effective_cache_size",
                value="8388608",  # 8GB in 8kB pages
            ),
            gcp.sql.DatabaseInstanceSettingsDatabaseFlagArgs(
                name="maintenance_work_mem",
                value="524288",  # 512MB in kB
            ),
            gcp.sql.DatabaseInstanceSettingsDatabaseFlagArgs(
                name="checkpoint_completion_target",
                value="0.9",
            ),
            gcp.sql.DatabaseInstanceSettingsDatabaseFlagArgs(
                name="wal_buffers",
                value="16384",  # 16MB in kB
            ),
            gcp.sql.DatabaseInstanceSettingsDatabaseFlagArgs(
                name="default_statistics_target",
                value="100",
            ),
            gcp.sql.DatabaseInstanceSettingsDatabaseFlagArgs(
                name="random_page_cost",
                value="1.1",  # For SSD
            ),
            gcp.sql.DatabaseInstanceSettingsDatabaseFlagArgs(
                name="effective_io_concurrency",
                value="200",
            ),
            gcp.sql.DatabaseInstanceSettingsDatabaseFlagArgs(
                name="work_mem",
                value="10485",  # ~10MB in kB
            ),
            gcp.sql.DatabaseInstanceSettingsDatabaseFlagArgs(
                name="log_min_duration_statement",
                value="1000",  # Log queries > 1s
            ),
        ],
        "insights_config": (
            gcp.sql.DatabaseInstanceSettingsInsightsConfigArgs(
                query_insights_enabled=True,
                query_string_length=1024,
                record_application_tags=True,
                record_client_address=True,
            )
            if enable_insights
            else None
        ),
    }

    # Add KMS encryption if provided
    if kms_key_name:
        settings_args["disk_encryption_configuration"] = (
            gcp.sql.DatabaseInstanceSettingsDiskEncryptionConfigurationArgs(
                kms_key_name=kms_key_name
            )
        )

    # Create Cloud SQL instance
    db_instance = gcp.sql.DatabaseInstance(
        f"{name}-db",
        name=f"{name}-db",
        project=project,
        region=region,
        database_version=database_version,
        root_password=master_password,
        settings=gcp.sql.DatabaseInstanceSettingsArgs(**settings_args),
        deletion_protection=True,
    )

    # Create database
    database = gcp.sql.Database(
        f"{name}-database",
        name="cerebro",
        project=project,
        instance=db_instance.name,
        charset="UTF8",
        collation="en_US.UTF8",
    )

    # Create database user
    db_user = gcp.sql.User(
        f"{name}-user",
        name="cerebro",
        project=project,
        instance=db_instance.name,
        password=master_password,
    )

    return {
        "db_instance": db_instance,
        "database": database,
        "db_user": db_user,
        "connection_name": db_instance.connection_name,
        "private_ip": db_instance.private_ip_address,
        "public_ip": db_instance.public_ip_address,
        "self_link": db_instance.self_link,
    }


def create_read_replica(
    name: str,
    project: str,
    region: str,
    master_instance_name: pulumi.Output[str],
    tier: str = "db-custom-2-8192",  # Smaller for replica
    kms_key_name: pulumi.Output[str] = None,
) -> dict:
    """
    Create a read replica for scaling read traffic.

    Args:
        name: Replica name
        project: GCP project ID
        region: Region for replica (can differ from master)
        master_instance_name: Master instance name
        tier: Machine tier for replica
        kms_key_name: KMS key name for encryption

    Returns:
        Dictionary with replica resources
    """
    settings_args = {
        "tier": tier,
        "disk_autoresize": True,
        "ip_configuration": gcp.sql.DatabaseInstanceSettingsIpConfigurationArgs(
            ipv4_enabled=True,
            require_ssl=True,
        ),
    }

    if kms_key_name:
        settings_args["disk_encryption_configuration"] = (
            gcp.sql.DatabaseInstanceSettingsDiskEncryptionConfigurationArgs(
                kms_key_name=kms_key_name
            )
        )

    replica = gcp.sql.DatabaseInstance(
        f"{name}-replica",
        name=f"{name}-replica",
        project=project,
        region=region,
        database_version="POSTGRES_15",
        master_instance_name=master_instance_name,
        replica_configuration=gcp.sql.DatabaseInstanceReplicaConfigurationArgs(
            failover_target=False,
        ),
        settings=gcp.sql.DatabaseInstanceSettingsArgs(**settings_args),
    )

    return {
        "db_instance": replica,
        "connection_name": replica.connection_name,
        "private_ip": replica.private_ip_address,
        "public_ip": replica.public_ip_address,
    }