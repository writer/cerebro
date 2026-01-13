"""
AWS RDS PostgreSQL database infrastructure.

Creates:
- RDS PostgreSQL instances with Multi-AZ support
- DB subnet groups
- Parameter groups for performance tuning
- Read replicas for scaling
- Automated backups and snapshots
"""

import pulumi
import pulumi_aws as aws
from typing import Optional


def create_rds_postgres(
    name: str,
    vpc_id: pulumi.Output[str],
    subnet_ids: list[pulumi.Output[str]],
    security_group_id: pulumi.Output[str],
    instance_class: str = "db.r6g.large",
    allocated_storage: int = 100,
    max_allocated_storage: int = 1000,
    engine_version: str = "17.6",
    database_name: str = "cerebro",
    master_username: str = "cerebro",
    master_password: pulumi.Output[str] = None,
    multi_az: bool = True,
    backup_retention_period: int = 30,
    backup_window: str = "03:00-04:00",
    maintenance_window: str = "Mon:04:00-Mon:05:00",
    kms_key_id: pulumi.Output[str] = None,
    performance_insights_enabled: bool = True,
    deletion_protection: bool = True,
    existing_db_instance_id: Optional[str] = None,
    existing_parameter_group_id: Optional[str] = None,
    existing_subnet_group_id: Optional[str] = None,
) -> dict:
    """
    Create RDS PostgreSQL database with production settings.

    Args:
        name: Database identifier prefix
        vpc_id: VPC ID
        subnet_ids: List of subnet IDs for DB subnet group
        security_group_id: Security group ID for database access
        instance_class: RDS instance class
        allocated_storage: Initial storage in GB
        max_allocated_storage: Max storage for autoscaling in GB
        engine_version: PostgreSQL version
        database_name: Initial database name
        master_username: Master username
        master_password: Master password (auto-generated if not provided)
        multi_az: Enable Multi-AZ for HA
        backup_retention_period: Automated backup retention in days
        backup_window: Preferred backup window (UTC)
        maintenance_window: Preferred maintenance window (UTC)
        kms_key_id: KMS key for encryption at rest
        performance_insights_enabled: Enable Performance Insights
        deletion_protection: Prevent accidental deletion

    Returns:
        Dictionary with database resources
    """
    # Generate password if not provided
    if master_password is None:
        import pulumi_random as random

        master_password = random.RandomPassword(
            f"{name}-db-password",
            length=32,
            special=True,
            override_special="!#$%&*()-_=+[]{}<>:?",
        ).result

    if existing_db_instance_id:
        db_instance = aws.rds.Instance.get(f"{name}-db", existing_db_instance_id)
        parameter_group = (
            aws.rds.ParameterGroup.get(
                f"{name}-db-params",
                existing_parameter_group_id,
            )
            if existing_parameter_group_id
            else None
        )
        subnet_group = (
            aws.rds.SubnetGroup.get(
                f"{name}-db-subnet-group",
                existing_subnet_group_id,
            )
            if existing_subnet_group_id
            else None
        )

        return {
            "db_instance": db_instance,
            "parameter_group": parameter_group,
            "subnet_group": subnet_group,
            "endpoint": db_instance.endpoint,
            "identifier": db_instance.identifier,
        }

    # Create DB subnet group
    subnet_group = aws.rds.SubnetGroup(
        f"{name}-db-subnet-group",
        subnet_ids=subnet_ids,
        tags={
            "Name": f"{name}-db-subnet-group",
        },
    )

    # Create parameter group for performance tuning
    parameter_group = aws.rds.ParameterGroup(
        f"{name}-db-params",
        family="postgres17",
        description=f"Parameter group for {name}",
        parameters=[
            # Connection settings
            aws.rds.ParameterGroupParameterArgs(
                name="max_connections",
                value="500",
                apply_method="pending-reboot",
            ),
            # Memory settings
            aws.rds.ParameterGroupParameterArgs(
                name="shared_buffers",
                value="{DBInstanceClassMemory/4096}",  # 25% of RAM
                apply_method="pending-reboot",
            ),
            aws.rds.ParameterGroupParameterArgs(
                name="effective_cache_size",
                value="{DBInstanceClassMemory/2048}",  # 50% of RAM
                apply_method="pending-reboot",
            ),
            # Write-ahead log
            aws.rds.ParameterGroupParameterArgs(
                name="wal_buffers",
                value="16384",  # 16MB
                apply_method="pending-reboot",
            ),
            # Query tuning
            aws.rds.ParameterGroupParameterArgs(
                name="random_page_cost",
                value="1.1",  # For SSD storage
                apply_method="pending-reboot",
            ),
            # Logging
            aws.rds.ParameterGroupParameterArgs(
                name="log_min_duration_statement",
                value="1000",  # Log queries > 1s
                apply_method="pending-reboot",
            ),
            aws.rds.ParameterGroupParameterArgs(
                name="log_connections",
                value="1",
                apply_method="pending-reboot",
            ),
            aws.rds.ParameterGroupParameterArgs(
                name="log_disconnections",
                value="1",
                apply_method="pending-reboot",
            ),
        ],
        tags={
            "Name": f"{name}-db-params",
        },
    )

    # Create RDS instance
    db_kwargs = {
        "identifier": name,
        "engine": "postgres",
        "engine_version": engine_version,
        "instance_class": instance_class,
        "allocated_storage": allocated_storage,
        "max_allocated_storage": max_allocated_storage,
        "storage_type": "gp3",
        "storage_encrypted": True,
        "db_name": database_name,
        "username": master_username,
        "password": master_password,
        "db_subnet_group_name": subnet_group.name,
        "vpc_security_group_ids": [security_group_id],
        "parameter_group_name": parameter_group.name,
        "multi_az": multi_az,
        "backup_retention_period": backup_retention_period,
        "backup_window": backup_window,
        "maintenance_window": maintenance_window,
        "auto_minor_version_upgrade": True,
        "deletion_protection": deletion_protection,
        "skip_final_snapshot": False,
        "final_snapshot_identifier": f"{name}-final-snapshot",
        "copy_tags_to_snapshot": True,
        "enabled_cloudwatch_logs_exports": ["postgresql", "upgrade"],
        "performance_insights_enabled": performance_insights_enabled,
        "tags": {
            "Name": name,
            "ManagedBy": "Pulumi",
        },
    }

    # Add KMS encryption if provided
    if kms_key_id:
        db_kwargs["kms_key_id"] = kms_key_id

    # Add Performance Insights retention if enabled
    if performance_insights_enabled:
        db_kwargs["performance_insights_retention_period"] = 7  # days

    db_instance = aws.rds.Instance(
        f"{name}-db",
        **db_kwargs,
    )

    return {
        "db_instance": db_instance,
        "subnet_group": subnet_group,
        "parameter_group": parameter_group,
        "endpoint": db_instance.endpoint,
        "address": db_instance.address,
        "port": db_instance.port,
    }


def create_read_replica(
    name: str,
    source_db_instance: pulumi.Output[str],
    instance_class: str = "db.r6g.large",
    kms_key_id: pulumi.Output[str] = None,
    performance_insights_enabled: bool = True,
    existing_replica_id: Optional[str] = None,
) -> dict:
    """
    Create a read replica for scaling read traffic.

    Args:
        name: Replica identifier
        source_db_instance: Source DB instance identifier
        instance_class: Replica instance class
        kms_key_id: KMS key for encryption
        performance_insights_enabled: Enable Performance Insights

    Returns:
        Dictionary with replica resources
    """
    if existing_replica_id:
        replica = aws.rds.Instance.get(f"{name}-replica", existing_replica_id)
        return {
            "db_instance": replica,
            "endpoint": replica.endpoint,
            "address": replica.address,
        }

    replica_kwargs = {
        "identifier": name,
        "replicate_source_db": source_db_instance,
        "instance_class": instance_class,
        "auto_minor_version_upgrade": True,
        "publicly_accessible": False,
        "performance_insights_enabled": performance_insights_enabled,
        "tags": {
            "Name": name,
            "Type": "ReadReplica",
            "ManagedBy": "Pulumi",
        },
    }

    if kms_key_id:
        replica_kwargs["kms_key_id"] = kms_key_id

    if performance_insights_enabled:
        replica_kwargs["performance_insights_retention_period"] = 7

    replica = aws.rds.Instance(
        f"{name}-replica",
        **replica_kwargs,
    )

    return {
        "db_instance": replica,
        "endpoint": replica.endpoint,
        "address": replica.address,
    }
