"""
Postgres state store for the Cerebro rewrite.
"""

from urllib.parse import quote

import pulumi
import pulumi_aws as aws
import pulumi_random as random


def create_postgres(
    name: str,
    vpc_id: pulumi.Input[str],
    subnet_ids: list[pulumi.Input[str]],
    app_security_group_id: pulumi.Input[str],
    kms_key_arn: pulumi.Input[str],
    secret_name: str,
    instance_class: str = "db.t4g.micro",
    allocated_storage: int = 20,
    storage_type: str = "gp3",
    max_allocated_storage: int | None = None,
    iops: int | None = None,
    storage_throughput: int | None = None,
    backup_retention_days: int = 7,
    deletion_protection: bool = False,
    multi_az: bool = False,
    apply_immediately: bool = True,
    final_snapshot_identifier: str | None = None,
) -> dict:
    """Create the RDS Postgres database and expose its DSN through Secrets Manager."""
    security_group = aws.ec2.SecurityGroup(
        f"{name}-postgres-sg",
        vpc_id=vpc_id,
        description=f"Postgres access for {name}",
        ingress=[
            aws.ec2.SecurityGroupIngressArgs(
                protocol="tcp",
                from_port=5432,
                to_port=5432,
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
        tags={"Name": f"{name}-postgres-sg"},
    )

    subnet_group = aws.rds.SubnetGroup(
        f"{name}-postgres-subnets",
        subnet_ids=subnet_ids,
        tags={"Name": f"{name}-postgres-subnets"},
    )

    password = random.RandomPassword(
        f"{name}-postgres-password",
        length=32,
        special=True,
        override_special="!#$%&*+-_=?:",
    )

    instance = aws.rds.Instance(
        f"{name}-postgres",
        identifier=f"{name}-postgres",
        engine="postgres",
        engine_version="16.4",
        instance_class=instance_class,
        allocated_storage=allocated_storage,
        **_postgres_storage_args(
            allocated_storage=allocated_storage,
            storage_type=storage_type,
            max_allocated_storage=max_allocated_storage,
            iops=iops,
            storage_throughput=storage_throughput,
        ),
        db_name="cerebro",
        username="cerebro",
        password=password.result,
        db_subnet_group_name=subnet_group.name,
        vpc_security_group_ids=[security_group.id],
        port=5432,
        storage_encrypted=True,
        kms_key_id=kms_key_arn,
        publicly_accessible=False,
        backup_retention_period=backup_retention_days,
        deletion_protection=deletion_protection,
        multi_az=multi_az,
        skip_final_snapshot=not deletion_protection,
        final_snapshot_identifier=final_snapshot_identifier or (f"{name}-postgres-final" if deletion_protection else None),
        apply_immediately=apply_immediately,
        tags={"Name": f"{name}-postgres"},
    )

    secret = aws.secretsmanager.Secret(
        f"{name}-postgres-dsn",
        name=secret_name,
        kms_key_id=kms_key_arn,
        tags={"Name": secret_name},
    )

    dsn = pulumi.Output.all(password.result, instance.address).apply(
        lambda args: f"postgres://cerebro:{quote(args[0], safe='')}@{args[1]}:5432/cerebro?sslmode=require&connect_timeout=15"
    )
    secret_version = aws.secretsmanager.SecretVersion(
        f"{name}-postgres-dsn-version",
        secret_id=secret.id,
        secret_string=dsn,
    )

    return {
        "instance": instance,
        "security_group": security_group,
        "secret": secret,
        "secret_version": secret_version,
    }


def _postgres_storage_args(
    *,
    allocated_storage: int,
    storage_type: str,
    max_allocated_storage: int | None = None,
    iops: int | None = None,
    storage_throughput: int | None = None,
) -> dict:
    if allocated_storage <= 0:
        raise ValueError("allocated_storage must be positive")
    if max_allocated_storage is None:
        max_allocated_storage = max(allocated_storage * 2, allocated_storage + 20)
    if max_allocated_storage < allocated_storage:
        raise ValueError("max_allocated_storage must be >= allocated_storage")

    args = {
        "storage_type": (storage_type or "gp3").strip() or "gp3",
        "max_allocated_storage": max_allocated_storage,
    }
    if iops is not None:
        args["iops"] = iops
    if storage_throughput is not None:
        args["storage_throughput"] = storage_throughput
    return args
