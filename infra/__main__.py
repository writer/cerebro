"""
Main Pulumi program for Cerebro infrastructure.

Deploys production-ready infrastructure on AWS or GCP.
"""
import pulumi
import pulumi_aws as aws
import pulumi_random as random

# Get configuration
config = pulumi.Config()
environment = config.get("environment") or "production"
domain = config.get("domain") or ""
secret_key = config.require_secret("secretKey")
api_min_instances = config.get_int("apiMinInstances") or 2
api_max_instances = config.get_int("apiMaxInstances") or 20
worker_min_instances = config.get_int("workerMinInstances") or 2
worker_max_instances = config.get_int("workerMaxInstances") or 50
container_image = config.get("containerImage") or "073877318660.dkr.ecr.us-east-1.amazonaws.com/cerebro:latest"
alb_internal = config.get_bool("albInternal")
if alb_internal is None:
    alb_internal = True


def _config_bool(key: str, default: bool) -> bool:
    value = config.get_bool(key)
    return default if value is None else value

# Import AWS modules
from aws import (
    networking,
    secrets,
    database,
    cache,
    kms,
    compute,
    load_balancer,
    monitoring,
)

# Create VPC and networking
vpc_cidr = "10.0.0.0/16"
vpc_stack = networking.create_vpc(
    name=f"cerebro-{environment}",
    cidr_block=vpc_cidr,
    availability_zones=2,
    enable_nat_gateway=True,
    enable_vpn_gateway=False,
    alb_ingress_cidrs=[vpc_cidr] if alb_internal else None,
)

# Create KMS key for encryption
kms_key = kms.create_kms_key(
    name=f"cerebro-{environment}",
    description="Cerebro encryption key",
)

# Generate database password if not provided
db_password = config.get_secret("dbPassword") or random.RandomPassword(
    "db-password",
    length=32,
    special=True,
    override_special="!#$%&*()-_=+[]{}<>:?",
).result

# Generate Redis password if not provided
redis_password = config.get_secret("redisPassword") or random.RandomPassword(
    "redis-password",
    length=32,
    special=False,
).result

# Store secrets in AWS Secrets Manager
cerebro_secrets = secrets.create_secrets(
    name=f"cerebro-{environment}",
    secrets={
        "SECRET_KEY": secret_key,
        "DB_PASSWORD": db_password,
        "REDIS_PASSWORD": redis_password,
        "KMS_KEY_ID": kms_key.id,
    },
)

# Create PostgreSQL database
database_stack = database.create_rds_postgres(
    name=f"cerebro-{environment}",
    vpc_id=vpc_stack["vpc_id"],
    subnet_ids=vpc_stack["database_subnet_ids"],
    security_group_id=vpc_stack["db_security_group_id"],
    instance_class=config.get("dbInstanceClass") or "db.r6g.xlarge",
    allocated_storage=config.get_int("dbStorageSize") or 500,
    master_password=db_password,
    multi_az=_config_bool("enableMultiAz", True),
    backup_retention_period=config.get_int("backupRetentionDays") or 30,
    kms_key_id=kms_key.arn,
    existing_db_instance_id=config.get("dbInstanceId"),
    existing_parameter_group_id=config.get("dbParameterGroupId"),
    existing_subnet_group_id=config.get("dbSubnetGroupId"),
)

# Create read replicas if enabled
read_replicas = []
if _config_bool("enableReadReplicas", True):
    replica_count = config.get_int("readReplicaCount") or 2
    for i in range(replica_count):
        existing_replica_id = config.get(f"dbReplica{i+1}Id")
        replica = database.create_read_replica(
            name=f"cerebro-{environment}-replica-{i+1}",
            source_db_instance=database_stack["db_instance"].identifier,
            instance_class="db.r6g.large",
            kms_key_id=kms_key.arn,
            existing_replica_id=existing_replica_id,
        )
        read_replicas.append(replica)

existing_redis_replication_group_id = config.get("redisReplicationGroupId")
existing_redis_parameter_group_id = config.get("redisParameterGroupId")
existing_redis_subnet_group_id = config.get("redisSubnetGroupId")

# Create Redis cluster
redis_stack = cache.create_elasticache_redis(
    name=f"cerebro-{environment}",
    vpc_id=vpc_stack["vpc_id"],
    subnet_ids=vpc_stack["database_subnet_ids"],
    security_group_id=vpc_stack["redis_security_group_id"],
    node_type=config.get("redisNodeType") or "cache.r6g.large",
    num_cache_nodes=3,
    auth_token=redis_password,
    at_rest_encryption_enabled=True,
    transit_encryption_enabled=True,
    kms_key_id=kms_key.arn,
    parameter_group_name=None if existing_redis_parameter_group_id else config.get("redisParameterGroupName"),
    existing_parameter_group_id=existing_redis_parameter_group_id,
    subnet_group_name=None if existing_redis_subnet_group_id else config.get("redisSubnetGroupName"),
    existing_subnet_group_id=existing_redis_subnet_group_id,
    existing_replication_group_id=existing_redis_replication_group_id,
)

# Create Application Load Balancer
alb_stack = load_balancer.create_application_load_balancer(
    name=f"cerebro-{environment}",
    vpc_id=vpc_stack["vpc_id"],
    subnet_ids=vpc_stack["private_subnet_ids"] if alb_internal else vpc_stack["public_subnet_ids"],
    security_group_id=vpc_stack["alb_security_group_id"],
    certificate_domain=domain or None,
    internal=alb_internal,
)

# Create ECS cluster and services
ecs_stack = compute.create_ecs_cluster(
    name=f"cerebro-{environment}",
    vpc_id=vpc_stack["vpc_id"],
    subnet_ids=vpc_stack["private_subnet_ids"],
    security_group_id=vpc_stack["app_security_group_id"],
    secrets_arn=cerebro_secrets.arn,
    database_endpoint=database_stack["endpoint"],
    redis_endpoint=redis_stack["primary_endpoint"],
    db_password=db_password,
    redis_password=redis_password,
    kms_key_id=kms_key.id,
    target_group_arn=alb_stack["target_group"].arn,
    container_image=container_image,
    api_min_instances=api_min_instances,
    api_max_instances=api_max_instances,
    worker_min_instances=worker_min_instances,
    worker_max_instances=worker_max_instances,
    log_retention_days=config.get_int("logRetentionDays") or 30,
    enable_flower=_config_bool("enableFlower", True),
)

# Create monitoring and alarms
monitoring_stack = monitoring.create_monitoring(
    name=f"cerebro-{environment}",
    alb_arn_suffix=alb_stack["alb"].arn_suffix,
    target_group_arn_suffix=alb_stack["target_group"].arn_suffix,
    ecs_cluster_name=ecs_stack["cluster"].name,
    ecs_service_names=[
        ecs_stack["api_service"].name,
        ecs_stack["worker_service"].name,
        ecs_stack["beat_service"].name,
    ],
    db_instance_id=database_stack["db_instance"].id,
    redis_cluster_id=redis_stack["replication_group"].id,
    log_retention_days=config.get_int("logRetentionDays") or 30,
)

# Export outputs
pulumi.export("vpc_id", vpc_stack["vpc_id"])
pulumi.export(
    "api_url",
    pulumi.Output.concat("https://", domain)
    if domain
    else pulumi.Output.concat("http://", alb_stack["alb"].dns_name),
)
pulumi.export("alb_dns_name", alb_stack["alb"].dns_name)
pulumi.export("db_endpoint", database_stack["endpoint"])
pulumi.export("redis_endpoint", redis_stack["primary_endpoint"])
pulumi.export("ecs_cluster_name", ecs_stack["cluster"].name)
pulumi.export("kms_key_id", kms_key.id)
pulumi.export("secrets_arn", cerebro_secrets.arn)

if _config_bool("enableFlower", True):
    pulumi.export("flower_url", pulumi.Output.concat(
        "http://", alb_stack["alb"].dns_name, ":5555"
    ))

if len(read_replicas) > 0:
    pulumi.export("read_replica_endpoints", [
        replica["endpoint"] for replica in read_replicas
    ])

# Export connection strings
pulumi.export("database_url", pulumi.Output.concat(
    "postgresql://cerebro:",
    db_password,
    "@",
    database_stack["endpoint"],
    "/cerebro"
))

pulumi.export("redis_url", pulumi.Output.concat(
    "rediss://:",
    redis_password,
    "@",
    redis_stack["primary_endpoint"],
    ":6379/0"
))

pulumi.export(
    "readme",
    pulumi.Output.all(
        api_url=pulumi.Output.concat(
            "https://",
            domain
        ) if domain else pulumi.Output.concat("http://", alb_stack["alb"].dns_name),
        alb_dns=alb_stack["alb"].dns_name,
        cluster=ecs_stack["cluster"].name,
        db_endpoint=database_stack["endpoint"],
        redis_endpoint=redis_stack["primary_endpoint"],
    ).apply(
        lambda args: (
            "# Cerebro Production Stack\n\n"
            "This stack deploys the Cerebro application onto AWS using Pulumi-managed "
            "infrastructure. Key endpoints and references:\n\n"
            f"- **API URL:** {args['api_url']}\n"
            f"- **ALB DNS:** {args['alb_dns']}\n"
            f"- **ECS Cluster:** {args['cluster']}\n"
            f"- **PostgreSQL Endpoint:** {args['db_endpoint']}\n"
            f"- **Redis Endpoint:** {args['redis_endpoint']}\n\n"
            "Deployment artifacts (container images, task definitions, and secrets) "
            "are managed automatically. Update `cerebro:containerImage` and rerun "
            "`pulumi up` to roll out new releases."
        )
    ),
)