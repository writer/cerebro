"""
Main Pulumi program for Cerebro infrastructure on GCP.

Deploys production-ready infrastructure on Google Cloud Platform.
"""
import pulumi
import pulumi_gcp as gcp
import pulumi_random as random

# Get configuration
config = pulumi.Config()
project = config.require("gcp:project")
region = config.get("gcp:region") or "us-central1"
environment = config.get("environment") or "production"
domain = config.require("domain")
secret_key = config.require_secret("secretKey")
api_min_instances = config.get_int("apiMinInstances") or 2
api_max_instances = config.get_int("apiMaxInstances") or 20
worker_min_instances = config.get_int("workerMinInstances") or 1
worker_max_instances = config.get_int("workerMaxInstances") or 50

# Import GCP modules
from gcp import (
    networking,
    kms,
    secrets,
    database,
    cache,
    compute,
    load_balancer,
    monitoring,
)

# Create VPC and networking
vpc_stack = networking.create_vpc(
    name=f"cerebro-{environment}",
    project=project,
    region=region,
    enable_cloud_nat=True,
)

# Create KMS key for encryption
kms_stack = kms.create_kms_key(
    name=f"cerebro-{environment}",
    project=project,
    location=region,
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

# Store secrets in Secret Manager
secret_resources = secrets.create_secrets(
    name=f"cerebro-{environment}",
    project=project,
    secrets={
        "SECRET_KEY": secret_key,
        "DB_PASSWORD": db_password,
        "REDIS_PASSWORD": redis_password,
        "KMS_KEY_ID": kms_stack["crypto_key_id"],
    },
    kms_key_name=kms_stack["crypto_key_id"],
)

# Create Cloud SQL PostgreSQL database
database_stack = database.create_cloud_sql_postgres(
    name=f"cerebro-{environment}",
    project=project,
    region=region,
    network_id=vpc_stack["network_id"],
    tier=config.get("dbTier") or "db-custom-4-16384",
    disk_size=config.get_int("dbStorageSize") or 100,
    master_password=db_password,
    availability_type="REGIONAL" if config.get_bool("enableMultiAz") else "ZONAL",
    kms_key_name=kms_stack["crypto_key_id"],
)

# Create read replicas if enabled
read_replicas = []
if config.get_bool("enableReadReplicas"):
    replica_count = config.get_int("readReplicaCount") or 2
    for i in range(replica_count):
        replica = database.create_read_replica(
            name=f"cerebro-{environment}-replica-{i+1}",
            project=project,
            region=region,
            master_instance_name=database_stack["db_instance"].name,
            tier="db-custom-2-8192",
            kms_key_name=kms_stack["crypto_key_id"],
        )
        read_replicas.append(replica)

# Create Memorystore Redis
redis_stack = cache.create_memorystore_redis(
    name=f"cerebro-{environment}",
    project=project,
    region=region,
    network_id=vpc_stack["network_id"],
    tier="STANDARD_HA" if config.get_bool("enableMultiAz") else "BASIC",
    memory_size_gb=config.get_int("redisMemoryGb") or 5,
    auth_string=redis_password,
)

# Get container image from config or use default
container_image = config.get("containerImage") or f"gcr.io/{project}/cerebro:latest"

# Create Cloud Run services
compute_stack = compute.create_cloud_run_services(
    name=f"cerebro-{environment}",
    project=project,
    region=region,
    container_image=container_image,
    network_id=vpc_stack["network_id"],
    subnet_id=vpc_stack["private_subnet_id"],
    database_connection_name=database_stack["connection_name"],
    redis_host=redis_stack["host"],
    kms_key_id=kms_stack["crypto_key_id"],
    secret_ids={
        "SECRET_KEY": secret_resources["SECRET_KEY"].secret_id,
        "DB_PASSWORD": secret_resources["DB_PASSWORD"].secret_id,
        "REDIS_PASSWORD": secret_resources["REDIS_PASSWORD"].secret_id,
    },
    api_min_instances=api_min_instances,
    api_max_instances=api_max_instances,
    worker_min_instances=worker_min_instances,
    worker_max_instances=worker_max_instances,
)

# Create HTTPS Load Balancer
lb_stack = load_balancer.create_https_load_balancer(
    name=f"cerebro-{environment}",
    project=project,
    cloud_run_service_url=compute_stack["api_url"],
    domain=domain,
    enable_cdn=config.get_bool("enableCdn") or False,
)

# Create monitoring and alerts
monitoring_stack = monitoring.create_monitoring(
    name=f"cerebro-{environment}",
    project=project,
    api_service_name=compute_stack["api_service"].name,
    worker_service_name=compute_stack["worker_service"].name,
    db_instance_name=database_stack["db_instance"].name,
    redis_instance_name=redis_stack["redis_instance"].name,
    load_balancer_url=domain,
    alert_email=config.get("alertEmail"),
)

# Export outputs
pulumi.export("project_id", project)
pulumi.export("region", region)
pulumi.export("network_id", vpc_stack["network_id"])
pulumi.export("api_url", pulumi.Output.concat("https://", domain))
pulumi.export("api_service_url", compute_stack["api_url"])
pulumi.export("load_balancer_ip", lb_stack["ip_address"])
pulumi.export("db_connection_name", database_stack["connection_name"])
pulumi.export("db_private_ip", database_stack["private_ip"])
pulumi.export("redis_host", redis_stack["host"])
pulumi.export("redis_port", redis_stack["port"])
pulumi.export("kms_key_id", kms_stack["crypto_key_id"])

if len(read_replicas) > 0:
    pulumi.export(
        "read_replica_ips",
        [replica["private_ip"] for replica in read_replicas],
    )

# Export connection strings
pulumi.export(
    "database_url",
    pulumi.Output.concat(
        "postgresql://cerebro:",
        db_password,
        "@",
        database_stack["private_ip"],
        "/cerebro",
    ),
)

pulumi.export(
    "redis_url",
    pulumi.Output.concat(
        "rediss://:",
        redis_password,
        "@",
        redis_stack["host"],
        ":",
        redis_stack["port"],
        "/0",
    ),
)