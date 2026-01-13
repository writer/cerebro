"""
Main Pulumi program for Cerebro infrastructure.

Deploys production-ready infrastructure on AWS or GCP.
"""

import pulumi
import pulumi_aws as aws
import pulumi_random as random

# Get configuration
config = pulumi.Config()


def _config_bool(key: str, default: bool) -> bool:
    value = config.get_bool(key)
    return default if value is None else value


def _config_int(key: str, default: int) -> int:
    value = config.get_int(key)
    return default if value is None else value


environment = config.get("environment") or "production"
domain = config.get("domain") or ""
secret_key = config.require_secret("secretKey")
api_min_instances = _config_int("apiMinInstances", 2)
api_max_instances = _config_int("apiMaxInstances", 20)
worker_min_instances = _config_int("workerMinInstances", 2)
worker_max_instances = _config_int("workerMaxInstances", 50)
api_cpu = _config_int("apiCpu", 1024)
api_memory = _config_int("apiMemory", 2048)
worker_cpu = _config_int("workerCpu", 2048)
worker_memory = _config_int("workerMemory", 4096)
container_image = (
    config.get("containerImage")
    or "073877318660.dkr.ecr.us-east-1.amazonaws.com/cerebro:latest"
)
alb_internal = config.get_bool("albInternal")
if alb_internal is None:
    alb_internal = True

# Feature flags for production hardening
enable_waf = _config_bool("enableWaf", False)
waf_rate_limit = _config_int("wafRateLimit", 2000)
enable_backup = _config_bool("enableBackup", False)
backup_retention_days = _config_int("backupRetentionDays", 35)
enable_blue_green = _config_bool("enableBlueGreen", False)
blue_green_termination_wait = _config_int("blueGreenTerminationWait", 5)

# Import AWS modules
from aws import (
    backup,
    blue_green,
    cache,
    compute,
    dynamodb,
    kms,
    load_balancer,
    monitoring,
    networking,
    secrets,
    waf,
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

# Generate Redis password if not provided
redis_password = (
    config.get_secret("redisPassword")
    or random.RandomPassword(
        "redis-password",
        length=32,
        special=False,
    ).result
)

automation_org_id = config.get("automationOrgId") or ""
session_base_url = config.get("sessionBaseUrl") or ""
autonomy_slack_webhook = config.get_secret("autonomySlackWebhook")
if autonomy_slack_webhook is None:
    autonomy_slack_webhook = pulumi.Output.secret("")

# Store secrets in AWS Secrets Manager
cerebro_secrets = secrets.create_secrets(
    name=f"cerebro-{environment}",
    secrets={
        "SECRET_KEY": secret_key,
        "REDIS_PASSWORD": redis_password,
        "KMS_KEY_ID": kms_key.id,
        "CEREBRO_AUTOMATION_ORG_ID": automation_org_id,
        "CEREBRO_SESSION_BASE_URL": session_base_url,
        "AUTONOMY_SLACK_WEBHOOK": autonomy_slack_webhook,
    },
)

# Create DynamoDB tables
dynamodb_stack = dynamodb.create_dynamodb_tables(
    name="cerebro",
    environment=environment,
    kms_key_arn=kms_key.arn,
    enable_point_in_time_recovery=True,
    enable_streams=True,
    audit_ttl_enabled=True,
    tags={
        "Project": "Cerebro",
    },
)

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
    parameter_group_name=(
        None
        if existing_redis_parameter_group_id
        else config.get("redisParameterGroupName")
    ),
    existing_parameter_group_id=existing_redis_parameter_group_id,
    subnet_group_name=(
        None if existing_redis_subnet_group_id else config.get("redisSubnetGroupName")
    ),
    existing_subnet_group_id=existing_redis_subnet_group_id,
    existing_replication_group_id=existing_redis_replication_group_id,
)

# Create Application Load Balancer
alb_stack = load_balancer.create_application_load_balancer(
    name=f"cerebro-{environment}",
    vpc_id=vpc_stack["vpc_id"],
    subnet_ids=(
        vpc_stack["private_subnet_ids"]
        if alb_internal
        else vpc_stack["public_subnet_ids"]
    ),
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
    dynamodb_table_arns=[
        dynamodb_stack["core_table_arn"],
        dynamodb_stack["audit_table_arn"],
        dynamodb_stack["agents_table_arn"],
        dynamodb_stack["notifications_table_arn"],
        dynamodb_stack["users_table_arn"],
    ],
    dynamodb_core_table=dynamodb_stack["core_table_name"],
    dynamodb_audit_table=dynamodb_stack["audit_table_name"],
    dynamodb_agents_table=dynamodb_stack["agents_table_name"],
    dynamodb_notifications_table=dynamodb_stack["notifications_table_name"],
    dynamodb_users_table=dynamodb_stack["users_table_name"],
    redis_endpoint=redis_stack["primary_endpoint"],
    redis_password=redis_password,
    kms_key_id=kms_key.id,
    target_group_arn=alb_stack["target_group"].arn,
    container_image=container_image,
    api_min_instances=api_min_instances,
    api_max_instances=api_max_instances,
    api_cpu=api_cpu,
    api_memory=api_memory,
    worker_min_instances=worker_min_instances,
    worker_max_instances=worker_max_instances,
    worker_cpu=worker_cpu,
    worker_memory=worker_memory,
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
    dynamodb_table_names=[
        dynamodb_stack["core_table_name"],
        dynamodb_stack["audit_table_name"],
        dynamodb_stack["agents_table_name"],
        dynamodb_stack["notifications_table_name"],
        dynamodb_stack["users_table_name"],
    ],
    redis_cluster_id=redis_stack["replication_group"].id,
    log_retention_days=config.get_int("logRetentionDays") or 30,
)

# WAF - Web Application Firewall
waf_stack = None
if enable_waf:
    waf_stack = waf.create_waf(
        name=f"cerebro-{environment}",
        alb_arn=alb_stack["alb"].arn,
        rate_limit=waf_rate_limit,
        tags={
            "Project": "Cerebro",
            "Environment": environment,
        },
    )

# Automated Backups for DynamoDB tables
backup_stack = None
if enable_backup:
    backup_stack = backup.create_backup_plan(
        name=f"cerebro-{environment}",
        resource_arns=[
            dynamodb_stack["core_table_arn"],
            dynamodb_stack["audit_table_arn"],
            dynamodb_stack["agents_table_arn"],
            dynamodb_stack["notifications_table_arn"],
            dynamodb_stack["users_table_arn"],
        ],
        backup_retention_days=backup_retention_days,
        tags={
            "Project": "Cerebro",
            "Environment": environment,
        },
    )

# Blue-Green Deployment for ECS API service
blue_green_stack = None
if enable_blue_green:
    # Create green target group for blue-green deployments
    green_target_group = blue_green.create_green_target_group(
        name=f"cerebro-{environment}-api",
        vpc_id=vpc_stack["vpc_id"],
        container_port=8000,
        health_check_path="/health",
        tags={
            "Project": "Cerebro",
            "Environment": environment,
        },
    )

    blue_green_stack = blue_green.create_blue_green_deployment(
        name=f"cerebro-{environment}-api",
        cluster_name=ecs_stack["cluster"].name,
        service_name=ecs_stack["api_service"].name,
        listener_arn=alb_stack["listener"].arn,
        target_group_names=(
            alb_stack["target_group"].name,
            green_target_group.name,
        ),
        termination_wait_time_minutes=blue_green_termination_wait,
        tags={
            "Project": "Cerebro",
            "Environment": environment,
        },
    )

# Export outputs
pulumi.export("vpc_id", vpc_stack["vpc_id"])
pulumi.export(
    "api_url",
    (
        pulumi.Output.concat("https://", domain)
        if domain
        else pulumi.Output.concat("http://", alb_stack["alb"].dns_name)
    ),
)
pulumi.export("alb_dns_name", alb_stack["alb"].dns_name)
pulumi.export("redis_endpoint", redis_stack["primary_endpoint"])
pulumi.export("ecs_cluster_name", ecs_stack["cluster"].name)
pulumi.export("kms_key_id", kms_key.id)
pulumi.export("secrets_arn", cerebro_secrets.arn)

# Export DynamoDB table names
pulumi.export("dynamodb_core_table", dynamodb_stack["core_table_name"])
pulumi.export("dynamodb_audit_table", dynamodb_stack["audit_table_name"])
pulumi.export("dynamodb_agents_table", dynamodb_stack["agents_table_name"])
pulumi.export(
    "dynamodb_notifications_table", dynamodb_stack["notifications_table_name"]
)
pulumi.export("dynamodb_users_table", dynamodb_stack["users_table_name"])

# Export DynamoDB Stream ARNs (for Lambda triggers)
pulumi.export("dynamodb_core_stream_arn", dynamodb_stack["core_stream_arn"])
pulumi.export("dynamodb_audit_stream_arn", dynamodb_stack["audit_stream_arn"])

if _config_bool("enableFlower", True):
    pulumi.export(
        "flower_url",
        pulumi.Output.concat("http://", alb_stack["alb"].dns_name, ":5555"),
    )

# Export Redis connection string
pulumi.export(
    "redis_url",
    pulumi.Output.concat(
        "rediss://:", redis_password, "@", redis_stack["primary_endpoint"], ":6379/0"
    ),
)

# Export new production hardening features
if waf_stack:
    pulumi.export("waf_web_acl_arn", waf_stack["web_acl"].arn)

if backup_stack:
    pulumi.export("backup_vault_arn", backup_stack["vault"].arn)
    pulumi.export("backup_plan_id", backup_stack["plan"].id)

if blue_green_stack:
    pulumi.export("codedeploy_app_name", blue_green_stack["application"].name)
    pulumi.export("codedeploy_deployment_group", blue_green_stack["deployment_group"].deployment_group_name)

pulumi.export(
    "readme",
    pulumi.Output.all(
        api_url=(
            pulumi.Output.concat("https://", domain)
            if domain
            else pulumi.Output.concat("http://", alb_stack["alb"].dns_name)
        ),
        alb_dns=alb_stack["alb"].dns_name,
        cluster=ecs_stack["cluster"].name,
        core_table=dynamodb_stack["core_table_name"],
        audit_table=dynamodb_stack["audit_table_name"],
        agents_table=dynamodb_stack["agents_table_name"],
        redis_endpoint=redis_stack["primary_endpoint"],
    ).apply(
        lambda args: (
            "# Cerebro Production Stack\n\n"
            "This stack deploys the Cerebro application onto AWS using Pulumi-managed "
            "infrastructure. Key endpoints and references:\n\n"
            f"- **API URL:** {args['api_url']}\n"
            f"- **ALB DNS:** {args['alb_dns']}\n"
            f"- **ECS Cluster:** {args['cluster']}\n"
            f"- **DynamoDB Core Table:** {args['core_table']}\n"
            f"- **DynamoDB Audit Table:** {args['audit_table']}\n"
            f"- **DynamoDB Agents Table:** {args['agents_table']}\n"
            f"- **Redis Endpoint:** {args['redis_endpoint']}\n\n"
            "Deployment artifacts (container images, task definitions, and secrets) "
            "are managed automatically. Update `cerebro:containerImage` and rerun "
            "`pulumi up` to roll out new releases."
        )
    ),
)
