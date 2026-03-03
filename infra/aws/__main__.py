"""
Pulumi infrastructure for Cerebro Security Platform (Go).

Deploys:
- VPC with public/private subnets
- ECS Fargate cluster running the Go API
- Application Load Balancer
- Secrets Manager for credentials
- KMS for encryption
- CloudWatch for logging/monitoring
- Optional WAF for API protection
"""

import pulumi
import pulumi_aws as aws

import compute
import ecr
import infisical
import jobs
import kms
import load_balancer
import monitoring
import networking
import tailscale as ts
import waf

# Configuration
config = pulumi.Config()

# Derive environment from stack name to maintain stable resource names
# Stack "go-prod" -> environment "go-production"
# Stack "go-dev" -> environment "go-dev"
# Falls back to config or "production" if not matching pattern
def _get_environment() -> str:
    if config.get("environment"):
        return config.get("environment")
    stack = pulumi.get_stack()
    if stack == "go-prod":
        return "go-production"
    elif stack.startswith("go-"):
        return stack.replace("-prod", "-production")
    return "production"

environment = _get_environment()
domain = config.get("domain") or ""

# Container image - default to ECR latest if not provided
container_image = config.get("containerImage") or "073877318660.dkr.ecr.us-east-1.amazonaws.com/cerebro:latest"

alb_internal = config.get_bool("albInternal")
if alb_internal is None:
    alb_internal = True


def _config_int(key: str, default: int) -> int:
    value = config.get_int(key)
    return default if value is None else value


def _config_bool(key: str, default: bool) -> bool:
    value = config.get_bool(key)
    return default if value is None else value


# ECS sizing
api_cpu = _config_int("apiCpu", 1024)
api_memory = _config_int("apiMemory", 2048)
api_min_instances = _config_int("apiMinInstances", 2)
api_max_instances = _config_int("apiMaxInstances", 10)

# Feature flags
enable_waf = _config_bool("enableWaf", True)
# Environment-aware defaults: production gets more secure settings
is_production = "prod" in environment.lower()
enable_alb_access_logs = _config_bool("enableAlbAccessLogs", is_production)
enable_alb_deletion_protection = _config_bool("enableAlbDeletionProtection", is_production)
enable_kms_log_encryption = _config_bool("enableKmsLogEncryption", is_production)
nat_gateway_per_az = _config_bool("natGatewayPerAz", is_production)
log_retention_days = _config_int("logRetentionDays", 30)

# Slack integration for job alarms
slack_channel_id = config.get("slackAlarmChannelId")
slack_workspace_id = config.get("slackWorkspaceId")

# Infisical integration
enable_infisical = _config_bool("enableInfisicalSyncRole", False)
infisical_principal_arn = config.get("infisicalAssumeRolePrincipalArn")
infisical_external_id = config.get("infisicalExternalId")

# External secrets (Infisical-synced) - secrets are read from AWS Secrets Manager
external_secrets_prefix = config.get("externalSecretsPrefix") or f"cerebro-{environment}"

# Tailscale subnet router for internal access
enable_tailscale = _config_bool("enableTailscale", False)
tailscale_hostname = config.get("tailscaleHostname") or f"cerebro-{environment}"
tailscale_advertise_routes = config.get_object("tailscaleAdvertiseRoutes") or []

# Distributed job workers
enable_workers = _config_bool("enableWorkers", True)
worker_cpu = _config_int("workerCpu", 512)
worker_memory = _config_int("workerMemory", 1024)
worker_min_instances = _config_int("workerMinInstances", 1)
worker_max_instances = _config_int("workerMaxInstances", 10)
worker_concurrency = _config_int("workerConcurrency", 4)

# Existing VPC configuration (optional - if set, skips VPC creation)
use_existing_vpc = _config_bool("useExistingVpc", False)
existing_vpc_id = config.get("vpcId")
existing_private_subnet_ids = config.get_object("privateSubnetIds") or []
existing_public_subnet_ids = config.get_object("publicSubnetIds") or []
existing_vpc_cidr = config.get("vpcCidr") or "10.0.0.0/16"

# =============================================================================
# KMS (must come before networking for flow logs encryption)
# =============================================================================

kms_key = kms.create_kms_key(
    name=f"cerebro-{environment}",
    description="Cerebro encryption key",
)

# Optional KMS key for CloudWatch Logs encryption
logs_kms_key = None
if enable_kms_log_encryption:
    logs_kms_key = kms.create_cloudwatch_logs_key(
        name=f"cerebro-{environment}",
    )

# =============================================================================
# NETWORKING
# =============================================================================

if use_existing_vpc and existing_vpc_id:
    # Use existing VPC - only create security groups
    vpc_cidr = existing_vpc_cidr
    vpc_stack = networking.use_existing_vpc(
        name=f"cerebro-{environment}",
        vpc_id=existing_vpc_id,
        public_subnet_ids=existing_public_subnet_ids,
        private_subnet_ids=existing_private_subnet_ids,
        alb_ingress_cidrs=[vpc_cidr] if alb_internal else None,
    )
else:
    # Create new VPC with all networking components
    vpc_cidr = "10.0.0.0/16"
    vpc_stack = networking.create_vpc(
        name=f"cerebro-{environment}",
        cidr_block=vpc_cidr,
        availability_zones=2,
        enable_nat_gateway=True,
        nat_gateway_per_az=nat_gateway_per_az,
        alb_ingress_cidrs=[vpc_cidr] if alb_internal else None,
        enable_flow_logs=True,
        flow_logs_retention_days=log_retention_days,
        flow_logs_kms_key_arn=logs_kms_key["key_arn"] if logs_kms_key else None,
    )

# =============================================================================
# SECRETS
# =============================================================================

# Infisical-synced secrets (each key is a dedicated secret)
# Snowflake key-pair auth (required)
secret_keys = [
    "SNOWFLAKE_PRIVATE_KEY",
    "SNOWFLAKE_ACCOUNT",
    "SNOWFLAKE_USER",
]

optional_secrets = [
    "API_KEYS",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "SLACK_WEBHOOK_URL",
    "JIRA_API_TOKEN",
    "LINEAR_API_KEY",
]
for key in optional_secrets:
    if config.get_bool(f"enable{key.replace('_', ' ').title().replace(' ', '')}"):
        secret_keys.append(key)

# =============================================================================
# LOAD BALANCER
# =============================================================================

alb_stack = load_balancer.create_alb(
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
    health_check_path="/health",
    container_port=8080,
    enable_deletion_protection=enable_alb_deletion_protection,
    enable_access_logs=enable_alb_access_logs,
)

# =============================================================================
# DISTRIBUTED JOB QUEUE
# =============================================================================

job_queue_stack = jobs.create_job_queue(
    name=f"cerebro-{environment}",
    kms_key_arn=kms_key["key_arn"],
    visibility_timeout=60,
    message_retention=1209600,  # 14 days
)

job_store_stack = jobs.create_job_store(
    name=f"cerebro-{environment}",
    kms_key_arn=kms_key["key_arn"],
)

# =============================================================================
# ECS COMPUTE
# =============================================================================

# Environment variables for the Go app
app_environment = {
    "API_PORT": "8080",
    "LOG_LEVEL": "info",
    "CEDAR_POLICIES_PATH": "/app/policies",
    "SNOWFLAKE_DATABASE": config.get("snowflakeDatabase") or "CEREBRO",
    "SNOWFLAKE_SCHEMA": config.get("snowflakeSchema") or "CEREBRO",
    "JOB_REGION": aws.get_region().region,
}

# Optional non-secret config
if config.get("jiraBaseUrl"):
    app_environment["JIRA_BASE_URL"] = config.get("jiraBaseUrl")
if config.get("jiraEmail"):
    app_environment["JIRA_EMAIL"] = config.get("jiraEmail")
if config.get("jiraProject"):
    app_environment["JIRA_PROJECT"] = config.get("jiraProject")
if config.get("linearTeamId"):
    app_environment["LINEAR_TEAM_ID"] = config.get("linearTeamId")

# GCP WIF (optional - enables AWS->GCP federated auth for GCP scans)
if config.get("gcpWifAudience"):
    app_environment["CEREBRO_GCP_WIF_AUDIENCE"] = config.get("gcpWifAudience")
if config.get("gcpImpersonateServiceAccount"):
    app_environment["CEREBRO_GCP_IMPERSONATE_SERVICE_ACCOUNT"] = config.get("gcpImpersonateServiceAccount")
if config.get("gcpImpersonateDelegates"):
    app_environment["CEREBRO_GCP_IMPERSONATE_DELEGATES"] = config.get("gcpImpersonateDelegates")

# Job queue config added to environment via Pulumi outputs
# Note: These are Output objects, handled by compute module

ecs_stack = compute.create_ecs_cluster(
    name=f"cerebro-{environment}",
    vpc_id=vpc_stack["vpc_id"],
    subnet_ids=vpc_stack["private_subnet_ids"],
    security_group_id=vpc_stack["app_security_group_id"],
    kms_key_id=kms_key["key_id"],
    target_group_arn=alb_stack["target_group"].arn,
    container_image=container_image,
    api_cpu=api_cpu,
    api_memory=api_memory,
    api_min_instances=api_min_instances,
    api_max_instances=api_max_instances,
    log_retention_days=log_retention_days,
    environment=app_environment,
    secret_keys=secret_keys,
    external_secrets_prefix=external_secrets_prefix,
    job_queue_url=job_queue_stack["queue_url"],
    job_queue_arn=job_queue_stack["queue_arn"],
    job_table_name=job_store_stack["table_name"],
    log_group_kms_key_id=logs_kms_key["key_arn"] if logs_kms_key else None,
)

# Worker service
worker_stack = None
if enable_workers:
    worker_stack = jobs.create_worker_service(
        name=f"cerebro-{environment}",
        cluster_arn=ecs_stack["cluster"].arn,
        subnet_ids=vpc_stack["private_subnet_ids"],
        security_group_id=vpc_stack["app_security_group_id"],
        container_image=container_image,
        queue_url=job_queue_stack["queue_url"],
        table_name=job_store_stack["table_name"],
        kms_key_id=kms_key["key_id"],
        log_group_name=ecs_stack["log_group"].name,
        queue_arn=job_queue_stack["queue_arn"],
        table_arn=job_store_stack["table_arn"],
        worker_cpu=worker_cpu,
        worker_memory=worker_memory,
        worker_min_instances=worker_min_instances,
        worker_max_instances=worker_max_instances,
        worker_concurrency=worker_concurrency,
        environment=app_environment,
        secret_keys=secret_keys,
        external_secrets_prefix=external_secrets_prefix,
        capacity_providers=ecs_stack["capacity_providers"],
    )

# SQS Queue Policy - restrict access to ECS task roles (API + Worker)
# API needs SendMessage to enqueue jobs, Worker needs full access to process them
import json as _json

def _build_sqs_policy(args):
    queue_arn = args[0]
    role_arns = [arn for arn in args[1:] if arn]
    if not role_arns:
        return _json.dumps({"Version": "2012-10-17", "Statement": []})
    return _json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowECSTaskRoles",
                "Effect": "Allow",
                "Principal": {"AWS": role_arns},
                "Action": [
                    "sqs:SendMessage",
                    "sqs:ReceiveMessage",
                    "sqs:DeleteMessage",
                    "sqs:GetQueueAttributes",
                    "sqs:ChangeMessageVisibility",
                ],
                "Resource": queue_arn,
            },
        ],
    })

sqs_queue_policy = aws.sqs.QueuePolicy(
    f"cerebro-{environment}-queue-policy",
    queue_url=job_queue_stack["queue_url"],
    policy=pulumi.Output.all(
        job_queue_stack["queue_arn"],
        ecs_stack["task_role"].arn,
        worker_stack["task_role"].arn if worker_stack else None,
    ).apply(_build_sqs_policy),
)

# Job queue alarms with optional Slack integration
job_alarms_stack = jobs.create_job_alarms(
    name=f"cerebro-{environment}",
    queue_name=f"cerebro-{environment}-jobs",
    dlq_name=f"cerebro-{environment}-jobs-dlq",
    slack_channel_id=slack_channel_id,
    slack_workspace_id=slack_workspace_id,
)

# =============================================================================
# MONITORING
# =============================================================================

monitoring_stack = monitoring.create_monitoring(
    name=f"cerebro-{environment}",
    alb_arn_suffix=alb_stack["alb"].arn_suffix,
    target_group_arn_suffix=alb_stack["target_group"].arn_suffix,
    ecs_cluster_name=ecs_stack["cluster"].name,
    ecs_service_name=ecs_stack["api_service"].name,
    log_retention_days=log_retention_days,
)

# =============================================================================
# WAF (optional)
# =============================================================================

waf_stack = None
if enable_waf:
    waf_stack = waf.create_waf(
        name=f"cerebro-{environment}",
        alb_arn=alb_stack["alb"].arn,
        rate_limit=2000,
        enable_logging=True,
        log_retention_days=log_retention_days,
        log_group_kms_key_id=logs_kms_key["key_arn"] if logs_kms_key else None,
    )

# =============================================================================
# TAILSCALE SUBNET ROUTER (optional)
# =============================================================================

tailscale_stack = None
if enable_tailscale:
    # Auth key is stored in Secrets Manager (Infisical-synced)
    # Default: {external_secrets_prefix}/TAILSCALE_AUTH_KEY
    # Override via config: tailscaleAuthKeySecretName
    tailscale_auth_key_secret_name = (
        config.get("tailscaleAuthKeySecretName")
        or f"{external_secrets_prefix}/TAILSCALE_AUTH_KEY"
    )
    
    # Get the secret ARN from the name
    tailscale_auth_key_secret = aws.secretsmanager.get_secret(
        name=tailscale_auth_key_secret_name,
    )
    
    # Advertise only the private subnets (where ALB/ECS live)
    # Routes are auto-approved via ACL for tag:exitnode
    # Configure via cerebro:tailscaleAdvertiseRoutes in stack config
    if not tailscale_advertise_routes:
        raise ValueError("cerebro:tailscaleAdvertiseRoutes must be configured when enableTailscale is true")
    
    tailscale_stack = ts.create_tailscale_subnet_router(
        name=f"cerebro-{environment}",
        vpc_id=vpc_stack["vpc_id"],
        subnet_id=vpc_stack["private_subnet_ids"][0],
        advertise_routes=tailscale_advertise_routes,
        tailscale_hostname=tailscale_hostname,
        auth_key_secret_arn=tailscale_auth_key_secret.arn,
        kms_key_arn=kms_key["key_arn"],
    )

# =============================================================================
# OUTPUTS
# =============================================================================

pulumi.export("vpc_id", vpc_stack["vpc_id"])
pulumi.export("ecs_cluster_name", ecs_stack["cluster"].name)
pulumi.export("ecs_service_name", ecs_stack["api_service"].name)
pulumi.export("alb_dns_name", alb_stack["alb"].dns_name)
pulumi.export("kms_key_id", kms_key["key_id"])
pulumi.export("kms_key_alias", kms_key["alias"].name)

pulumi.export(
    "api_url",
    (
        pulumi.Output.concat("https://", domain)
        if domain
        else pulumi.Output.concat("http://", alb_stack["alb"].dns_name)
    ),
)

if waf_stack:
    pulumi.export("waf_web_acl_arn", waf_stack["web_acl"].arn)

# KMS key outputs
if logs_kms_key:
    pulumi.export("logs_kms_key_arn", logs_kms_key["key_arn"])

# Job queue outputs
pulumi.export("job_queue_url", job_queue_stack["queue_url"])
pulumi.export("job_queue_arn", job_queue_stack["queue_arn"])
pulumi.export("job_dlq_url", job_queue_stack["dlq_url"])
pulumi.export("job_table_name", job_store_stack["table_name"])
pulumi.export("job_table_arn", job_store_stack["table_arn"])

# Job alarms Slack integration outputs
if job_alarms_stack.get("sns_topic"):
    pulumi.export("job_alarms_sns_topic_arn", job_alarms_stack["sns_topic"].arn)

if worker_stack:
    pulumi.export("worker_service_name", worker_stack["service"].name)

# =============================================================================
# INFISICAL (optional)
# =============================================================================

infisical_stack = None
if enable_infisical and infisical_principal_arn:
    infisical_stack = infisical.create_infisical_sync_role(
        name=f"cerebro-{environment}",
        assume_role_principal_arn=infisical_principal_arn,
        external_id=infisical_external_id,
        kms_key_arn=kms_key["key_arn"],
    )
    pulumi.export("infisical_role_arn", infisical_stack["role_arn"])

if tailscale_stack:
    pulumi.export("tailscale_instance_id", tailscale_stack["instance_id"])
    pulumi.export("tailscale_private_ip", tailscale_stack["private_ip"])

# =============================================================================
# ECR REPOSITORY
# =============================================================================

ecr_repository = ecr.create_ecr_repository(
    name="cerebro",
    enable_immutable_tags=True,  # Tags are immutable except for 'latest'
    scan_on_push=True,
    lifecycle_policy_days=30,
    kms_key_arn=kms_key["key_arn"],
)

pulumi.export("ecr_repository_url", ecr_repository.repository_url)
pulumi.export("ecr_repository_arn", ecr_repository.arn)
