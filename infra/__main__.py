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

from aws import compute, kms, load_balancer, monitoring, networking, secrets, waf

# Configuration
config = pulumi.Config()
environment = config.get("environment") or "production"
domain = config.get("domain") or ""
container_image = config.require("containerImage")
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
log_retention_days = _config_int("logRetentionDays", 30)

# =============================================================================
# NETWORKING
# =============================================================================

vpc_cidr = "10.0.0.0/16"
vpc_stack = networking.create_vpc(
    name=f"cerebro-{environment}",
    cidr_block=vpc_cidr,
    availability_zones=2,
    enable_nat_gateway=True,
    alb_ingress_cidrs=[vpc_cidr] if alb_internal else None,
)

# =============================================================================
# KMS
# =============================================================================

kms_key = kms.create_kms_key(
    name=f"cerebro-{environment}",
    description="Cerebro encryption key",
)

# =============================================================================
# SECRETS
# =============================================================================

# Build secrets dict from config - only include configured secrets
secrets_dict = {
    "SNOWFLAKE_CONNECTION_STRING": config.require_secret("snowflakeConnectionString"),
}
secret_keys = ["SNOWFLAKE_CONNECTION_STRING"]

# Optional secrets - only add if configured
if config.get_secret("anthropicApiKey"):
    secrets_dict["ANTHROPIC_API_KEY"] = config.get_secret("anthropicApiKey")
    secret_keys.append("ANTHROPIC_API_KEY")

if config.get_secret("openaiApiKey"):
    secrets_dict["OPENAI_API_KEY"] = config.get_secret("openaiApiKey")
    secret_keys.append("OPENAI_API_KEY")

if config.get_secret("slackWebhookUrl"):
    secrets_dict["SLACK_WEBHOOK_URL"] = config.get_secret("slackWebhookUrl")
    secret_keys.append("SLACK_WEBHOOK_URL")

if config.get_secret("jiraApiToken"):
    secrets_dict["JIRA_API_TOKEN"] = config.get_secret("jiraApiToken")
    secret_keys.append("JIRA_API_TOKEN")

if config.get_secret("linearApiKey"):
    secrets_dict["LINEAR_API_KEY"] = config.get_secret("linearApiKey")
    secret_keys.append("LINEAR_API_KEY")

cerebro_secrets = secrets.create_secrets(
    name=f"cerebro-{environment}",
    secrets=secrets_dict,
    kms_key_arn=kms_key.arn,
)

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
    "SNOWFLAKE_SCHEMA": config.get("snowflakeSchema") or "RAW",
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

ecs_stack = compute.create_ecs_cluster(
    name=f"cerebro-{environment}",
    vpc_id=vpc_stack["vpc_id"],
    subnet_ids=vpc_stack["private_subnet_ids"],
    security_group_id=vpc_stack["app_security_group_id"],
    secrets_arn=cerebro_secrets.arn,
    kms_key_id=kms_key.id,
    target_group_arn=alb_stack["target_group"].arn,
    container_image=container_image,
    api_cpu=api_cpu,
    api_memory=api_memory,
    api_min_instances=api_min_instances,
    api_max_instances=api_max_instances,
    log_retention_days=log_retention_days,
    environment=app_environment,
    secret_keys=secret_keys,
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
    )

# =============================================================================
# OUTPUTS
# =============================================================================

pulumi.export("vpc_id", vpc_stack["vpc_id"])
pulumi.export("ecs_cluster_name", ecs_stack["cluster"].name)
pulumi.export("ecs_service_name", ecs_stack["api_service"].name)
pulumi.export("alb_dns_name", alb_stack["alb"].dns_name)
pulumi.export("secrets_arn", cerebro_secrets.arn)
pulumi.export("kms_key_id", kms_key.id)

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
