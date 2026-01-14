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
import pulumi_tailscale as tailscale

from aws import compute, infisical, kms, load_balancer, monitoring, networking, secrets, tailscale as ts, waf

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

# Infisical integration
enable_infisical = _config_bool("enableInfisicalSyncRole", False)
infisical_principal_arn = config.get("infisicalAssumeRolePrincipalArn")
infisical_external_id = config.get("infisicalExternalId")

# External secrets (Infisical-synced) - when enabled, secrets are read from 
# AWS Secrets Manager instead of Pulumi config
use_external_secrets = _config_bool("useExternalSecrets", False)
external_secrets_prefix = config.get("externalSecretsPrefix") or f"cerebro-{environment}"

# Tailscale subnet router for internal access
enable_tailscale = _config_bool("enableTailscale", False)
tailscale_hostname = config.get("tailscaleHostname") or f"cerebro-{environment}"

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

# When using external secrets (Infisical), secrets are synced to AWS Secrets Manager
# and referenced by ARN. Otherwise, we create our own secret from Pulumi config.
if use_external_secrets:
    # External secrets mode: reference Infisical-synced secrets
    # Secrets should be synced to: {prefix}/SNOWFLAKE_CONNECTION_STRING, etc.
    cerebro_secrets = None  # No Pulumi-managed secret
    
    # List of secret keys that will be injected from external secrets
    secret_keys = ["SNOWFLAKE_CONNECTION_STRING"]
    
    # Optional external secrets - check if they exist
    optional_secrets = [
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "SLACK_WEBHOOK_URL",
        "JIRA_API_TOKEN",
        "LINEAR_API_KEY",
    ]
    # In external mode, we assume all configured secrets exist
    # The actual existence is validated at runtime by ECS
    for key in optional_secrets:
        if config.get_bool(f"enable{key.replace('_', ' ').title().replace(' ', '')}"):
            secret_keys.append(key)
else:
    # Pulumi-managed secrets mode
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
    secrets_arn=cerebro_secrets.arn if cerebro_secrets else None,
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
    external_secrets_prefix=external_secrets_prefix if use_external_secrets else None,
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
# TAILSCALE SUBNET ROUTER (optional)
# =============================================================================

tailscale_stack = None
if enable_tailscale:
    # Create a reusable, ephemeral auth key
    ts_auth_key = tailscale.TailnetKey(
        f"cerebro-{environment}-tailscale-key",
        reusable=True,
        ephemeral=True,
        preauthorized=True,
        expiry=7776000,  # 90 days
        tags=["tag:exitnode"],
    )
    
    # Advertise only the private subnets (where ALB/ECS live)
    # Routes are auto-approved via ACL for tag:exitnode
    tailscale_stack = ts.create_tailscale_subnet_router(
        name=f"cerebro-{environment}",
        vpc_id=vpc_stack["vpc_id"],
        subnet_id=vpc_stack["private_subnet_ids"][0],
        advertise_routes=["10.0.10.0/24", "10.0.11.0/24"],  # private subnets only
        tailscale_auth_key=ts_auth_key.key,
        tailscale_hostname=tailscale_hostname,
    )

# =============================================================================
# OUTPUTS
# =============================================================================

pulumi.export("vpc_id", vpc_stack["vpc_id"])
pulumi.export("ecs_cluster_name", ecs_stack["cluster"].name)
pulumi.export("ecs_service_name", ecs_stack["api_service"].name)
pulumi.export("alb_dns_name", alb_stack["alb"].dns_name)
if cerebro_secrets:
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

# =============================================================================
# INFISICAL (optional)
# =============================================================================

infisical_stack = None
if enable_infisical and infisical_principal_arn:
    infisical_stack = infisical.create_infisical_sync_role(
        name=f"cerebro-{environment}",
        assume_role_principal_arn=infisical_principal_arn,
        external_id=infisical_external_id,
        kms_key_arn=kms_key.arn,
    )
    pulumi.export("infisical_role_arn", infisical_stack["role_arn"])

if tailscale_stack:
    pulumi.export("tailscale_instance_id", tailscale_stack["instance_id"])
    pulumi.export("tailscale_private_ip", tailscale_stack["private_ip"])
