"""
Pulumi infrastructure for the Cerebro rewrite runtime.

Deploys a private ECS service backed by:
- RDS Postgres for current state
- NATS JetStream for the append log
- Neo4j/Aura for graph projections
"""

import pulumi
import pulumi_aws as aws

import audit_storage
import cache
import certificate as cert
import compute
import ecr
import infisical
import kms
import legacy
import load_balancer
import monitoring
import nats
import neo4j
import networking
import postgres
import resilience
import tailscale as ts
import waf
import web
try:
    from source_rollouts import apply_source_runtime_rollouts
except ModuleNotFoundError:  # pragma: no cover - used when imported as aws.__main__
    from aws.source_rollouts import apply_source_runtime_rollouts

config = pulumi.Config()


def _get_environment() -> str:
    if config.get("environment"):
        return config.get("environment")
    stack = pulumi.get_stack()
    if stack == "go-prod":
        return "go-production"
    if stack.startswith("go-"):
        return stack.replace("-prod", "-production")
    return "production"


def _config_int(key: str, default: int) -> int:
    value = config.get_int(key)
    return default if value is None else value


def _config_bool(key: str, default: bool) -> bool:
    value = config.get_bool(key)
    return default if value is None else value


def _disabled_runtime_ids(entries: list[dict]) -> list[str]:
    runtime_ids = []
    for entry in entries or []:
        if isinstance(entry, dict) and str(entry.get("runtimeId", "")).strip():
            runtime_ids.append(str(entry["runtimeId"]).strip())
    return sorted(set(runtime_ids))


# The cross-task lease around source-runtime cursor advances landed in
# writer/cerebro PR #554 and ships in v2.1.25. Below that version the API
# service still races other API replicas on cursor reads, so the
# apiMaxInstances guardrail must stay engaged.
_MIN_CROSS_TASK_SYNC_LOCK_VERSION = "2.1.25"


def _supports_cross_task_sync_lock(image_tag: str) -> bool:
    if not image_tag or not image_tag.startswith("v"):
        return False
    semver = image_tag[1:].split("-", 1)[0]
    try:
        parts = [int(part) for part in semver.split(".")[:3]]
    except ValueError:
        return False
    if len(parts) != 3:
        return False
    minimum = tuple(int(part) for part in _MIN_CROSS_TASK_SYNC_LOCK_VERSION.split("."))
    return tuple(parts) >= minimum


def _config_optional_secret(key: str) -> pulumi.Output[str] | None:
    value = config.get(key)
    if not value:
        return None
    return config.get_secret(key)


def _env_ref(value) -> str:
    text = str(value).strip()
    if not text.startswith("env:"):
        return ""
    env_name = text.removeprefix("env:").strip()
    if not env_name:
        raise ValueError("source runtime env reference must include an environment variable name")
    return env_name


def _source_runtime_env_refs(source_runtimes: list[dict]) -> list[str]:
    refs = set()
    for runtime in source_runtimes:
        if not isinstance(runtime, dict):
            raise ValueError("sourceRuntimes entries must be objects")
        runtime_id = str(runtime.get("id", "")).strip()
        runtime_config = runtime.get("config") or {}
        if not isinstance(runtime_config, dict):
            raise ValueError(f"source runtime {runtime_id or '<unknown>'} config must be an object")
        for value in runtime_config.values():
            env_name = _env_ref(value)
            if env_name:
                refs.add(env_name)
    return sorted(refs)


def _secret_env_name(secret_key) -> str:
    if isinstance(secret_key, dict):
        return str(secret_key.get("name", "")).strip()
    return str(secret_key).strip()


def _validate_source_secret_refs(secret_keys: list, env_refs: list[str]) -> None:
    existing = {_secret_env_name(secret_key) for secret_key in (secret_keys or [])}
    missing = [env_name for env_name in env_refs if env_name not in existing]
    if missing:
        raise ValueError(f"source runtime env refs must be declared in cerebro:sourceSecretKeys: {', '.join(missing)}")


environment = _get_environment()
domain = config.get("domain") or ""
certificate_domain = config.get("certificateDomain") or ""
certificate_import_arn = config.get("certificateImportArn") or ""
ecr_base_uri = config.require("ecrBaseUri")
image_tag = config.get("imageTag") or "v1.0.0"
container_image = f"{ecr_base_uri}:{image_tag}"

web_enabled = _config_bool("webEnabled", False)
web_ecr_base_uri = config.get("webEcrBaseUri") or ecr_base_uri
web_image_tag = config.get("webImageTag") or ""
web_container_image = f"{web_ecr_base_uri}:{web_image_tag}" if web_ecr_base_uri and web_image_tag else ""
web_domain = config.get("webDomain") or ""
web_certificate_arn = config.get("webCertificateArn") or ""
web_certificate_domain = config.get("webCertificateDomain") or ""
web_certificate_import_arn = config.get("webCertificateImportArn") or ""
web_cpu = _config_int("webCpu", 512)
web_memory = _config_int("webMemory", 1024)
web_min_instances = _config_int("webMinInstances", 1)
web_max_instances = _config_int("webMaxInstances", 1)
web_container_port = _config_int("webContainerPort", 3000)
web_api_base = config.get("webApiBase") or (f"https://{domain}" if domain else "")
web_forward_auth_headers = _config_bool("webForwardAuthHeaders", False)
web_proxy_timeout_ms = _config_int("webProxyTimeoutMs", 600000)
web_api_key_secret_name = config.get("webApiKeySecretName") or "CEREBRO_API_KEYS"
web_oidc_enabled = _config_bool("webOidcEnabled", False)
web_oidc_issuer = (config.get("webOidcIssuer") or "").rstrip("/")
web_oidc_authorization_endpoint = (config.get("webOidcAuthorizationEndpoint") or "").rstrip("/")
web_oidc_token_endpoint = (config.get("webOidcTokenEndpoint") or "").rstrip("/")
web_oidc_user_info_endpoint = (config.get("webOidcUserInfoEndpoint") or "").rstrip("/")
web_oidc_client_id = config.get("webOidcClientId") or ""
web_oidc_client_secret = _config_optional_secret("webOidcClientSecret")
web_oidc_session_cookie_name = config.get("webOidcSessionCookieName") or "CerebroWebOidcSession"
web_oidc_session_timeout_seconds = _config_int("webOidcSessionTimeoutSeconds", 28800)

if web_enabled and not web_container_image:
    raise ValueError("cerebro:webEcrBaseUri and cerebro:webImageTag are required when webEnabled is true")
if web_enabled and not web_api_base:
    raise ValueError("cerebro:webApiBase or cerebro:domain is required when webEnabled is true")
if web_oidc_enabled:
    if not web_enabled:
        raise ValueError("cerebro:webEnabled must be true when cerebro:webOidcEnabled is true")
    if not (
        web_domain
        and (web_certificate_arn or (web_certificate_domain and web_certificate_domain == web_domain))
    ):
        raise ValueError("cerebro:webDomain and a web certificate are required when cerebro:webOidcEnabled is true")
    if not (web_oidc_issuer and web_oidc_client_id and web_oidc_client_secret):
        raise ValueError("cerebro:webOidcIssuer, cerebro:webOidcClientId, and cerebro:webOidcClientSecret are required when webOidcEnabled is true")

web_oidc_auth = None
if web_oidc_enabled:
    web_oidc_auth = {
        "issuer": web_oidc_issuer,
        "authorization_endpoint": web_oidc_authorization_endpoint or f"{web_oidc_issuer}/v1/authorize",
        "token_endpoint": web_oidc_token_endpoint or f"{web_oidc_issuer}/v1/token",
        "user_info_endpoint": web_oidc_user_info_endpoint or f"{web_oidc_issuer}/v1/userinfo",
        "client_id": web_oidc_client_id,
        "client_secret": web_oidc_client_secret,
        "session_cookie_name": web_oidc_session_cookie_name,
        "session_timeout": web_oidc_session_timeout_seconds,
    }

alb_internal = _config_bool("albInternal", True)
alb_idle_timeout_seconds = _config_int("albIdleTimeoutSeconds", 300)
web_alb_idle_timeout_seconds = _config_int("webAlbIdleTimeoutSeconds", alb_idle_timeout_seconds)
configured_alb_ingress_cidrs = config.get_object("albIngressCidrs") or None
is_production = "prod" in environment.lower()

api_cpu = _config_int("apiCpu", 1024)
api_memory = _config_int("apiMemory", 2048)
api_min_instances = _config_int("apiMinInstances", 1)
api_max_instances = _config_int("apiMaxInstances", 1)
api_request_count_per_target_scaling_target = _config_int("apiRequestCountPerTargetScalingTarget", 0)
orchestrator_enabled = _config_bool("orchestratorEnabled", False)
orchestrator_schedule_expression = config.get("orchestratorScheduleExpression") or "rate(1 hour)"
orchestrator_cpu = _config_int("orchestratorCpu", api_cpu)
orchestrator_memory = _config_int("orchestratorMemory", api_memory)
orchestrator_command = config.get_object("orchestratorCommand") or ["orchestrator", "run"]
orchestrator_task_count = _config_int("orchestratorTaskCount", 1)
orchestrator_schedules = config.get_object("orchestratorSchedules") or []

if api_max_instances > 1 and not _supports_cross_task_sync_lock(image_tag):
    raise ValueError(
        "Source runtime sync cursors are cross-task locked starting with writer/cerebro "
        f"v{_MIN_CROSS_TASK_SYNC_LOCK_VERSION}; set cerebro:apiMaxInstances to 1 or upgrade "
        f"cerebro:imageTag (current: {image_tag})."
    )

log_retention_days = _config_int("logRetentionDays", 30)
enable_waf = _config_bool("enableWaf", True)
enable_alb_access_logs = _config_bool("enableAlbAccessLogs", is_production)
alb_access_logs_retention_days = _config_int("albAccessLogsRetentionDays", log_retention_days)
enable_alb_deletion_protection = _config_bool("enableAlbDeletionProtection", is_production)
enable_kms_log_encryption = _config_bool("enableKmsLogEncryption", is_production)
nat_gateway_per_az = _config_bool("natGatewayPerAz", is_production)

# Keep Infisical-managed runtime inputs in a separate prefix so sync pruning
# cannot delete Pulumi-managed generated secrets such as Postgres and Neo4j.
enable_infisical = _config_bool("enableInfisicalSyncRole", False)
infisical_principal_arn = config.get("infisicalAssumeRolePrincipalArn")
infisical_external_id = config.get("infisicalExternalId")
external_secrets_prefix = config.get("externalSecretsPrefix") or f"cerebro-{environment}"
infisical_secrets_prefix = config.get("infisicalSecretsPrefix") or external_secrets_prefix

# Tailscale subnet router for internal access.
enable_tailscale = _config_bool("enableTailscale", False)
tailscale_hostname = config.get("tailscaleHostname") or f"cerebro-{environment}"
tailscale_advertise_routes = config.get_object("tailscaleAdvertiseRoutes") or []

# Existing VPC configuration.
use_existing_vpc = _config_bool("useExistingVpc", False)
existing_vpc_id = config.get("vpcId")
existing_private_subnet_ids = config.get_object("privateSubnetIds") or []
existing_public_subnet_ids = config.get_object("publicSubnetIds") or []
existing_vpc_cidr = config.get("vpcCidr") or "10.0.0.0/16"

# Runtime backing services.
postgres_instance_class = config.get("postgresInstanceClass") or ("db.t4g.small" if is_production else "db.t4g.micro")
postgres_allocated_storage = _config_int("postgresAllocatedStorage", 50 if is_production else 20)
postgres_storage_type = config.get("postgresStorageType") or "gp3"
postgres_max_allocated_storage_config = config.get_int("postgresMaxAllocatedStorage")
postgres_iops_config = config.get_int("postgresIops")
postgres_storage_throughput_config = config.get_int("postgresStorageThroughput")
postgres_max_allocated_storage = (
    postgres_max_allocated_storage_config if postgres_max_allocated_storage_config and postgres_max_allocated_storage_config > 0 else None
)
postgres_iops = postgres_iops_config if postgres_iops_config and postgres_iops_config > 0 else None
postgres_storage_throughput = (
    postgres_storage_throughput_config if postgres_storage_throughput_config and postgres_storage_throughput_config > 0 else None
)
postgres_backup_retention_days = _config_int("postgresBackupRetentionDays", 14 if is_production else 3)
postgres_deletion_protection = _config_bool("postgresDeletionProtection", is_production)
postgres_multi_az = _config_bool("postgresMultiAz", is_production)
postgres_apply_immediately = _config_bool("postgresApplyImmediately", not is_production)
postgres_final_snapshot_identifier = config.get("postgresFinalSnapshotIdentifier") or None
retain_legacy_jobs_table = _config_bool("retainLegacyJobsTableForDeletionProtectionTransition", False)

cache_enabled = _config_bool("cacheEnabled", False)
cache_engine = (config.get("cacheEngine") or "valkey").strip().lower()
cache_major_engine_version = (config.get("cacheMajorEngineVersion") or "").strip() or None
cache_namespace = config.get("cacheNamespace") or f"cerebro:{environment}:grc"
cache_default_ttl = config.get("cacheDefaultTTL") or "30s"
cache_stale_ttl = config.get("cacheStaleTTL") or "5m"
cache_max_payload_bytes = _config_int("cacheMaxPayloadBytes", 1048576)

nats_cpu = _config_int("natsCpu", 512)
nats_memory = _config_int("natsMemory", 1024)
jetstream_subject_prefix = config.get("jetstreamSubjectPrefix") or "events"
jetstream_stream_name = config.get("jetstreamStreamName") or "CEREBRO_EVENTS"
jetstream_max_bytes = config.get("jetstreamMaxBytes") or ""
jetstream_max_age = config.get("jetstreamMaxAge") or ""
enable_jetstream_lag_probe = _config_bool("enableJetstreamLagProbe", True)
jetstream_lag_probe_interval_seconds = _config_int("jetstreamLagProbeIntervalSeconds", 60)
jetstream_lag_alarm_threshold = _config_int("jetstreamLagAlarmThreshold", 10000)
api_request_count_per_target_alarm_threshold = _config_int("apiRequestCountPerTargetAlarmThreshold", 0)
api_latency_p95_alarm_threshold_seconds = _config_int("apiLatencyP95AlarmThresholdSeconds", 3)
web_latency_p95_alarm_threshold_seconds = _config_int("webLatencyP95AlarmThresholdSeconds", 3)
dashboard_latency_p95_alarm_threshold_ms = _config_int("dashboardLatencyP95AlarmThresholdMs", 3000)
access_audit_denied_alarm_threshold = _config_int("accessAuditDeniedAlarmThreshold", 0)
access_audit_auth_failure_alarm_threshold = _config_int("accessAuditAuthFailureAlarmThreshold", 0)
access_audit_tenant_mismatch_alarm_threshold = _config_int("accessAuditTenantMismatchAlarmThreshold", -1)
access_audit_sensitive_denied_alarm_threshold = _config_int("accessAuditSensitiveDeniedAlarmThreshold", -1)
aws_service_quota_alarm_threshold_percent = _config_int("awsServiceQuotaAlarmThresholdPercent", 80)
runtime_controls_appconfig_enabled = _config_bool("runtimeControlsAppConfigEnabled", True)
orchestrator_step_functions_enabled = _config_bool("orchestratorStepFunctionsEnabled", False)
orchestrator_sqs_buffer_enabled = _config_bool("orchestratorSqsBufferEnabled", False)
orchestrator_sqs_buffer_pipe_state = str(config.get("orchestratorSqsBufferPipeState") or "STOPPED").strip().upper()
synthetics_canary_enabled = _config_bool("syntheticsCanaryEnabled", False)
synthetics_canary_start = _config_bool("syntheticsCanaryStart", False)
cloudtrail_audit_log_group_name = config.get("cloudTrailAuditLogGroupName") or ""
cost_anomaly_detection_enabled = _config_bool("costAnomalyDetectionEnabled", False)
monthly_cost_budget_limit_usd = _config_int("monthlyCostBudgetLimitUsd", 0)
alarm_action_arns = config.get_object("alarmActionArns") or []
alarm_email_subscriptions = config.get_object("alarmEmailSubscriptions") or []

neo4j_database = config.get("neo4jDatabase")
neo4j_aura_enabled = _config_bool("neo4jAuraEnabled", False)
neo4j_aura_instance_id = config.get("neo4jAuraInstanceId") or ""
neo4j_aura_instance_name = config.get("neo4jAuraInstanceName") or f"cerebro-graphdb-{environment}-writer"
neo4j_aura_client_id = config.get_secret("neo4jAuraClientId")
neo4j_aura_client_secret = config.get_secret("neo4jAuraClientSecret")
neo4j_aura_project_id = config.get_secret("neo4jAuraProjectId")
neo4j_aura_password = _config_optional_secret("neo4jAuraPassword")
neo4j_aura_cloud_provider = config.get("neo4jAuraCloudProvider") or "gcp"
neo4j_aura_region = config.get("neo4jAuraRegion") or "us-central1"
neo4j_aura_memory = config.get("neo4jAuraMemory") or "8GB"
neo4j_aura_version = config.get("neo4jAuraVersion") or "5"
neo4j_aura_type = config.get("neo4jAuraType") or "professional-db"
neo4j_aura_vector_optimized = _config_bool("neo4jAuraVectorOptimized", True)
neo4j_secret_import_arns = config.get_object("neo4jSecretImportArns") or {}
api_keys = _config_optional_secret("apiKeys")
api_credentials_secret_name = config.get("apiCredentialsSecretName") or "CEREBRO_API_CREDENTIALS_JSON"
api_auth_enabled = _config_bool("apiAuthEnabled", is_production)
allowed_tenants = config.get_object("allowedTenants") or []
capability_token_secret_name = config.get("capabilityTokenSecretName") or "CEREBRO_CAPABILITY_TOKEN_SECRETS"
capability_token_audience = config.get("capabilityTokenAudience") or "cerebro-api"

# =============================================================================
# DEVICE-AUTH (secheck agent sender-constrained tokens)
# =============================================================================
# The secheck agent's DPoP replay protection is in-process per Cerebro replica
# (see internal/deviceauth/dpop.go). With more than one API replica each
# replica would maintain an isolated jti cache, so a legitimate proof routed
# to a different replica than the one that initially saw it would falsely
# look like a replay -> 401. The Cerebro server fails closed at startup in
# that case (errDeviceAuthRequiresSharedDPoPReplay); we fail fast HERE so the
# operator sees the message during `pulumi up` rather than after the rollout.
#
# Placement note: this block reads api_auth_enabled and api_max_instances,
# both of which must be defined upstream of this point. Do NOT move this
# block earlier -- the previous revision did, and crashed at runtime with
# `NameError: name 'api_auth_enabled' is not defined` whenever
# deviceAuthEnabled was true.
device_auth_enabled = _config_bool("deviceAuthEnabled", False)
device_auth_current_kid = config.get("deviceAuthCurrentKID") or ""
device_auth_signing_keys_secret_name = config.get("deviceAuthSigningKeysSecretName") or ""
device_auth_issuer = config.get("deviceAuthIssuer") or ""
device_auth_audience = config.get("deviceAuthAudience") or ""
device_auth_access_ttl = config.get("deviceAuthAccessTTL") or ""
device_auth_refresh_ttl = config.get("deviceAuthRefreshTTL") or ""
device_auth_bootstrap_token_ttl = config.get("deviceAuthBootstrapTokenTTL") or ""
device_auth_dpop_proof_ttl = config.get("deviceAuthDPoPProofTTL") or ""
device_auth_clock_skew = config.get("deviceAuthClockSkew") or ""
device_auth_idempotency_ttl = config.get("deviceAuthIdempotencyTTL") or ""
device_auth_attestation_required = _config_bool("deviceAuthAttestationRequired", False)
device_auth_apple_team_id = config.get("deviceAuthAppleTeamID") or ""
device_auth_apple_bundle_ids = config.get_object("deviceAuthAppleBundleIDs") or []

if device_auth_enabled:
    if not api_auth_enabled:
        raise ValueError(
            "cerebro:deviceAuthEnabled requires cerebro:apiAuthEnabled=true "
            "(server-side: errDeviceAuthRequiresAPIAuth)."
        )
    if api_max_instances > 1:
        raise ValueError(
            "cerebro:deviceAuthEnabled is incompatible with cerebro:apiMaxInstances > 1 "
            f"(current: {api_max_instances}). The secheck DPoP replay cache is in-process; "
            "pin apiMaxInstances=1 or migrate to shared replay state before raising it."
        )
    if not device_auth_signing_keys_secret_name:
        raise ValueError(
            "cerebro:deviceAuthSigningKeysSecretName is required when "
            "cerebro:deviceAuthEnabled is true. Provision an AWS SecretsManager "
            "entry holding the JSON-encoded Ed25519 signing-key bundle "
            "(see PR description) and set this config to its name."
        )
    if not device_auth_current_kid:
        raise ValueError(
            "cerebro:deviceAuthCurrentKID is required when cerebro:deviceAuthEnabled is true. "
            "It must match one of the kid values inside the signing-keys JSON."
        )
    if device_auth_attestation_required and not (
        device_auth_apple_team_id and device_auth_apple_bundle_ids
    ):
        raise ValueError(
            "cerebro:deviceAuthAttestationRequired=true requires both "
            "cerebro:deviceAuthAppleTeamID and a non-empty cerebro:deviceAuthAppleBundleIDs list."
        )
source_runtime_config = apply_source_runtime_rollouts({
    "sourceSecretKeys": config.get_object("sourceSecretKeys") or [],
    "sourceRuntimes": config.get_object("sourceRuntimes") or [],
    "orchestratorSchedules": orchestrator_schedules,
    "sourceRuntimeRollouts": config.get_object("sourceRuntimeRollouts") or [],
})
source_secret_keys = source_runtime_config["sourceSecretKeys"]
source_runtimes = source_runtime_config["sourceRuntimes"]
source_runtime_service_bootstrap_ids = config.get_object("sourceRuntimeServiceBootstrapIds")
orchestrator_schedules = source_runtime_config["orchestratorSchedules"]
source_runtime_observability = config.get_object("sourceRuntimeObservability") or []
temporarily_disabled_source_runtimes = config.get_object("temporarilyDisabledSourceRuntimes") or []
source_runtime_env_refs = _source_runtime_env_refs(source_runtimes)
_validate_source_secret_refs(source_secret_keys, source_runtime_env_refs)

runtime_controls_stack = resilience.create_runtime_controls(
    name=f"cerebro-{environment}",
    environment=environment,
    disabled_runtime_ids=_disabled_runtime_ids(temporarily_disabled_source_runtimes),
    enabled=runtime_controls_appconfig_enabled,
)


def _infisical_secret(env_name: str, source: str | None = None) -> dict[str, str]:
    return {
        "name": env_name,
        "source": source or env_name,
        "prefix": infisical_secrets_prefix,
    }


def _infisical_source_secret(secret_key) -> dict[str, str]:
    if isinstance(secret_key, dict):
        return {
            "name": str(secret_key.get("name", "")).strip(),
            "source": str(secret_key.get("source") or secret_key.get("name", "")).strip(),
            "prefix": str(secret_key.get("prefix") or infisical_secrets_prefix).strip(),
        }
    name = str(secret_key).strip()
    return _infisical_secret(name)


mcp_oauth_enabled = _config_bool("mcpOauthEnabled", False)
mcp_oauth_public_origin = (config.get("publicOrigin") or (f"https://{domain}" if domain else "")).rstrip("/")
mcp_oauth_upstream_issuer = (config.get("mcpOauthUpstreamIssuer") or "").rstrip("/")
mcp_oauth_upstream_redirect_uri = (
    config.get("mcpOauthUpstreamRedirectUri")
    or (f"{mcp_oauth_public_origin}/oauth/callback" if mcp_oauth_public_origin else "")
)
mcp_oauth_upstream_client_id_secret_name = (
    config.get("mcpOauthUpstreamClientIdSecretName") or "CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_ID"
)
mcp_oauth_upstream_client_secret_name = (
    config.get("mcpOauthUpstreamClientSecretName") or "CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_SECRET"
)
mcp_oauth_security_groups = [
    str(group).strip()
    for group in (config.get_object("mcpOauthSecurityGroups") or [])
    if str(group).strip()
]
mcp_oauth_tenant_id = (config.get("mcpOauthTenantId") or "").strip()
mcp_oauth_allowed_tenants = [
    str(tenant).strip()
    for tenant in (config.get_object("mcpOauthAllowedTenants") or allowed_tenants)
    if str(tenant).strip()
]
if mcp_oauth_enabled:
    if not api_auth_enabled:
        raise ValueError("cerebro:apiAuthEnabled must be true when cerebro:mcpOauthEnabled is true")
    if not capability_token_secret_name:
        raise ValueError("cerebro:capabilityTokenSecretName is required when cerebro:mcpOauthEnabled is true")
    if not mcp_oauth_public_origin:
        raise ValueError("cerebro:domain is required when cerebro:mcpOauthEnabled is true")
    if not mcp_oauth_upstream_issuer:
        raise ValueError("cerebro:mcpOauthUpstreamIssuer is required when cerebro:mcpOauthEnabled is true")
    if not mcp_oauth_upstream_redirect_uri:
        raise ValueError("cerebro:mcpOauthUpstreamRedirectUri is required when cerebro:mcpOauthEnabled is true")
    if not mcp_oauth_upstream_client_id_secret_name:
        raise ValueError("cerebro:mcpOauthUpstreamClientIdSecretName is required when cerebro:mcpOauthEnabled is true")
    if not mcp_oauth_upstream_client_secret_name:
        raise ValueError("cerebro:mcpOauthUpstreamClientSecretName is required when cerebro:mcpOauthEnabled is true")
    if not mcp_oauth_security_groups:
        raise ValueError("cerebro:mcpOauthSecurityGroups is required when cerebro:mcpOauthEnabled is true")
    if not mcp_oauth_tenant_id and not mcp_oauth_allowed_tenants:
        raise ValueError("cerebro:mcpOauthTenantId or cerebro:mcpOauthAllowedTenants is required when cerebro:mcpOauthEnabled is true")

# Optional IAM grants for S3-backed sources. Source configuration now lives in
# source runtimes, not process env; this only scopes task-role permissions.
s3_sources = config.get_object("s3Sources") or []
s3_source_iam_configs = []
for src in s3_sources:
    bucket = src.get("bucket")
    if not bucket:
        continue
    bucket_arn = src.get("bucketArn") or f"arn:aws:s3:::{bucket}"
    s3_source_iam_configs.append({
        "bucket_arn": bucket_arn,
        "prefixes": src.get("prefixes") or [],
        "role_arn": src.get("roleArn"),
    })

# =============================================================================
# KMS
# =============================================================================

kms_key = kms.create_kms_key(
    name=f"cerebro-{environment}",
    description="Cerebro runtime encryption key",
)

logs_kms_key = None
if enable_kms_log_encryption:
    logs_kms_key = kms.create_cloudwatch_logs_key(name=f"cerebro-{environment}")

if retain_legacy_jobs_table:
    legacy.retain_jobs_table_without_deletion_protection(
        name=f"cerebro-{environment}",
        kms_key_arn=kms_key["key_arn"],
    )

# =============================================================================
# NETWORKING
# =============================================================================

if use_existing_vpc and existing_vpc_id:
    app_ingress_ports = [8080, web_container_port] if web_enabled else [8080]
    vpc_cidr = existing_vpc_cidr
    alb_ingress_cidrs = (
        configured_alb_ingress_cidrs
        if configured_alb_ingress_cidrs is not None
        else ([vpc_cidr] if alb_internal else None)
    )
    vpc_stack = networking.use_existing_vpc(
        name=f"cerebro-{environment}",
        vpc_id=existing_vpc_id,
        public_subnet_ids=existing_public_subnet_ids,
        private_subnet_ids=existing_private_subnet_ids,
        alb_ingress_cidrs=alb_ingress_cidrs,
        app_ingress_ports=app_ingress_ports,
    )
else:
    app_ingress_ports = [8080, web_container_port] if web_enabled else [8080]
    vpc_cidr = "10.0.0.0/16"
    alb_ingress_cidrs = (
        configured_alb_ingress_cidrs
        if configured_alb_ingress_cidrs is not None
        else ([vpc_cidr] if alb_internal else None)
    )
    vpc_stack = networking.create_vpc(
        name=f"cerebro-{environment}",
        cidr_block=vpc_cidr,
        availability_zones=2,
        enable_nat_gateway=True,
        nat_gateway_per_az=nat_gateway_per_az,
        alb_ingress_cidrs=alb_ingress_cidrs,
        enable_flow_logs=True,
        flow_logs_retention_days=log_retention_days,
        flow_logs_kms_key_arn=logs_kms_key["key_arn"] if logs_kms_key else None,
        app_ingress_ports=app_ingress_ports,
    )

public_origin = config.get("publicOrigin") or f"https://{domain}"
trusted_proxy_cidrs = config.get_object("trustedProxyCIDRs")
if trusted_proxy_cidrs is None:
    trusted_proxy_cidrs = [vpc_cidr] if alb_internal else []
trusted_proxy_count = _config_int("trustedProxyCount", 1 if trusted_proxy_cidrs else 0)

# =============================================================================
# RUNTIME BACKING SERVICES
# =============================================================================

postgres_stack = postgres.create_postgres(
    name=f"cerebro-{environment}",
    vpc_id=vpc_stack["vpc_id"],
    subnet_ids=vpc_stack["private_subnet_ids"],
    app_security_group_id=vpc_stack["app_security_group_id"],
    kms_key_arn=kms_key["key_arn"],
    secret_name=f"{external_secrets_prefix}/CEREBRO_POSTGRES_DSN",
    instance_class=postgres_instance_class,
    allocated_storage=postgres_allocated_storage,
    storage_type=postgres_storage_type,
    max_allocated_storage=postgres_max_allocated_storage,
    iops=postgres_iops,
    storage_throughput=postgres_storage_throughput,
    backup_retention_days=postgres_backup_retention_days,
    deletion_protection=postgres_deletion_protection,
    multi_az=postgres_multi_az,
    apply_immediately=postgres_apply_immediately,
    final_snapshot_identifier=postgres_final_snapshot_identifier,
)

nats_stack = nats.create_nats_service(
    name=f"cerebro-{environment}",
    vpc_id=vpc_stack["vpc_id"],
    subnet_ids=vpc_stack["private_subnet_ids"],
    app_security_group_id=vpc_stack["app_security_group_id"],
    kms_key_arn=kms_key["key_arn"],
    log_group_kms_key_id=logs_kms_key["key_arn"] if logs_kms_key else None,
    log_retention_days=log_retention_days,
    cpu=nats_cpu,
    memory=nats_memory,
    stream_name=jetstream_stream_name,
    subject_prefix=jetstream_subject_prefix,
    stream_max_bytes=jetstream_max_bytes,
    stream_max_age=jetstream_max_age,
    enable_lag_probe=enable_jetstream_lag_probe,
    lag_probe_interval_seconds=jetstream_lag_probe_interval_seconds,
)

cache_stack = None
if cache_enabled:
    cache_stack = cache.create_query_cache(
        name=f"cerebro-{environment}",
        vpc_id=vpc_stack["vpc_id"],
        subnet_ids=vpc_stack["private_subnet_ids"],
        app_security_group_id=vpc_stack["app_security_group_id"],
        kms_key_arn=kms_key["key_arn"],
        secret_name=f"{external_secrets_prefix}/CEREBRO_CACHE_URL",
        engine=cache_engine,
        major_engine_version=cache_major_engine_version,
    )

neo4j_stack = None
neo4j_secret_stack = None
if neo4j_aura_enabled:
    if not all([neo4j_aura_client_id, neo4j_aura_client_secret, neo4j_aura_project_id]):
        raise ValueError("neo4jAuraClientId, neo4jAuraClientSecret, and neo4jAuraProjectId are required when neo4jAuraEnabled is true")

    neo4j_instance = neo4j.create_aura_instance(
        name=f"cerebro-{environment}",
        client_id=neo4j_aura_client_id,
        client_secret=neo4j_aura_client_secret,
        project_id=neo4j_aura_project_id,
        instance_name=neo4j_aura_instance_name,
        cloud_provider=neo4j_aura_cloud_provider,
        region=neo4j_aura_region,
        memory=neo4j_aura_memory,
        version=neo4j_aura_version,
        instance_type=neo4j_aura_type,
        vector_optimized=neo4j_aura_vector_optimized,
        import_instance_id=neo4j_aura_instance_id,
    )
    neo4j_stack = {"instance": neo4j_instance}

    if neo4j_aura_password is None:
        neo4j_aura_password = neo4j_instance.password

    neo4j_secret_stack = neo4j.create_runtime_secrets(
        name=f"cerebro-{environment}",
        external_secrets_prefix=external_secrets_prefix,
        neo4j_uri=neo4j_instance.connection_url,
        neo4j_password=neo4j_aura_password,
        api_keys=api_keys,
        kms_key_id=kms_key["key_arn"],
        import_arns=neo4j_secret_import_arns,
        tags={
            "ManagedBy": "Pulumi",
            "Environment": environment,
            "Service": "cerebro",
        },
    )

# =============================================================================
# LOAD BALANCER
# =============================================================================

certificate_stack = None
if certificate_domain:
    certificate_stack = cert.create_certificate(
        name=f"cerebro-{environment}",
        domain=certificate_domain,
        import_arn=certificate_import_arn,
        tags={
            "Environment": environment,
            "Service": "cerebro",
        },
    )

web_certificate_stack = None
if web_certificate_domain:
    web_certificate_stack = cert.create_certificate(
        name=f"cerebro-{environment}-web",
        domain=web_certificate_domain,
        import_arn=web_certificate_import_arn,
        tags={
            "Environment": environment,
            "Service": "cerebro-web",
        },
    )

load_balancer_certificate_arn = None
if certificate_stack and certificate_domain == domain:
    load_balancer_certificate_arn = certificate_stack["certificate_arn"]

web_load_balancer_certificate_arn = web_certificate_arn or None
if not web_load_balancer_certificate_arn and web_certificate_stack and web_certificate_domain == web_domain:
    web_load_balancer_certificate_arn = web_certificate_stack["certificate_arn"]

alb_stack = load_balancer.create_alb(
    name=f"cerebro-{environment}",
    vpc_id=vpc_stack["vpc_id"],
    subnet_ids=vpc_stack["private_subnet_ids"] if alb_internal else vpc_stack["public_subnet_ids"],
    security_group_id=vpc_stack["alb_security_group_id"],
    certificate_domain=domain or None,
    certificate_arn=load_balancer_certificate_arn,
    internal=alb_internal,
    health_check_path="/health",
    container_port=8080,
    enable_deletion_protection=enable_alb_deletion_protection,
    enable_access_logs=enable_alb_access_logs,
    access_logs_retention_days=alb_access_logs_retention_days,
    idle_timeout_seconds=alb_idle_timeout_seconds,
    allowed_hostnames=[domain] if domain else None,
)

web_alb_stack = None
if web_enabled:
    web_alb_stack = load_balancer.create_alb(
        name=f"cerebro-{environment}-web",
        vpc_id=vpc_stack["vpc_id"],
        subnet_ids=vpc_stack["private_subnet_ids"] if alb_internal else vpc_stack["public_subnet_ids"],
        security_group_id=vpc_stack["alb_security_group_id"],
        certificate_domain=web_domain or None,
        certificate_arn=web_load_balancer_certificate_arn,
        internal=alb_internal,
        health_check_path="/api/health",
        container_port=web_container_port,
        enable_deletion_protection=enable_alb_deletion_protection,
        enable_access_logs=enable_alb_access_logs,
        access_logs_retention_days=alb_access_logs_retention_days,
        allowed_hostnames=[web_domain] if web_domain else None,
        oidc_auth=web_oidc_auth,
        idle_timeout_seconds=web_alb_idle_timeout_seconds,
    )

# =============================================================================
# ECS COMPUTE
# =============================================================================

secret_keys = [
    "CEREBRO_POSTGRES_DSN",
    "CEREBRO_NEO4J_URI",
    "CEREBRO_NEO4J_USERNAME",
    "CEREBRO_NEO4J_PASSWORD",
]
if api_auth_enabled:
    secret_keys.append("CEREBRO_API_KEYS")
    secret_keys.append({"name": "API_KEYS", "source": "CEREBRO_API_KEYS"})
    if api_credentials_secret_name:
        secret_keys.append({"name": "CEREBRO_API_CREDENTIALS_JSON", "source": api_credentials_secret_name})
    if capability_token_secret_name:
        secret_keys.append(_infisical_secret("CEREBRO_CAPABILITY_TOKEN_SECRETS", capability_token_secret_name))
if device_auth_enabled:
    secret_keys.append(_infisical_secret("CEREBRO_DEVICE_AUTH_SIGNING_KEYS_JSON", device_auth_signing_keys_secret_name))
if mcp_oauth_enabled:
    secret_keys.append(_infisical_secret("CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_ID", mcp_oauth_upstream_client_id_secret_name))
    secret_keys.append(_infisical_secret("CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_SECRET", mcp_oauth_upstream_client_secret_name))
if cache_stack:
    secret_keys.append("CEREBRO_CACHE_URL")
secret_keys.extend(_infisical_source_secret(secret_key) for secret_key in source_secret_keys)

app_environment = {
    "CEREBRO_HTTP_ADDR": ":8080",
    "CEREBRO_SHUTDOWN_TIMEOUT": config.get("shutdownTimeout") or "10s",
    "CEREBRO_IMAGE_TAG": image_tag,
    "CEREBRO_API_AUTH_ENABLED": str(api_auth_enabled).lower(),
    "API_AUTH_ENABLED": str(api_auth_enabled).lower(),
    "CEREBRO_PUBLIC_ORIGIN": public_origin,
    "CEREBRO_TRUSTED_PROXY_COUNT": str(trusted_proxy_count),
    "CEREBRO_CAPABILITY_TOKEN_AUDIENCE": capability_token_audience,
    "CEREBRO_APPEND_LOG_DRIVER": "jetstream",
    "CEREBRO_JETSTREAM_URL": nats_stack["url"],
    "CEREBRO_JETSTREAM_SUBJECT_PREFIX": jetstream_subject_prefix,
    "CEREBRO_STATE_STORE_DRIVER": "postgres",
    "CEREBRO_GRAPH_STORE_DRIVER": "neo4j",
}
if not api_auth_enabled:
    app_environment["ALLOW_INSECURE_API"] = "true"
if device_auth_enabled:
    # Replica count is pinned to 1 by the guard above; surface it to the
    # server explicitly so operators reading `aws ecs describe-task-definition`
    # see the in-process DPoP replay protection invariant.
    app_environment["CEREBRO_DEVICE_AUTH_ENABLED"] = "true"
    app_environment["CEREBRO_DEVICE_AUTH_CURRENT_KID"] = device_auth_current_kid
    app_environment["CEREBRO_DEVICE_AUTH_REPLICA_COUNT"] = str(api_max_instances)
    if device_auth_issuer:
        app_environment["CEREBRO_DEVICE_AUTH_ISSUER"] = device_auth_issuer
    if device_auth_audience:
        app_environment["CEREBRO_DEVICE_AUTH_AUDIENCE"] = device_auth_audience
    if device_auth_access_ttl:
        app_environment["CEREBRO_DEVICE_AUTH_ACCESS_TTL"] = device_auth_access_ttl
    if device_auth_refresh_ttl:
        app_environment["CEREBRO_DEVICE_AUTH_REFRESH_TTL"] = device_auth_refresh_ttl
    if device_auth_bootstrap_token_ttl:
        app_environment["CEREBRO_DEVICE_AUTH_BOOTSTRAP_TOKEN_TTL"] = device_auth_bootstrap_token_ttl
    if device_auth_dpop_proof_ttl:
        app_environment["CEREBRO_DEVICE_AUTH_DPOP_PROOF_TTL"] = device_auth_dpop_proof_ttl
    if device_auth_clock_skew:
        app_environment["CEREBRO_DEVICE_AUTH_CLOCK_SKEW"] = device_auth_clock_skew
    if device_auth_idempotency_ttl:
        app_environment["CEREBRO_DEVICE_AUTH_IDEMPOTENCY_TTL"] = device_auth_idempotency_ttl
    if device_auth_attestation_required:
        app_environment["CEREBRO_DEVICE_AUTH_ATTESTATION_REQUIRED"] = "true"
        app_environment["CEREBRO_DEVICE_AUTH_APPLE_TEAM_ID"] = device_auth_apple_team_id
        app_environment["CEREBRO_DEVICE_AUTH_APPLE_BUNDLE_IDS"] = ",".join(device_auth_apple_bundle_ids)
    elif device_auth_apple_team_id:
        app_environment["CEREBRO_DEVICE_AUTH_APPLE_TEAM_ID"] = device_auth_apple_team_id
        if device_auth_apple_bundle_ids:
            app_environment["CEREBRO_DEVICE_AUTH_APPLE_BUNDLE_IDS"] = ",".join(device_auth_apple_bundle_ids)
if neo4j_database:
    app_environment["CEREBRO_NEO4J_DATABASE"] = neo4j_database
if allowed_tenants:
    app_environment["CEREBRO_ALLOWED_TENANTS"] = ",".join(allowed_tenants)
    app_environment["ALLOWED_TENANTS"] = ",".join(allowed_tenants)
if mcp_oauth_enabled:
    app_environment.update({
        "CEREBRO_MCP_OAUTH_ENABLED": "true",
        "CEREBRO_MCP_OAUTH_UPSTREAM_ISSUER": mcp_oauth_upstream_issuer,
        "CEREBRO_MCP_OAUTH_UPSTREAM_REDIRECT_URI": mcp_oauth_upstream_redirect_uri,
        "CEREBRO_MCP_OAUTH_SECURITY_GROUPS": ",".join(mcp_oauth_security_groups),
        "CEREBRO_MCP_OAUTH_DYNAMIC_CLIENT_REGISTRATION_ENABLED": "true",
    })
    if mcp_oauth_tenant_id:
        app_environment["CEREBRO_MCP_OAUTH_TENANT_ID"] = mcp_oauth_tenant_id
    if mcp_oauth_allowed_tenants:
        app_environment["CEREBRO_MCP_OAUTH_ALLOWED_TENANTS"] = ",".join(mcp_oauth_allowed_tenants)
if trusted_proxy_cidrs:
    app_environment["CEREBRO_TRUSTED_PROXY_CIDRS"] = ",".join(trusted_proxy_cidrs)
if source_runtime_env_refs:
    app_environment["CEREBRO_SOURCE_CONFIG_ENV_ALLOWLIST"] = ",".join(source_runtime_env_refs)
if cache_stack:
    app_environment.update({
        "CEREBRO_CACHE_MODE": cache_engine,
        "CEREBRO_CACHE_NAMESPACE": cache_namespace,
        "CEREBRO_CACHE_DEFAULT_TTL": cache_default_ttl,
        "CEREBRO_CACHE_STALE_TTL": cache_stale_ttl,
        "CEREBRO_CACHE_MAX_PAYLOAD_BYTES": str(cache_max_payload_bytes),
    })

graph_agent_llm_provider = config.get("graphAgentLlmProvider")
if graph_agent_llm_provider:
    app_environment["CEREBRO_GRAPH_AGENT_LLM_PROVIDER"] = graph_agent_llm_provider
graph_agent_llm_model = config.get("graphAgentLlmModel")
if graph_agent_llm_model:
    app_environment["CEREBRO_GRAPH_AGENT_LLM_MODEL"] = graph_agent_llm_model
graph_agent_llm_model_sonnet = config.get("graphAgentLlmModelSonnet")
if graph_agent_llm_model_sonnet:
    app_environment["CEREBRO_GRAPH_AGENT_LLM_MODEL_SONNET"] = graph_agent_llm_model_sonnet
graph_agent_llm_model_opus = config.get("graphAgentLlmModelOpus")
if graph_agent_llm_model_opus:
    app_environment["CEREBRO_GRAPH_AGENT_LLM_MODEL_OPUS"] = graph_agent_llm_model_opus
graph_agent_llm_model_haiku = config.get("graphAgentLlmModelHaiku")
if graph_agent_llm_model_haiku:
    app_environment["CEREBRO_GRAPH_AGENT_LLM_MODEL_HAIKU"] = graph_agent_llm_model_haiku
bedrock_region = config.get("bedrockRegion")
if bedrock_region:
    app_environment["CEREBRO_BEDROCK_REGION"] = bedrock_region
openrouter_api_key_secret = config.get("openrouterApiKeySecret")
if openrouter_api_key_secret:
    secret_keys.append({"name": "CEREBRO_OPENROUTER_API_KEY", "source": openrouter_api_key_secret})
bedrock_model_ids = []
if str(graph_agent_llm_provider or "").strip().lower() == "bedrock":
    bedrock_model_ids = [
        model
        for model in [
            graph_agent_llm_model,
            graph_agent_llm_model_sonnet,
            graph_agent_llm_model_opus,
            graph_agent_llm_model_haiku,
        ]
        if model
    ]

runtime_dependencies = [
    postgres_stack["secret_version"],
    nats_stack["service"],
]
if neo4j_secret_stack:
    runtime_dependencies.extend(neo4j_secret_stack["versions"])
if cache_stack:
    runtime_dependencies.append(cache_stack["secret_version"])

ecs_stack = compute.create_ecs_cluster(
    name=f"cerebro-{environment}",
    vpc_id=vpc_stack["vpc_id"],
    subnet_ids=vpc_stack["private_subnet_ids"],
    security_group_id=vpc_stack["app_security_group_id"],
    kms_key_id=kms_key["key_id"],
    target_group_arn=alb_stack["target_group"].arn,
    container_image=container_image,
    alb_arn_suffix=alb_stack["alb"].arn_suffix,
    target_group_arn_suffix=alb_stack["target_group"].arn_suffix,
    api_cpu=api_cpu,
    api_memory=api_memory,
    api_min_instances=api_min_instances,
    api_max_instances=api_max_instances,
    api_request_count_per_target_scaling_target=api_request_count_per_target_scaling_target,
    log_retention_days=log_retention_days,
    environment=app_environment,
    secret_keys=secret_keys,
    external_secrets_prefix=external_secrets_prefix,
    bedrock_model_ids=bedrock_model_ids,
    log_group_kms_key_id=logs_kms_key["key_arn"] if logs_kms_key else None,
    s3_source_iam_configs=s3_source_iam_configs or None,
    depends_on=runtime_dependencies,
    orchestrator_enabled=orchestrator_enabled,
    orchestrator_schedule_expression=orchestrator_schedule_expression,
    orchestrator_cpu=orchestrator_cpu,
    orchestrator_memory=orchestrator_memory,
    orchestrator_command=orchestrator_command,
    orchestrator_task_count=orchestrator_task_count,
    orchestrator_schedules=orchestrator_schedules,
    source_runtimes=source_runtimes,
    source_runtime_service_bootstrap_ids=source_runtime_service_bootstrap_ids,
)

step_functions_stack = resilience.create_orchestrator_step_function(
    name=f"cerebro-{environment}",
    cluster_arn=ecs_stack["cluster"].arn,
    task_definition_arn=ecs_stack["orchestrator_task_definition"].arn if ecs_stack.get("orchestrator_task_definition") else "",
    subnet_ids=vpc_stack["private_subnet_ids"],
    security_group_id=vpc_stack["app_security_group_id"],
    execution_role_arn=ecs_stack["execution_role"].arn,
    task_role_arn=ecs_stack["worker_task_role"].arn if ecs_stack.get("worker_task_role") else ecs_stack["task_role"].arn,
    enabled=orchestrator_step_functions_enabled and bool(ecs_stack.get("orchestrator_task_definition")),
)
if orchestrator_sqs_buffer_enabled and not step_functions_stack.get("state_machine"):
    raise ValueError(
        "cerebro:orchestratorSqsBufferEnabled requires cerebro:orchestratorStepFunctionsEnabled=true "
        "and cerebro:orchestratorEnabled=true"
    )
buffer_stack = resilience.create_orchestrator_buffer(
    name=f"cerebro-{environment}",
    target_state_machine_arn=step_functions_stack["state_machine"].arn if step_functions_stack.get("state_machine") else None,
    enabled=orchestrator_sqs_buffer_enabled,
    desired_state=orchestrator_sqs_buffer_pipe_state,
)
synthetics_stack = resilience.create_synthetic_canary(
    name=f"cerebro-{environment}",
    url=pulumi.Output.concat("https://", domain) if domain else pulumi.Output.concat("http://", alb_stack["alb"].dns_name),
    subnet_ids=vpc_stack["private_subnet_ids"],
    security_group_id=vpc_stack["app_security_group_id"],
    enabled=synthetics_canary_enabled,
    start_canary=synthetics_canary_start,
)

web_stack = None
if web_enabled:
    web_secret_keys = []
    if web_api_key_secret_name:
        web_secret_keys.append({"name": "CEREBRO_API_KEYS", "source": web_api_key_secret_name})

    web_stack = web.create_web_service(
        name=f"cerebro-{environment}-web",
        cluster_id=ecs_stack["cluster"].id,
        cluster_name=ecs_stack["cluster"].name,
        subnet_ids=vpc_stack["private_subnet_ids"],
        security_group_id=vpc_stack["app_security_group_id"],
        target_group_arn=web_alb_stack["target_group"].arn,
        container_image=web_container_image,
        kms_key_id=kms_key["key_id"],
        external_secrets_prefix=external_secrets_prefix,
        cpu=web_cpu,
        memory=web_memory,
        min_instances=web_min_instances,
        max_instances=web_max_instances,
        container_port=web_container_port,
        log_retention_days=log_retention_days,
        log_group_kms_key_id=logs_kms_key["key_arn"] if logs_kms_key else None,
        environment={
            "CEREBRO_API_BASE": web_api_base,
            "CEREBRO_FORWARD_AUTH_HEADERS": str(web_forward_auth_headers).lower(),
            "CEREBRO_PROXY_TIMEOUT_MS": str(web_proxy_timeout_ms),
            "NEXT_TELEMETRY_DISABLED": "1",
        },
        secret_keys=web_secret_keys,
        depends_on=[ecs_stack["capacity_providers"], web_alb_stack["listener"]],
    )

# =============================================================================
# MONITORING / EDGE
# =============================================================================

monitoring_stack = monitoring.create_monitoring(
    name=f"cerebro-{environment}",
    alb_arn_suffix=alb_stack["alb"].arn_suffix,
    target_group_arn_suffix=alb_stack["target_group"].arn_suffix,
    ecs_cluster_name=ecs_stack["cluster"].name,
    ecs_service_name=ecs_stack["api_service"].name,
    postgres_identifier=f"cerebro-{environment}-postgres",
    web_alb_arn_suffix=web_alb_stack["alb"].arn_suffix if web_alb_stack else None,
    web_target_group_arn_suffix=web_alb_stack["target_group"].arn_suffix if web_alb_stack else None,
    web_ecs_service_name=web_stack["service"].name if web_stack else None,
    log_group_name=ecs_stack["log_group"].name,
    log_retention_days=log_retention_days,
    jetstream_stream_name=jetstream_stream_name,
    jetstream_lag_alarm_threshold=jetstream_lag_alarm_threshold,
    api_request_count_per_target_alarm_threshold=api_request_count_per_target_alarm_threshold,
    api_latency_p95_alarm_threshold_seconds=api_latency_p95_alarm_threshold_seconds,
    web_latency_p95_alarm_threshold_seconds=web_latency_p95_alarm_threshold_seconds,
    dashboard_latency_p95_alarm_threshold_ms=dashboard_latency_p95_alarm_threshold_ms,
    access_audit_denied_alarm_threshold=access_audit_denied_alarm_threshold,
    access_audit_auth_failure_alarm_threshold=access_audit_auth_failure_alarm_threshold,
    access_audit_tenant_mismatch_alarm_threshold=access_audit_tenant_mismatch_alarm_threshold,
    access_audit_sensitive_denied_alarm_threshold=access_audit_sensitive_denied_alarm_threshold,
    aws_service_quota_alarm_threshold_percent=aws_service_quota_alarm_threshold_percent,
    alarm_action_arns=alarm_action_arns,
    alarm_email_subscriptions=alarm_email_subscriptions,
    orchestrator_schedules=orchestrator_schedules,
    orchestrator_rule_names=[rule.name for rule in ecs_stack.get("orchestrator_rules", [])],
    orchestrator_scheduler_group_name=ecs_stack["orchestrator_scheduler_group"].name if ecs_stack.get("orchestrator_scheduler_group") else None,
    orchestrator_scheduler_dlq_queue_name=ecs_stack["orchestrator_scheduler_dlq"].name if ecs_stack.get("orchestrator_scheduler_dlq") else None,
    cloudtrail_audit_log_group_name=cloudtrail_audit_log_group_name or None,
    source_runtimes=source_runtimes,
    source_runtime_observability=source_runtime_observability,
)

cost_controls_stack = resilience.create_cost_controls(
    name=f"cerebro-{environment}",
    sns_topic_arns=alarm_action_arns,
    email_subscriptions=alarm_email_subscriptions,
    monthly_budget_usd=monthly_cost_budget_limit_usd,
    anomaly_detection_enabled=cost_anomaly_detection_enabled,
)

waf_stack = None
if enable_waf:
    waf_stack = waf.create_waf(
        name=f"cerebro-{environment}",
        alb_arn=alb_stack["alb"].arn,
        additional_alb_arns=[web_alb_stack["alb"].arn] if web_alb_stack else None,
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
    if not tailscale_advertise_routes:
        raise ValueError("cerebro:tailscaleAdvertiseRoutes must be configured when enableTailscale is true")

    tailscale_auth_key_secret_name = config.get("tailscaleAuthKeySecretName") or f"{external_secrets_prefix}/TAILSCALE_AUTH_KEY"
    tailscale_auth_key_secret = aws.secretsmanager.get_secret(name=tailscale_auth_key_secret_name)

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
# INFISICAL / ECR
# =============================================================================

infisical_stack = None
if enable_infisical and infisical_principal_arn:
    infisical_stack = infisical.create_infisical_sync_role(
        name=f"cerebro-{environment}",
        assume_role_principal_arn=infisical_principal_arn,
        external_id=infisical_external_id,
        kms_key_arn=kms_key["key_arn"],
        secrets_prefix=infisical_secrets_prefix,
    )

repository = ecr.create_ecr_repository(
    name="cerebro",
    enable_immutable_tags=True,
    scan_on_push=True,
    lifecycle_policy_days=30,
    kms_key_arn=kms_key["key_arn"],
)

# =============================================================================
# CLOSEOUT AUDIT BUCKET
# =============================================================================

audit_bucket_stack = None
if pulumi.get_stack() == "sec-dev":
    audit_bucket_stack = audit_storage.create_audit_bucket(
        name=f"cerebro-{environment}",
        bucket_name=f"cerebro-{environment}-audit",
        kms_key_arn=kms_key["key_arn"],
        task_role=ecs_stack["task_role"],
    )
elif pulumi.get_stack() == "go-prod":
    audit_bucket_stack = audit_storage.create_audit_bucket(
        name="cerebro-go-prod",
        bucket_name="cerebro-go-prod-audit",
        kms_key_arn=kms_key["key_arn"],
        task_role=ecs_stack["task_role"],
    )

# =============================================================================
# OUTPUTS
# =============================================================================

pulumi.export("vpc_id", vpc_stack["vpc_id"])
pulumi.export("ecs_cluster_name", ecs_stack["cluster"].name)
pulumi.export("ecs_service_name", ecs_stack["api_service"].name)
pulumi.export("task_role_arn", ecs_stack["task_role"].arn)
if ecs_stack.get("worker_task_role"):
    pulumi.export("worker_task_role_arn", ecs_stack["worker_task_role"].arn)
if web_stack:
    pulumi.export("web_ecs_service_name", web_stack["service"].name)
if ecs_stack.get("orchestrator_task_definition"):
    pulumi.export("orchestrator_task_definition_arn", ecs_stack["orchestrator_task_definition"].arn)
if ecs_stack.get("orchestrator_task_definitions"):
    pulumi.export("orchestrator_task_definition_arns", [task.arn for task in ecs_stack["orchestrator_task_definitions"]])
if ecs_stack.get("orchestrator_rule"):
    pulumi.export("orchestrator_schedule_rule_name", ecs_stack["orchestrator_rule"].name)
if ecs_stack.get("orchestrator_rules"):
    pulumi.export("orchestrator_schedule_rule_names", [rule.name for rule in ecs_stack["orchestrator_rules"]])
if ecs_stack.get("orchestrator_scheduler_group"):
    pulumi.export("orchestrator_scheduler_group_name", ecs_stack["orchestrator_scheduler_group"].name)
if ecs_stack.get("orchestrator_scheduler_dlq"):
    pulumi.export("orchestrator_scheduler_dlq_name", ecs_stack["orchestrator_scheduler_dlq"].name)
if ecs_stack.get("orchestrator_scheduler_schedules"):
    pulumi.export("orchestrator_scheduler_schedule_names", [schedule.name for schedule in ecs_stack["orchestrator_scheduler_schedules"]])
if runtime_controls_stack.get("application"):
    pulumi.export("runtime_controls_appconfig_application_id", runtime_controls_stack["application"].id)
if step_functions_stack.get("state_machine"):
    pulumi.export("orchestrator_state_machine_arn", step_functions_stack["state_machine"].arn)
if buffer_stack.get("queue"):
    pulumi.export("orchestrator_buffer_queue_name", buffer_stack["queue"].name)
if synthetics_stack.get("canary"):
    pulumi.export("synthetics_canary_name", synthetics_stack["canary"].name)
if cost_controls_stack.get("anomaly_monitor"):
    pulumi.export("cost_anomaly_monitor_arn", cost_controls_stack["anomaly_monitor"].arn)
pulumi.export("alb_dns_name", alb_stack["alb"].dns_name)
pulumi.export("api_url", pulumi.Output.concat("https://", domain) if domain else pulumi.Output.concat("http://", alb_stack["alb"].dns_name))
if web_alb_stack:
    pulumi.export("web_alb_dns_name", web_alb_stack["alb"].dns_name)
    pulumi.export("web_url", pulumi.Output.concat("https://", web_domain) if web_domain else pulumi.Output.concat("http://", web_alb_stack["alb"].dns_name))
    if web_domain:
        pulumi.export("web_oidc_redirect_uri", f"https://{web_domain}/oauth2/idpresponse")
pulumi.export("kms_key_id", kms_key["key_id"])
pulumi.export("kms_key_alias", kms_key["alias"].name)
pulumi.export("postgres_endpoint", postgres_stack["instance"].address)
pulumi.export("postgres_secret_name", postgres_stack["secret"].name)
pulumi.export("nats_url", nats_stack["url"])
pulumi.export("jetstream_stream_name", nats_stack["stream_name"])
pulumi.export("jetstream_lag_probe_enabled", nats_stack["lag_probe_enabled"])
if cache_stack:
    pulumi.export("cache_name", cache_stack["cache"].name)
    pulumi.export("cache_secret_name", cache_stack["secret"].name)
if neo4j_stack:
    pulumi.export("neo4j_instance_id", neo4j_stack["instance"].instance_id)
    pulumi.export("neo4j_connection_url", neo4j_stack["instance"].connection_url)
pulumi.export("ecr_repository_url", repository.repository_url)
pulumi.export("ecr_repository_arn", repository.arn)

if certificate_stack:
    pulumi.export("certificate_arn", certificate_stack["certificate_arn"])
    pulumi.export("certificate_validation_records", certificate_stack["validation_records"])
if web_certificate_stack:
    pulumi.export("web_certificate_arn", web_certificate_stack["certificate_arn"])
    pulumi.export("web_certificate_validation_records", web_certificate_stack["validation_records"])
if waf_stack:
    pulumi.export("waf_web_acl_arn", waf_stack["web_acl"].arn)
if logs_kms_key:
    pulumi.export("logs_kms_key_arn", logs_kms_key["key_arn"])
if infisical_stack:
    pulumi.export("infisical_role_arn", infisical_stack["role_arn"])
if tailscale_stack:
    pulumi.export("tailscale_instance_id", tailscale_stack["instance_id"])
    pulumi.export("tailscale_private_ip", tailscale_stack["private_ip"])
if audit_bucket_stack:
    pulumi.export("cerebro_audit_bucket", audit_bucket_stack["bucket"].bucket)
    pulumi.export("cerebro_audit_bucket_kms_key_arn", audit_bucket_stack["kms_key_arn"])
