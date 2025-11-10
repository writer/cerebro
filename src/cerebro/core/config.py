"""Configuration management for Cerebro."""

import logging
import os
from typing import Any, Dict, List, Optional, Set
from uuid import UUID
from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)
_DEV_ENVIRONMENTS = {"dev", "development", "test", "testing"}


_API_SETTING_FIELDS: Set[str] = {
    "api_base_url",
    "api_title",
    "api_description",
    "api_v1_prefix",
    "api_allowed_origins",
    "api_allowed_origins_overrides",
    "api_cors_allow_credentials",
    "api_cors_allow_methods",
    "api_cors_allow_headers",
    "api_default_rate_limits",
    "api_default_rate_limits_overrides",
}

_AGENT_SETTING_FIELDS: Set[str] = {
    "enable_nl_query_translation",
    "claude_model",
    "claude_max_tokens",
    "claude_temperature",
    "openai_api_key",
    "openai_model",
    "openai_embedding_model",
    "enable_agent_metrics",
    "agent_metrics_path",
    "enable_agent_telemetry",
    "enable_agent_memory_embeddings",
    "agent_memory_half_life_hours",
    "agent_memory_decay_boost",
    "agent_memory_decay_cap",
    "agent_memory_summary_max_chars",
    "agent_memory_max_snippets",
    "agent_memory_max_entries_per_org",
    "agent_memory_max_entries_per_session",
    "agent_memory_prune_batch_size",
    "agent_memory_prune_min_decay",
    "agent_memory_prune_max_age_hours",
    "agent_memory_prune_probability",
    "agent_memory_duplicate_window_hours",
    "agent_memory_mmr_lambda",
    "agent_memory_hybrid_alpha",
    "agent_memory_enable_annoy",
    "agent_memory_session_scope_boost",
    "agent_memory_incident_scope_boost",
    "agent_memory_finding_scope_boost",
    "agent_memory_role_weights",
    "agent_memory_decay_profiles",
    "agent_otel_endpoint",
    "agent_otel_headers",
    "agent_otel_timeout_seconds",
    "agent_default_runtime",
    "agent_runtime_preferences",
    "agent_runtime_event_retention_days",
    "agent_session_timeout_hours",
    "agent_default_dry_run",
}

_OPERATIONAL_ALERT_FIELDS: Set[str] = {
    "runtime_health_alert_webhook",
    "runtime_health_alert_window_hours",
    "runtime_health_warning_threshold",
    "runtime_health_error_threshold",
    "operational_alert_slack_webhook",
    "operational_alert_pagerduty_routing_key",
    "operational_alert_email_sender",
    "operational_alert_email_recipients",
    "operational_alert_smtp_host",
    "operational_alert_smtp_port",
    "operational_alert_smtp_username",
    "operational_alert_smtp_password",
    "operational_alert_smtp_use_tls",
    "operational_alert_smtp_use_ssl",
    "operational_integration_stale_hours",
    "operational_integration_stale_overrides",
    "operational_celery_queue_threshold",
    "operational_evidence_stale_hours",
    "operational_db_pool_utilization_threshold",
    "attack_graph_scoring",
}

_SELF_PLAY_FIELDS: Set[str] = {
    "self_play_enabled",
    "self_play_max_turns",
    "self_play_max_tool_calls",
    "self_play_scenario_batch_size",
    "self_play_created_by",
    "self_play_default_org_id",
    "self_play_persist_results",
    "self_play_max_backoff_seconds",
    "self_play_stream_responses",
    "self_play_static_scenarios",
}


class AuthSettings(BaseModel):
    secret_key: Optional[SecretStr] = Field(default=None, alias="secret_key")
    algorithm: str = Field(default="HS256")
    access_token_expire_minutes: int = Field(default=30)
    refresh_token_expire_days: int = Field(default=7)

    model_config = SettingsConfigDict(populate_by_name=True)


class IntegrationRetrySettings(BaseModel):
    enabled: bool = Field(default=True, alias="integration_sync_retry_enabled")
    cooldown_seconds: int = Field(default=3600, alias="integration_sync_retry_cooldown_seconds")
    lookback_minutes: Optional[int] = Field(default=60, alias="integration_sync_retry_lookback_minutes")

    model_config = SettingsConfigDict(populate_by_name=True)


class APISettings(BaseModel):
    api_base_url: str = Field(
        default="http://localhost:8000",
        description="Base URL for API endpoints (used for JWKS and OpenID configuration)",
    )
    api_title: str = Field(
        default="Cerebro Security API",
        description="API title for OpenAPI documentation",
    )
    api_description: str = Field(
        default="Security compliance and risk management platform",
        description="API description for OpenAPI documentation",
    )
    api_v1_prefix: str = Field(
        default="/api/v1",
        description="API version prefix for all v1 endpoints",
    )
    api_allowed_origins: List[str] = Field(
        default_factory=lambda: [
            "http://localhost:3000",
            "http://localhost:8080",
            "https://cerebro.yourdomain.com",
        ],
        description="Allowed CORS origins for the public API",
    )
    api_allowed_origins_overrides: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Environment-specific overrides for allowed CORS origins",
    )
    api_cors_allow_credentials: bool = Field(
        default=True,
        description="Allow credentials (cookies, auth headers) in CORS responses",
    )
    api_cors_allow_methods: List[str] = Field(
        default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        description="HTTP methods permitted by CORS",
    )
    api_cors_allow_headers: List[str] = Field(
        default_factory=lambda: ["Authorization", "Content-Type", "X-Requested-With"],
        description="HTTP headers permitted by CORS",
    )
    api_default_rate_limits: List[str] = Field(
        default_factory=lambda: ["100/minute"],
        description="Default rate limit configuration passed to SlowAPI",
    )
    api_default_rate_limits_overrides: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Environment-specific overrides for rate limits",
    )

    model_config = SettingsConfigDict(populate_by_name=True)

    def get_allowed_origins(self, environment: str) -> List[str]:
        env = environment.lower()
        return self.api_allowed_origins_overrides.get(env, self.api_allowed_origins)

    def get_default_rate_limits(self, environment: str) -> List[str]:
        env = environment.lower()
        return self.api_default_rate_limits_overrides.get(env, self.api_default_rate_limits)


class AgentRuntimeSettings(BaseModel):
    enable_nl_query_translation: bool = Field(
        default=True,
        description="Enable Anthropic-backed natural language SQL translation",
    )
    claude_model: str = Field(
        default="claude-3-5-sonnet-20241022",
        description="Claude model to use for agents",
    )
    claude_max_tokens: int = Field(
        default=8192, description="Maximum tokens per Claude request"
    )
    claude_temperature: float = Field(
        default=0.1, description="Claude temperature (0.0-1.0)"
    )
    openai_api_key: Optional[str] = Field(
        default=None, description="OpenAI API key for Agents runtime"
    )
    openai_model: str = Field(
        default="gpt-4.1", description="OpenAI model for Agents runtime"
    )
    openai_embedding_model: str = Field(
        default="text-embedding-3-small",
        description="OpenAI embedding model for agent memory",
    )
    enable_agent_metrics: bool = Field(
        default=True,
        description="Emit Prometheus metrics for agent runtimes",
    )
    agent_metrics_path: str = Field(
        default="/metrics",
        description="Path exposing Prometheus metrics when enabled",
    )
    enable_agent_telemetry: bool = Field(
        default=False,
        description="Enable OpenTelemetry spans for agent runtimes when tracing is configured",
    )
    enable_agent_memory_embeddings: bool = Field(
        default=True,
        description="Generate embeddings for agent memory store",
    )
    agent_memory_half_life_hours: int = Field(
        default=72,
        description="Half-life window in hours for decaying memory relevance scores",
    )
    agent_memory_decay_boost: float = Field(
        default=0.15,
        description="Increment applied to decay score when a memory snippet is retrieved",
    )
    agent_memory_decay_cap: float = Field(
        default=2.0,
        description="Maximum multiplier applied to memory relevance after repeated access",
    )
    agent_memory_summary_max_chars: int = Field(
        default=240,
        description="Maximum characters to retain in stored memory summaries",
    )
    agent_memory_max_snippets: int = Field(
        default=8,
        description="Maximum number of memory snippets injected into prompts and responses",
    )
    agent_memory_max_entries_per_org: int = Field(
        default=2000,
        description="Maximum number of memory entries retained per organization before pruning",
    )
    agent_memory_max_entries_per_session: int = Field(
        default=500,
        description="Maximum number of memory entries retained per session scope",
    )
    agent_memory_prune_batch_size: int = Field(
        default=200,
        description="How many low-value memory entries to remove per pruning run",
    )
    agent_memory_prune_min_decay: float = Field(
        default=0.05,
        description="Minimum decay score before a memory entry qualifies for pruning",
    )
    agent_memory_prune_max_age_hours: int = Field(
        default=720,
        description="Maximum age in hours before a memory entry is eligible for pruning",
    )
    agent_memory_prune_probability: float = Field(
        default=0.1,
        description="Probability between 0-1 that a pruning run is triggered on write",
    )
    agent_memory_duplicate_window_hours: int = Field(
        default=168,
        description="Window in hours to treat identical content hashes as duplicates",
    )
    agent_memory_mmr_lambda: float = Field(
        default=0.7,
        description="Lambda parameter for Max Marginal Relevance diversification (0-1)",
    )
    agent_memory_hybrid_alpha: float = Field(
        default=0.65,
        description="Weight (0-1) applied to embedding similarity vs lexical similarity when ranking memory",
    )
    agent_memory_enable_annoy: bool = Field(
        default=False,
        description="Enable Annoy approximate nearest neighbor preprocessing for memory retrieval (experimental)",
    )
    agent_memory_session_scope_boost: float = Field(
        default=1.2,
        description="Multiplier applied when a memory entry shares the active session scope",
    )
    agent_memory_incident_scope_boost: float = Field(
        default=1.15,
        description="Multiplier applied when a memory entry matches the active incident scope",
    )
    agent_memory_finding_scope_boost: float = Field(
        default=1.1,
        description="Multiplier applied when a memory entry matches any active finding scope",
    )
    agent_memory_role_weights: Dict[str, float] = Field(
        default_factory=lambda: {
            "assistant": 1.1,
            "user": 1.0,
            "tool": 0.95,
            "system": 0.9,
        },
        description="Relative weighting applied by role when ranking memory snippets",
    )
    agent_memory_decay_profiles: Dict[str, int] = Field(
        default_factory=lambda: {
            "session": 48,
            "incident": 96,
            "finding": 120,
        },
        description="Fallback half-life overrides per scope type (hours)",
    )
    agent_otel_endpoint: Optional[str] = Field(
        default=None,
        description="OTLP HTTP endpoint for exporting agent telemetry spans (e.g., http://collector:4318/v1/traces)",
    )
    agent_otel_headers: Optional[str] = Field(
        default=None,
        description="Comma-separated key=value pairs forwarded as OTLP exporter headers",
    )
    agent_otel_timeout_seconds: int = Field(
        default=5,
        description="Timeout in seconds for OTLP span exporter requests",
    )
    agent_default_runtime: str = Field(
        default="claude",
        description="Default agent runtime backend (claude or openai)",
    )
    agent_runtime_preferences: Dict[str, str] = Field(
        default_factory=lambda: {
            "security_analyst": "claude",
            "incident_responder": "claude",
            "identity_advisor": "openai",
            "analysis": "openai",
            "incident_response": "claude",
            "remediation": "claude",
            "reporting": "openai",
        },
        description="Preference map guiding runtime selection by agent type or skill tag",
    )
    agent_runtime_event_retention_days: int = Field(
        default=30,
        description="Number of days to retain agent runtime analytics events",
    )
    agent_session_timeout_hours: int = Field(
        default=24, description="Agent session timeout in hours"
    )
    agent_default_dry_run: bool = Field(
        default=True, description="Default to dry-run for destructive agent actions"
    )

    model_config = SettingsConfigDict(populate_by_name=True)

    @field_validator("agent_default_runtime")
    @classmethod
    def validate_agent_default_runtime(cls, v: str) -> str:
        runtime = v.lower()
        if runtime not in {"claude", "openai"}:
            raise ValueError("agent_default_runtime must be either 'claude' or 'openai'")
        return runtime


class OperationalAlertSettings(BaseModel):
    runtime_health_alert_webhook: Optional[str] = Field(
        default=None,
        description="Slack webhook URL for runtime health alerts",
    )
    runtime_health_alert_window_hours: int = Field(
        default=1,
        description="Lookback window in hours when evaluating runtime health alerts",
    )
    runtime_health_warning_threshold: int = Field(
        default=3,
        description="Runtime warning count threshold that triggers an alert",
    )
    runtime_health_error_threshold: int = Field(
        default=1,
        description="Runtime error count threshold that triggers a critical alert",
    )
    operational_alert_slack_webhook: Optional[str] = Field(
        default=None,
        description="Slack webhook URL for operational health alerts",
    )
    operational_alert_pagerduty_routing_key: Optional[str] = Field(
        default=None,
        description="PagerDuty Events API v2 routing key for operational alerts",
    )
    operational_alert_email_sender: Optional[str] = Field(
        default=None,
        description="Sender email address used when dispatching operational alert emails",
    )
    operational_alert_email_recipients: List[str] = Field(
        default_factory=list,
        description="Email recipients for operational alert notifications",
    )
    operational_alert_smtp_host: Optional[str] = Field(
        default=None,
        description="SMTP host used for operational alert emails",
    )
    operational_alert_smtp_port: int = Field(
        default=587,
        description="SMTP port used for operational alert emails",
    )
    operational_alert_smtp_username: Optional[str] = Field(
        default=None,
        description="SMTP username used for operational alert emails",
    )
    operational_alert_smtp_password: Optional[str] = Field(
        default=None,
        description="SMTP password used for operational alert emails",
    )
    operational_alert_smtp_use_tls: bool = Field(
        default=True,
        description="Use STARTTLS when sending operational alert emails",
    )
    operational_alert_smtp_use_ssl: bool = Field(
        default=False,
        description="Use implicit TLS (SMTPS) when sending operational alert emails",
    )
    operational_integration_stale_hours: int = Field(
        default=2,
        description="Hours without successful integration sync before raising an operational alert",
    )
    operational_integration_stale_overrides: Dict[str, int] = Field(
        default_factory=dict,
        description="Override integration stale thresholds in hours using partial integration name matches",
    )
    operational_celery_queue_threshold: int = Field(
        default=1000,
        description="Threshold for queued Celery tasks that triggers an operational alert",
    )
    operational_evidence_stale_hours: int = Field(
        default=3,
        description="Hours without evidence collection updates before sending email alerts",
    )
    operational_db_pool_utilization_threshold: float = Field(
        default=0.9,
        description="Database connection pool utilization threshold that triggers an operational alert",
    )
    attack_graph_scoring: Dict[str, Any] = Field(
        default_factory=dict,
        description="Configuration overrides for attack graph scoring weights",
    )

    model_config = SettingsConfigDict(populate_by_name=True)


class SelfPlaySettings(BaseModel):
    self_play_enabled: bool = Field(
        default=False,
        description="Enable agent self-play orchestration",
    )
    self_play_max_turns: int = Field(
        default=10,
        ge=1,
        description="Maximum turns per self-play match",
    )
    self_play_max_tool_calls: int = Field(
        default=20,
        ge=0,
        description="Maximum tool invocations per self-play match",
    )
    self_play_scenario_batch_size: int = Field(
        default=3,
        ge=1,
        description="Number of self-play scenarios processed per batch",
    )
    self_play_created_by: str = Field(
        default="self_play_orchestrator",
        description="Synthetic user identifier recorded on self-play sessions",
    )
    self_play_default_org_id: Optional[str] = Field(
        default=None,
        description="Override organization identifier used for self-play sessions",
    )
    self_play_persist_results: bool = Field(
        default=False,
        description="Persist self-play outcomes in the database",
    )
    self_play_max_backoff_seconds: int = Field(
        default=60,
        ge=1,
        description="Maximum delay applied between failed self-play matches",
    )
    self_play_stream_responses: bool = Field(
        default=True,
        description="Stream agent responses during self-play to capture transcript data",
    )
    self_play_static_scenarios: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Optional static scenario definitions for self-play runs",
    )

    model_config = SettingsConfigDict(populate_by_name=True)


class Settings(BaseSettings):
    @model_validator(mode="before")
    @classmethod
    def _migrate_legacy_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        auth_keys = (
            "secret_key",
            "algorithm",
            "access_token_expire_minutes",
            "refresh_token_expire_days",
        )
        legacy_auth = {key: data.pop(key) for key in auth_keys if key in data}
        if legacy_auth:
            auth_section = data.setdefault("auth", {})
            auth_section.update(legacy_auth)

        retry_keys = (
            "integration_sync_retry_enabled",
            "integration_sync_retry_cooldown_seconds",
            "integration_sync_retry_lookback_minutes",
        )
        legacy_retry = {key: data.pop(key) for key in retry_keys if key in data}
        if legacy_retry:
            retry_section = data.setdefault("integration_retry", {})
            retry_section.update(legacy_retry)

        for section_name, field_names in (
            ("api", _API_SETTING_FIELDS),
            ("agent", _AGENT_SETTING_FIELDS),
            ("operational_alerts", _OPERATIONAL_ALERT_FIELDS),
            ("self_play", _SELF_PLAY_FIELDS),
        ):
            legacy_section = {
                key: data.pop(key)
                for key in field_names
                if key in data
            }
            if legacy_section:
                section_data: Dict[str, Any] = data.setdefault(section_name, {})
                section_data.update(legacy_section)

        return data

    """Application settings."""

    # Database
    database_url: str = Field(
        default="postgresql://user:password@localhost/cerebro",
        description="PostgreSQL database URL"
    )
    
    # Security
    auth: AuthSettings = Field(default_factory=AuthSettings)
    api: APISettings = Field(default_factory=APISettings)
    
    # GitHub Integration
    github_token: Optional[str] = Field(
        default=None,
        description="GitHub personal access token used by the GitHub provider",
    )
    
    # AWS Integration
    aws_access_key_id: Optional[str] = Field(
        default=None,
        description="AWS access key ID used for collection workloads",
    )
    aws_secret_access_key: Optional[str] = Field(
        default=None,
        description="AWS secret access key paired with ``aws_access_key_id``",
    )
    aws_default_region: str = Field(
        default="us-east-1",
        description="Fallback AWS region when an account does not specify one",
    )
    
    # Google Cloud Integration
    google_application_credentials: Optional[str] = Field(
        default=None, description="Path to GCP service account credentials"
    )
    gcp_project_id: Optional[str] = Field(
        default=None, description="GCP project ID"
    )
    
    # Google Workspace Integration
    google_workspace_admin_email: Optional[str] = Field(
        default=None, description="Google Workspace admin email"
    )
    google_workspace_customer_id: Optional[str] = Field(
        default=None, description="Google Workspace customer ID"
    )

    # Slack Integration
    slack_signing_secret: Optional[str] = Field(
        default=None,
        description="Slack signing secret for verifying slash command signatures",
    )
    slack_bot_token: Optional[str] = Field(
        default=None,
        description="Slack bot token used for posting messages and notifications",
    )
    slack_default_org_id: Optional[UUID] = Field(
        default=None,
        description="Fallback organization ID for Slack commands when workspace mapping is unavailable",
    )

    # Collection tuning
    collection_concurrency_limit: int = Field(
        default=16,
        ge=1,
        le=50,
        description="Maximum number of concurrent resource configuration fetches per provider",
    )
    
    # Okta Integration
    okta_api_token: Optional[str] = Field(
        default=None, description="Okta API token"
    )
    okta_domain: Optional[str] = Field(
        default=None, description="Okta domain (e.g., company.okta.com)"
    )
    
    # Microsoft 365 Integration
    m365_tenant_id: Optional[str] = Field(
        default=None, description="Microsoft 365 tenant ID"
    )
    m365_client_id: Optional[str] = Field(
        default=None, description="Microsoft 365 application client ID"
    )
    m365_client_secret: Optional[str] = Field(
        default=None, description="Microsoft 365 application client secret"
    )

    # SentinelOne Integration
    sentinelone_enabled: bool = Field(
        default=False, description="Enable SentinelOne activity ingestion"
    )
    sentinelone_api_base_url: Optional[str] = Field(
        default=None, description="Base URL for the SentinelOne management API"
    )
    sentinelone_api_token: Optional[str] = Field(
        default=None, description="SentinelOne API token"
    )
    sentinelone_org_name: Optional[str] = Field(
        default=None, description="Organization label applied to SentinelOne events"
    )
    sentinelone_site: Optional[str] = Field(
        default=None, description="Optional site tag applied to SentinelOne events"
    )
    sentinelone_verify_tls: bool = Field(
        default=True, description="Verify TLS certificates for SentinelOne requests"
    )

    # Kandji Integration
    kandji_enabled: bool = Field(
        default=False, description="Enable Kandji device ingestion"
    )
    kandji_api_base_url: Optional[str] = Field(
        default=None, description="Base URL for the Kandji tenant (https://subdomain.api.kandji.io)"
    )
    kandji_api_token: Optional[str] = Field(
        default=None, description="Kandji API token"
    )
    kandji_org_name: Optional[str] = Field(
        default=None, description="Organization label applied to Kandji devices"
    )
    kandji_site: Optional[str] = Field(
        default=None, description="Optional site tag applied to Kandji telemetry"
    )
    kandji_verify_tls: bool = Field(
        default=True, description="Verify TLS certificates for Kandji requests"
    )

    integration_sync_stale_seconds: int = Field(
        default=3600,
        description="Seconds after which an integration sync is considered stale",
    )
    integration_sync_alert_cooldown_seconds: int = Field(
        default=1800,
        description="Cooldown period in seconds before repeating integration sync alerts",
    )
    integration_sync_alert_webhook: Optional[str] = Field(
        default=None,
        description="Slack webhook URL used for integration sync health alerts",
    )
    integration_coverage_alert_webhook: Optional[str] = Field(
        default=None,
        description="Slack webhook URL used for integration coverage alerts",
    )
    integration_coverage_warning_threshold: float = Field(
        default=0.7,
        description="Coverage ratio threshold below which a warning alert is sent",
    )
    integration_coverage_critical_threshold: float = Field(
        default=0.4,
        description="Coverage ratio threshold below which a critical alert is sent",
    )
    integration_retry: IntegrationRetrySettings = Field(default_factory=IntegrationRetrySettings)
    
    # Logging
    log_level: str = Field(default="INFO", description="Log level")
    log_format: str = Field(default="json", description="Log format")
    
    # Rule Engine
    cel_cache_size: int = Field(
        default=1000, description="CEL expression cache size"
    )
    cel_compilation_timeout: int = Field(
        default=30, description="CEL compilation timeout in seconds"
    )
    
    # Claude Code SDK / AI Agents
    anthropic_api_key: Optional[str] = Field(
        default=None, description="Anthropic API key for Claude integration"
    )
    agent: AgentRuntimeSettings = Field(default_factory=AgentRuntimeSettings)
    operational_alerts: OperationalAlertSettings = Field(default_factory=OperationalAlertSettings)
    self_play: SelfPlaySettings = Field(default_factory=SelfPlaySettings)
    
    # Collection Performance (Phase 1)
    collection_batch_size: int = Field(
        default=500, description="Batch size for database operations during collection"
    )
    iam_edge_batch_size: int = Field(
        default=1000, description="Batch size for IAM edge insertions"
    )
    
    # JWT Security (Phase 2)
    jwt_algorithm: str = Field(
        default="RS256", description="JWT signing algorithm (RS256 recommended for production)"
    )
    jwt_rotation_period_hours: int = Field(
        default=24, description="Hours between JWT key rotations"
    )
    jwt_key_overlap_hours: int = Field(
        default=48, description="Hours to keep old keys for seamless rotation"
    )
    jwt_clock_skew_seconds: int = Field(
        default=1, description="Allowed clock skew (seconds) for JWT validation"
    )
    jwks_cache_ttl_seconds: int = Field(
        default=300, description="JWKS endpoint cache TTL"
    )
    jwt_public_key_cache_ttl_seconds: int = Field(
        default=600,
        description="TTL in seconds for cached JWT verification public keys",
    )
    jwt_rotation_check_interval_seconds: int = Field(
        default=300,
        description="Interval in seconds for background JWT rotation checks",
    )

    access_token_cookie_name: str = Field(
        default="cerebro_access_token",
        description="HTTP cookie name storing the access token",
    )
    refresh_token_cookie_name: str = Field(
        default="cerebro_refresh_token",
        description="HTTP cookie name storing the refresh token",
    )
    auth_cookie_domain: Optional[str] = Field(
        default=None,
        description="Optional cookie domain override for authentication cookies",
    )
    auth_cookie_path: str = Field(
        default="/",
        description="Cookie path applied to authentication cookies",
    )
    auth_cookie_secure: bool = Field(
        default=True,
        description="Mark authentication cookies as Secure (HTTPS only)",
    )
    auth_cookie_same_site: str = Field(
        default="lax",
        description="SameSite mode for authentication cookies (lax, strict, none)",
    )
    csrf_cookie_name: str = Field(
        default="cerebro_csrf_token",
        description="Cookie storing CSRF token for double-submit defense",
    )
    csrf_cookie_secure: bool = Field(
        default=True,
        description="Mark CSRF cookie as Secure (HTTPS only)",
    )
    csrf_cookie_same_site: str = Field(
        default="lax",
        description="SameSite policy for CSRF cookie",
    )
    csrf_header_name: str = Field(
        default="X-CSRF-Token",
        description="Header expected to mirror the CSRF token",
    )

    # Environment and Debug Settings
    environment: str = Field(
        default="development",
        description="Environment: dev, development, test, testing, production"
    )
    enable_debug_endpoints: bool = Field(
        default=False,
        description="Enable debug endpoints (should be False in production)"
    )
    
    # Rate Limiting & Lockout (Phase 3)
    rate_limit_login_per_ip: int = Field(
        default=10, description="Login attempts per IP per minute"
    )
    rate_limit_login_per_user: int = Field(
        default=5, description="Login attempts per user per minute"
    )
    lockout_threshold: int = Field(
        default=5, description="Failed attempts before account lockout"
    )
    lockout_window_minutes: int = Field(
        default=15, description="Time window for counting failed attempts"
    )
    lockout_duration_minutes: int = Field(
        default=30, description="Duration of account lockout"
    )
    lockout_max_duration_hours: int = Field(
        default=24, description="Maximum lockout duration for repeated offenses"
    )
    
    # Credential Management (Phase 4)
    enable_provider_env_fallback: bool = Field(
        default=False, description="Allow fallback to environment variables for provider credentials"
    )
    credential_refresh_threshold_hours: int = Field(
        default=1, description="Hours before expiry to refresh credentials"
    )
    
    # Collectors
    collector_batch_size: int = Field(
        default=100, description="Collector batch size"
    )

    # Notifications
    notification_recipients: List[str] = Field(
        default=["admin@localhost"],
        description="Email addresses for collection completion and error notifications"
    )
    notification_sender_email: str = Field(
        default="noreply@cerebro.security",
        description="Sender email address for notifications"
    )
    collector_rate_limit: int = Field(
        default=10, description="Collector rate limit per second"
    )
    collector_timeout: int = Field(
        default=300, description="Collector timeout in seconds"
    )
    
    # Redis/Celery Configuration
    redis_url: str = Field(
        default="redis://localhost:6379/0", description="Redis URL for Celery"
    )
    celery_broker_url: Optional[str] = Field(
        default=None, description="Celery broker URL (defaults to redis_url)"
    )
    celery_result_backend: Optional[str] = Field(
        default=None, description="Celery result backend (defaults to redis_url)"
    )

    @property
    def effective_celery_broker_url(self) -> str:
        """Return broker URL falling back to Redis when unset."""

        return self.celery_broker_url or self.redis_url

    @property
    def effective_celery_result_backend(self) -> str:
        """Return result backend URL falling back to Redis when unset."""

        return self.celery_result_backend or self.redis_url

    def get_allowed_origins(self) -> List[str]:
        return self.api.get_allowed_origins(self.environment)

    def get_default_rate_limits(self) -> List[str]:
        return self.api.get_default_rate_limits(self.environment)
    
    # Key Management Service Configuration
    kms_provider: str = Field(
        default="local", description="KMS provider (aws, gcp, azure, vault, local) - local only for development"
    )
    
    # AWS KMS
    aws_kms_key_id: Optional[str] = Field(
        default=None, description="AWS KMS key ID for envelope encryption"
    )
    aws_kms_region: Optional[str] = Field(
        default=None, description="AWS KMS region (defaults to aws_default_region)"
    )
    
    # GCP KMS  
    gcp_kms_key_name: Optional[str] = Field(
        default=None, description="GCP KMS key resource name"
    )
    
    # Azure Key Vault
    azure_vault_url: Optional[str] = Field(
        default=None, description="Azure Key Vault URL"
    )
    azure_key_name: Optional[str] = Field(
        default=None, description="Azure Key Vault key name"
    )
    
    # HashiCorp Vault
    vault_url: Optional[str] = Field(
        default=None, description="Vault server URL"
    )
    vault_mount_path: str = Field(
        default="transit", description="Vault transit mount path"
    )
    vault_key_name: Optional[str] = Field(
        default=None, description="Vault transit key name"
    )
    
    @field_validator('kms_provider')
    @classmethod
    def validate_kms_provider(cls, v):
        """Validate KMS provider is secure for production environments."""
        environment = os.getenv('ENVIRONMENT', 'development').lower()

        if v == "local":
            if environment not in ['dev', 'development', 'test', 'testing']:
                raise ValueError(
                    "Local KMS provider is INSECURE and not allowed in production. "
                    "Local KMS uses predictable key derivation and is only suitable for development. "
                    "Use aws, gcp, azure, or vault KMS provider for production deployments."
                )
            # Warn even in development
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(
                "Using local KMS provider with predictable key derivation. "
                "This is insecure and should only be used for development/testing."
            )

        # Validate that the provider is supported
        valid_providers = {'aws', 'gcp', 'azure', 'vault', 'local'}
        if v not in valid_providers:
            raise ValueError(
                f"Invalid KMS provider '{v}'. Must be one of: {', '.join(sorted(valid_providers))}"
            )

        return v

    @field_validator('enable_provider_env_fallback')
    @classmethod
    def validate_env_fallback(cls, v):
        """Validate provider env fallback is not enabled in production."""
        environment = os.getenv('ENVIRONMENT', 'development').lower()
        if v and environment not in ['dev', 'development', 'test', 'testing']:
            raise ValueError(
                "Provider environment variable fallback is not allowed in production. "
                "Store credentials securely using the CredentialService with KMS encryption."
            )
        return v

    @field_validator('enable_debug_endpoints')
    @classmethod
    def validate_debug_endpoints(cls, v):
        """Validate debug endpoints are not enabled in production."""
        environment = os.getenv('ENVIRONMENT', 'development').lower()
        if v and environment not in ['dev', 'development', 'test', 'testing']:
            raise ValueError(
                "Debug endpoints are not allowed in production for security reasons. "
                "Set ENABLE_DEBUG_ENDPOINTS=false in production environments."
            )
        return v

    @field_validator('auth_cookie_same_site')
    @classmethod
    def validate_same_site(cls, v: str) -> str:
        allowed = {'lax', 'strict', 'none'}
        normalized = v.lower()
        if normalized not in allowed:
            allowed_list = ', '.join(sorted(allowed))
            raise ValueError(f"auth_cookie_same_site must be one of: {allowed_list}")
        return normalized

    @field_validator('csrf_cookie_same_site')
    @classmethod
    def validate_csrf_same_site(cls, v: str) -> str:
        allowed = {'lax', 'strict', 'none'}
        normalized = v.lower()
        if normalized not in allowed:
            allowed_list = ', '.join(sorted(allowed))
            raise ValueError(f"csrf_cookie_same_site must be one of: {allowed_list}")
        return normalized

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        env_nested_delimiter="__",
        populate_by_name=True,
        extra="allow",
    )

    @model_validator(mode="after")
    def _validate_auth(self) -> "Settings":
        env = (self.environment or "development").lower()
        if env not in _DEV_ENVIRONMENTS:
            secret = self.auth.secret_key
            if secret is None or not secret.get_secret_value().strip():
                raise ValueError(
                    "SECRET_KEY must be configured for non-development environments."
                )
        return self

    @property
    def secret_key(self) -> str:
        if self.auth.secret_key is None:
            return ""
        return self.auth.secret_key.get_secret_value()

    @property
    def algorithm(self) -> str:
        return self.auth.algorithm

    @property
    def access_token_expire_minutes(self) -> int:
        return self.auth.access_token_expire_minutes

    @property
    def refresh_token_expire_days(self) -> int:
        return self.auth.refresh_token_expire_days

    @property
    def integration_sync_retry_enabled(self) -> bool:
        return self.integration_retry.enabled

    @property
    def integration_sync_retry_cooldown_seconds(self) -> int:
        return self.integration_retry.cooldown_seconds

    @property
    def integration_sync_retry_lookback_minutes(self) -> Optional[int]:
        return self.integration_retry.lookback_minutes

    def __getattr__(self, item: str):
        if item in _API_SETTING_FIELDS:
            return getattr(self.api, item)
        if item in _AGENT_SETTING_FIELDS:
            return getattr(self.agent, item)
        if item in _OPERATIONAL_ALERT_FIELDS:
            return getattr(self.operational_alerts, item)
        if item in _SELF_PLAY_FIELDS:
            return getattr(self.self_play, item)
        raise AttributeError(f"{type(self).__name__!s} object has no attribute {item!r}")


settings = Settings()
