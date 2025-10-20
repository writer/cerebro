"""Configuration management for Cerebro."""

import os
from typing import Optional, List, Dict
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_DEV_SECRET = "CerebroDevSecret!0123456789$Dev"


class Settings(BaseSettings):
    """Application settings."""
    
    # Database
    database_url: str = Field(
        default="postgresql://user:password@localhost/cerebro",
        description="PostgreSQL database URL"
    )
    
    # Security
    secret_key: str = Field(
        default=DEFAULT_DEV_SECRET,
        description="Secret key for JWT tokens - MUST be set in production"
    )
    algorithm: str = Field(default="HS256", description="JWT algorithm")
    access_token_expire_minutes: int = Field(
        default=30, description="JWT token expiration in minutes"
    )
    refresh_token_expire_days: int = Field(
        default=7, description="JWT refresh token expiration in days"
    )
    
    # GitHub Integration
    github_token: Optional[str] = Field(
        default=None, description="GitHub personal access token"
    )
    
    # AWS Integration
    aws_access_key_id: Optional[str] = Field(
        default=None, description="AWS access key ID"
    )
    aws_secret_access_key: Optional[str] = Field(
        default=None, description="AWS secret access key"
    )
    aws_default_region: str = Field(
        default="us-east-1", description="Default AWS region"
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

    # Collection tuning
    collection_concurrency_limit: int = Field(
        default=10,
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
    claude_model: str = Field(
        default="claude-3-5-sonnet-20241022", 
        description="Claude model to use for agents"
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
    
    # Collection Performance (Phase 1)
    collection_concurrency_limit: int = Field(
        default=16, description="Maximum concurrent config fetches per collection run"
    )
    collection_batch_size: int = Field(
        default=500, description="Batch size for database operations during collection"
    )
    iam_edge_batch_size: int = Field(
        default=1000, description="Batch size for IAM edge insertions"
    )
    
    # API Configuration
    api_base_url: str = Field(
        default="http://localhost:8000",
        description="Base URL for API endpoints (used for JWKS and OpenID configuration)"
    )
    api_title: str = Field(
        default="Cerebro Security API",
        description="API title for OpenAPI documentation"
    )
    api_description: str = Field(
        default="Security compliance and risk management platform",
        description="API description for OpenAPI documentation"
    )
    api_v1_prefix: str = Field(
        default="/api/v1",
        description="API version prefix for all v1 endpoints"
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

    # Environment and Debug Settings
    environment: str = Field(
        default="production",
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
    
    @field_validator('secret_key')
    @classmethod
    def validate_secret_key(cls, v):
        """Validate that secret key is not default value."""
        environment = os.getenv('ENVIRONMENT', 'development').lower()

        if environment in ['dev', 'development', 'test', 'testing']:
            return v

        if not v or v == "your-secret-key-here" or len(v) < 32 or v == DEFAULT_DEV_SECRET:
            raise ValueError(
                "SECRET_KEY must be set to a secure value (minimum 32 characters) in production. "
                "Generate a secure key with: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
            )

        has_lower = any(ch.islower() for ch in v)
        has_digit = any(ch.isdigit() for ch in v)
        has_special = any(not ch.isalnum() for ch in v)

        if not (has_lower and has_digit and has_special):
            raise ValueError(
                "SECRET_KEY must contain at least one lowercase letter, one digit, "
                "and one special character when running in production."
            )
        return v

    @field_validator('kms_provider')
    @classmethod
    def validate_kms_provider(cls, v):
        """Validate KMS provider is secure for production environments."""
        environment = os.getenv('ENVIRONMENT', 'production').lower()

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

    @field_validator('agent_default_runtime')
    @classmethod
    def validate_agent_default_runtime(cls, v: str) -> str:
        runtime = v.lower()
        if runtime not in {'claude', 'openai'}:
            raise ValueError("agent_default_runtime must be either 'claude' or 'openai'")
        return runtime

    @field_validator('enable_provider_env_fallback')
    @classmethod
    def validate_env_fallback(cls, v):
        """Validate provider env fallback is not enabled in production."""
        environment = os.getenv('ENVIRONMENT', 'production').lower()
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
        environment = os.getenv('ENVIRONMENT', 'production').lower()
        if v and environment not in ['dev', 'development', 'test', 'testing']:
            raise ValueError(
                "Debug endpoints are not allowed in production for security reasons. "
                "Set ENABLE_DEBUG_ENDPOINTS=false in production environments."
            )
        return v

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False
    )


settings = Settings()
