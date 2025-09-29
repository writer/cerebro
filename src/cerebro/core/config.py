"""Configuration management for Cerebro."""

import os
from typing import Optional, List
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings."""
    
    # Database
    database_url: str = Field(
        default="postgresql://user:password@localhost/cerebro",
        description="PostgreSQL database URL"
    )
    
    # Security
    secret_key: str = Field(
        description="Secret key for JWT tokens - MUST be set in production"
    )
    algorithm: str = Field(default="HS256", description="JWT algorithm")
    access_token_expire_minutes: int = Field(
        default=30, description="JWT token expiration in minutes"
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
    jwks_cache_ttl_seconds: int = Field(
        default=300, description="JWKS endpoint cache TTL"
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
    collector_rate_limit: int = Field(
        default=10, description="Collector rate limit per second"
    )
    collector_timeout: int = Field(
        default=300, description="Collector timeout in seconds"
    )
    
    # API Configuration
    api_v1_prefix: str = Field(default="/api/v1", description="API v1 prefix")
    api_title: str = Field(
        default="Cerebro Security API", description="API title"
    )
    api_description: str = Field(
        default="Security System of Record API", description="API description"
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
    
    # Key Management Service Configuration
    kms_provider: str = Field(
        default="local", description="KMS provider (aws, gcp, azure, vault, local)"
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
        if v == "your-secret-key-here" or len(v) < 32:
            environment = os.getenv('ENVIRONMENT', 'production').lower()
            if environment not in ['dev', 'development', 'test', 'testing']:
                raise ValueError(
                    "SECRET_KEY must be set to a secure value (minimum 32 characters) in production. "
                    "Generate a secure key with: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
                )
        return v

    @field_validator('kms_provider')
    @classmethod
    def validate_kms_provider(cls, v):
        """Validate KMS provider is not local in production."""
        environment = os.getenv('ENVIRONMENT', 'production').lower()
        if v == "local" and environment not in ['dev', 'development', 'test', 'testing']:
            raise ValueError(
                "Local KMS provider is not allowed in production. "
                "Use aws, gcp, azure, or vault KMS provider for production deployments."
            )
        return v

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

    class Config:
        """Pydantic config."""
        env_file = ".env"
        case_sensitive = False


settings = Settings()
