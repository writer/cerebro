use std::fmt;

/// Bounded, provider-specific Tailscale failure taxonomy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailscaleError {
    /// Required public configuration is absent.
    MissingConfiguration(&'static str),
    /// Public configuration is malformed or outside its bound.
    InvalidConfiguration(&'static str),
    /// Base URL is not a credential-free HTTPS origin.
    InvalidBaseUrl,
    /// Request escaped the configured provider origin.
    InvalidOrigin,
    /// Authenticated tenant scope is missing or malformed.
    InvalidTenantId,
    /// Named credential reference is absent in the trusted host.
    MissingCredentialReference,
    /// Trusted host could not redeem its credential lease.
    CredentialUnavailable,
    /// Provider rejected authentication.
    AuthenticationRejected,
    /// Provider rejected the credential's scope.
    RequiredScopeMissing,
    /// Trusted host denied provider egress.
    EgressDenied,
    /// Provider DNS resolution failed.
    DnsFailure,
    /// Provider connection failed.
    ConnectionFailure,
    /// Provider deadline expired.
    ProviderTimeout,
    /// Provider requested a retry.
    RateLimited {
        /// Bounded provider retry delay.
        retry_after_seconds: Option<u64>,
    },
    /// Provider is temporarily unavailable.
    ProviderUnavailable {
        /// Provider HTTP status.
        status: u16,
    },
    /// Provider returned an unexpected status.
    UnexpectedStatus {
        /// Provider HTTP status.
        status: u16,
    },
    /// Retry-After exceeded the bounded host contract.
    InvalidRetryAfter,
    /// Response exceeded the declared byte limit.
    ResponseTooLarge,
    /// Response did not match the family envelope.
    MalformedResponse,
    /// Response contained more records than allowed.
    TooManyRecords,
    /// A provider record was malformed.
    InvalidProviderRecord,
    /// Provider record lacked stable identity.
    MissingStableIdentity,
    /// Cursor was invalid, repeated, or not round-trippable.
    InvalidCursor,
    /// Provider payload tried to supply authenticated tenant scope.
    TenantMismatch,
    /// Provider payload contained credential-shaped material.
    CredentialMaterial,
    /// Duplicate identity carried conflicting content.
    ConflictingDuplicate,
    /// Request did not belong to this kernel instance.
    RequestScopeMismatch,
    /// Event failed the exact compiled contract.
    EventContractRejected,
    /// Append failed after successful normalization.
    AppendFailure,
    /// Projection failed after append.
    ProjectionFailure,
    /// Runtime lease was lost.
    LeaseLoss,
    /// Runtime generation or authority is stale.
    StaleAuthority,
    /// Family is outside the closed catalog.
    UnknownFamily,
    /// Checked-in catalog and runtime definition disagree.
    InvalidCatalogContract,
    /// Internal bounded runtime failure.
    InternalRuntimeFailure,
}

impl TailscaleError {
    /// Stable error class suitable for bounded receipts.
    pub const fn class(&self) -> &'static str {
        match self {
            Self::MissingConfiguration(_) => "missing_configuration",
            Self::InvalidConfiguration(_) => "invalid_configuration",
            Self::InvalidBaseUrl => "invalid_base_url",
            Self::InvalidOrigin => "egress_denied",
            Self::InvalidTenantId => "invalid_tenant",
            Self::MissingCredentialReference => "missing_credential_reference",
            Self::CredentialUnavailable => "credential_unavailable",
            Self::AuthenticationRejected => "authentication_rejected",
            Self::RequiredScopeMissing => "required_scope_missing",
            Self::EgressDenied => "egress_denied",
            Self::DnsFailure => "dns_failure",
            Self::ConnectionFailure => "connection_failure",
            Self::ProviderTimeout => "provider_timeout",
            Self::RateLimited { .. } => "provider_rate_limit",
            Self::ProviderUnavailable { .. } => "provider_unavailable",
            Self::UnexpectedStatus { .. } => "unexpected_provider_status",
            Self::InvalidRetryAfter => "invalid_retry_after",
            Self::ResponseTooLarge => "response_too_large",
            Self::MalformedResponse => "malformed_response",
            Self::TooManyRecords => "record_limit_exceeded",
            Self::InvalidProviderRecord => "invalid_provider_record",
            Self::MissingStableIdentity => "missing_stable_identity",
            Self::InvalidCursor => "invalid_cursor",
            Self::TenantMismatch => "tenant_mismatch",
            Self::CredentialMaterial => "credential_material",
            Self::ConflictingDuplicate => "conflicting_duplicate",
            Self::RequestScopeMismatch => "request_scope_mismatch",
            Self::EventContractRejected => "event_contract_rejection",
            Self::AppendFailure => "append_failure",
            Self::ProjectionFailure => "projection_failure",
            Self::LeaseLoss => "lease_loss",
            Self::StaleAuthority => "stale_authority",
            Self::UnknownFamily => "unknown_family",
            Self::InvalidCatalogContract => "invalid_catalog_contract",
            Self::InternalRuntimeFailure => "internal_runtime_failure",
        }
    }

    /// Next valid operator action without provider payload or credential data.
    pub const fn operator_action(&self) -> &'static str {
        match self {
            Self::MissingConfiguration(_)
            | Self::InvalidConfiguration(_)
            | Self::InvalidBaseUrl => "repair source configuration",
            Self::MissingCredentialReference | Self::CredentialUnavailable => {
                "repair credential binding"
            }
            Self::AuthenticationRejected => "replace or reauthorize credential",
            Self::RequiredScopeMissing => "grant required Tailscale read scope",
            Self::RateLimited { .. } | Self::ProviderUnavailable { .. } | Self::ProviderTimeout => {
                "retry later"
            }
            Self::EgressDenied
            | Self::InvalidOrigin
            | Self::DnsFailure
            | Self::ConnectionFailure => "repair provider egress",
            Self::MalformedResponse
            | Self::TooManyRecords
            | Self::InvalidProviderRecord
            | Self::MissingStableIdentity
            | Self::CredentialMaterial
            | Self::TenantMismatch
            | Self::EventContractRejected
            | Self::ConflictingDuplicate => "inspect quarantined records",
            Self::InvalidCursor => "restart collection from last committed checkpoint",
            _ => "repair forward runtime implementation",
        }
    }
}

impl fmt::Display for TailscaleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.class())
    }
}

impl std::error::Error for TailscaleError {}
