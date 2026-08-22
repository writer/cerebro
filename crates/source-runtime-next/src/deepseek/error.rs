use std::{error::Error, fmt};

/// Stable, bounded DeepSeek runtime failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeepSeekError {
    /// Unknown family.
    InvalidFamily,
    /// Required public configuration is missing.
    MissingConfiguration(&'static str),
    /// Public configuration is invalid.
    InvalidConfiguration(&'static str),
    /// Base URL is malformed.
    InvalidBaseUrl,
    /// Base URL is outside the provider origin.
    UnsafeOrigin,
    /// Tenant context is invalid.
    InvalidTenantId,
    /// Credential reference is absent at the trusted host boundary.
    MissingCredentialReference,
    /// Credential lease cannot be redeemed by the trusted host.
    CredentialUnavailable,
    /// Cursor is invalid for a non-paginated operation.
    InvalidCursor,
    /// Request was not produced by this kernel.
    RequestScopeMismatch,
    /// Provider rejected authentication.
    AuthenticationRejected,
    /// Provider credential lacks required access.
    RequiredScopeMissing,
    /// Provider account has insufficient balance.
    InsufficientBalance,
    /// Trusted host denied provider egress.
    EgressDenied,
    /// Provider DNS lookup failed.
    DnsFailure,
    /// Provider connection failed.
    ConnectionFailure,
    /// Provider operation timed out.
    ProviderTimeout,
    /// Provider rate limit with an optional bounded retry delay.
    RateLimited {
        /// Provider retry delay in seconds.
        retry_after_seconds: Option<u64>,
    },
    /// Provider is temporarily unavailable.
    ProviderUnavailable {
        /// Provider HTTP status.
        status: u16,
    },
    /// Provider returned an unrecognized status.
    UnexpectedStatus {
        /// Provider HTTP status.
        status: u16,
    },
    /// Provider retry delay exceeds the runtime bound.
    InvalidRetryAfter,
    /// Response exceeded the byte bound.
    ResponseTooLarge,
    /// Response exceeded the record bound.
    TooManyRecords,
    /// Provider response shape is malformed.
    MalformedResponse,
    /// Provider record is structurally invalid.
    InvalidProviderRecord,
    /// Provider record lacks stable identity.
    MissingStableIdentity,
    /// Observation timestamp is invalid.
    InvalidObservedAt,
    /// Provider payload tried to supply tenant context.
    TenantMismatch,
    /// Provider payload contains credential-shaped material.
    CredentialMaterial,
    /// Same provider identity carried conflicting content.
    ConflictingDuplicate,
    /// Normalized event failed the compiled catalog contract.
    EventContractRejection,
    /// Durable append failed.
    AppendFailure,
    /// Projection failed.
    ProjectionFailure,
    /// Runtime lost its lease.
    LeaseLoss,
    /// Runtime authority or generation is stale.
    StaleAuthority,
    /// Internal runtime invariant failed.
    InternalRuntimeFailure,
}

impl DeepSeekError {
    /// Next valid operator action for this failure class.
    pub const fn operator_action(&self) -> &'static str {
        match self {
            Self::MissingConfiguration(_)
            | Self::InvalidConfiguration(_)
            | Self::InvalidBaseUrl
            | Self::UnsafeOrigin
            | Self::InvalidTenantId => "repair source configuration",
            Self::MissingCredentialReference | Self::CredentialUnavailable => {
                "repair credential binding"
            }
            Self::AuthenticationRejected => "repair the credential",
            Self::RequiredScopeMissing => "grant DeepSeek read scope",
            Self::InsufficientBalance => "top up the DeepSeek account",
            Self::RateLimited { .. }
            | Self::ProviderUnavailable { .. }
            | Self::DnsFailure
            | Self::ConnectionFailure
            | Self::ProviderTimeout => "retry later",
            Self::MalformedResponse
            | Self::InvalidProviderRecord
            | Self::MissingStableIdentity
            | Self::TenantMismatch
            | Self::CredentialMaterial
            | Self::ConflictingDuplicate
            | Self::EventContractRejection => "inspect quarantined records",
            Self::InvalidCursor | Self::InvalidObservedAt => "restart collection",
            Self::AppendFailure | Self::ProjectionFailure => "repair durable processing and retry",
            Self::LeaseLoss | Self::StaleAuthority => "restart collection with the current lease",
            Self::InvalidFamily
            | Self::RequestScopeMismatch
            | Self::EgressDenied
            | Self::InvalidRetryAfter
            | Self::ResponseTooLarge
            | Self::TooManyRecords
            | Self::UnexpectedStatus { .. }
            | Self::InternalRuntimeFailure => "repair the forward runtime implementation",
        }
    }
}

impl fmt::Display for DeepSeekError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "DeepSeek family is invalid",
            Self::MissingConfiguration(_) => "DeepSeek source configuration is missing",
            Self::InvalidConfiguration(_) => "DeepSeek source configuration is invalid",
            Self::InvalidBaseUrl => "DeepSeek base URL must be a credential-free HTTPS origin",
            Self::UnsafeOrigin => "DeepSeek base URL is outside the provider origin",
            Self::InvalidTenantId => "DeepSeek tenant ID is invalid",
            Self::MissingCredentialReference => "DeepSeek credential reference is missing",
            Self::CredentialUnavailable => "DeepSeek credential lease is unavailable",
            Self::InvalidCursor => "DeepSeek does not admit a continuation cursor",
            Self::RequestScopeMismatch => "DeepSeek request does not match the kernel",
            Self::AuthenticationRejected => "DeepSeek rejected authentication",
            Self::RequiredScopeMissing => "DeepSeek credential lacks required scope",
            Self::InsufficientBalance => "DeepSeek account balance is insufficient",
            Self::EgressDenied => "DeepSeek egress was denied",
            Self::DnsFailure => "DeepSeek DNS resolution failed",
            Self::ConnectionFailure => "DeepSeek connection failed",
            Self::ProviderTimeout => "DeepSeek operation timed out",
            Self::RateLimited { .. } => "DeepSeek rate limited the operation",
            Self::ProviderUnavailable { .. } => "DeepSeek is temporarily unavailable",
            Self::UnexpectedStatus { .. } => "DeepSeek returned an unexpected status",
            Self::InvalidRetryAfter => "DeepSeek retry delay exceeds its bound",
            Self::ResponseTooLarge => "DeepSeek response exceeds its byte bound",
            Self::TooManyRecords => "DeepSeek response exceeds its record bound",
            Self::MalformedResponse => "DeepSeek response is malformed",
            Self::InvalidProviderRecord => "DeepSeek provider record is invalid",
            Self::MissingStableIdentity => "DeepSeek record has no stable identity",
            Self::InvalidObservedAt => "DeepSeek observation time is invalid",
            Self::TenantMismatch => "DeepSeek payload attempted to supply tenant context",
            Self::CredentialMaterial => "DeepSeek payload contains credential-shaped material",
            Self::ConflictingDuplicate => "DeepSeek duplicate identity has conflicting content",
            Self::EventContractRejection => "DeepSeek event failed its catalog contract",
            Self::AppendFailure => "DeepSeek append failed",
            Self::ProjectionFailure => "DeepSeek projection failed",
            Self::LeaseLoss => "DeepSeek runtime lost its lease",
            Self::StaleAuthority => "DeepSeek runtime authority is stale",
            Self::InternalRuntimeFailure => "DeepSeek runtime failed internally",
        })
    }
}

impl Error for DeepSeekError {}
