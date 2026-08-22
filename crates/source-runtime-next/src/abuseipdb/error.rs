use std::{error::Error, fmt};

/// Bounded AbuseIPDB provider and runtime failure taxonomy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AbuseIpDbError {
    /// Family is outside the closed catalog.
    InvalidFamily,
    /// Required public configuration is missing.
    MissingConfiguration(&'static str),
    /// Public configuration is malformed.
    InvalidConfiguration(&'static str),
    /// Provider origin is not the exact HTTPS AbuseIPDB API root.
    InvalidOrigin,
    /// Authenticated tenant context is malformed.
    InvalidTenantId,
    /// Trusted host has no credential reference.
    MissingCredentialReference,
    /// Trusted host could not redeem the credential lease.
    CredentialUnavailable,
    /// Durable cursor is invalid or cannot round-trip.
    InvalidCursor,
    /// Request does not belong to this kernel.
    RequestScopeMismatch,
    /// Provider rejected authentication.
    AuthenticationRejected,
    /// Credential lacks the required provider permission.
    RequiredScopeMissing,
    /// Requested provider resource was not found.
    ProviderResourceNotFound,
    /// Trusted host denied provider egress.
    EgressDenied,
    /// Provider DNS lookup failed.
    DnsFailure,
    /// Provider connection failed.
    ConnectionFailure,
    /// Provider operation timed out.
    ProviderTimeout,
    /// Provider requested a bounded retry.
    RateLimited {
        /// Provider-declared retry delay, when present and bounded.
        retry_after_seconds: Option<u64>,
    },
    /// Provider returned a retryable server failure.
    ProviderUnavailable {
        /// Provider HTTP status.
        status: u16,
    },
    /// Provider returned an unexpected status.
    UnexpectedStatus {
        /// Provider HTTP status.
        status: u16,
    },
    /// Retry delay is outside the persistence bound.
    InvalidRetryAfter,
    /// Response exceeds the host-declared byte bound.
    ResponseTooLarge,
    /// Response exceeds the selected family record bound.
    TooManyRecords,
    /// Response JSON does not match the selected family.
    MalformedResponse,
    /// Provider record violates the family shape.
    InvalidProviderRecord,
    /// Provider record has no stable identity.
    MissingStableIdentity,
    /// Provider response changed the configured IP scope.
    ProviderIdentityMismatch,
    /// Provider payload attempted to provide tenant context.
    TenantMismatch,
    /// Credential-shaped material crossed into the kernel.
    CredentialMaterial,
    /// Duplicate provider identity has conflicting content.
    ConflictingDuplicate,
    /// Normalized record failed the exact event contract.
    EventContractRejection,
    /// Durable append failed.
    AppendFailure,
    /// Projection failed.
    ProjectionFailure,
    /// Runtime lost its source lease.
    LeaseLoss,
    /// Runtime authority or generation is stale.
    StaleAuthority,
    /// Internal runtime failure.
    InternalRuntimeFailure,
}

impl AbuseIpDbError {
    /// Next safe operator action without provider content.
    pub const fn operator_action(&self) -> &'static str {
        match self {
            Self::InvalidFamily
            | Self::MissingConfiguration(_)
            | Self::InvalidConfiguration(_)
            | Self::InvalidOrigin
            | Self::InvalidTenantId
            | Self::ProviderResourceNotFound => "repair source configuration",
            Self::MissingCredentialReference
            | Self::CredentialUnavailable
            | Self::AuthenticationRejected => "repair credential binding",
            Self::RequiredScopeMissing => "grant AbuseIPDB read access",
            Self::RateLimited { .. }
            | Self::ProviderUnavailable { .. }
            | Self::DnsFailure
            | Self::ConnectionFailure
            | Self::ProviderTimeout => "retry the collection later",
            Self::EgressDenied => "repair trusted-host egress policy",
            Self::InvalidCursor => "restart from the last committed checkpoint",
            Self::MalformedResponse
            | Self::InvalidProviderRecord
            | Self::MissingStableIdentity
            | Self::ProviderIdentityMismatch
            | Self::TenantMismatch
            | Self::CredentialMaterial
            | Self::ConflictingDuplicate
            | Self::EventContractRejection => "inspect quarantined provider records",
            Self::AppendFailure | Self::ProjectionFailure => "repair the durable commit path",
            Self::LeaseLoss | Self::StaleAuthority => "restart under the current lease",
            Self::RequestScopeMismatch
            | Self::InvalidRetryAfter
            | Self::ResponseTooLarge
            | Self::TooManyRecords
            | Self::UnexpectedStatus { .. }
            | Self::InternalRuntimeFailure => "repair the forward runtime implementation",
        }
    }
}

impl fmt::Display for AbuseIpDbError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "abuseipdb family is invalid",
            Self::MissingConfiguration(_) => "abuseipdb source configuration is missing",
            Self::InvalidConfiguration(_) => "abuseipdb source configuration is invalid",
            Self::InvalidOrigin => "abuseipdb provider origin is invalid",
            Self::InvalidTenantId => "abuseipdb tenant ID is invalid",
            Self::MissingCredentialReference => "abuseipdb credential reference is missing",
            Self::CredentialUnavailable => "abuseipdb credential lease is unavailable",
            Self::InvalidCursor => "abuseipdb cursor is invalid or not round-trippable",
            Self::RequestScopeMismatch => "abuseipdb request does not match the kernel",
            Self::AuthenticationRejected => "abuseipdb rejected authentication",
            Self::RequiredScopeMissing => "abuseipdb credential lacks required scope",
            Self::ProviderResourceNotFound => "abuseipdb resource was not found",
            Self::EgressDenied => "abuseipdb egress was denied",
            Self::DnsFailure => "abuseipdb DNS resolution failed",
            Self::ConnectionFailure => "abuseipdb connection failed",
            Self::ProviderTimeout => "abuseipdb operation timed out",
            Self::RateLimited { .. } => "abuseipdb rate limited the operation",
            Self::ProviderUnavailable { .. } => "abuseipdb is temporarily unavailable",
            Self::UnexpectedStatus { .. } => "abuseipdb returned an unexpected status",
            Self::InvalidRetryAfter => "abuseipdb retry delay exceeds its bound",
            Self::ResponseTooLarge => "abuseipdb response exceeds its byte bound",
            Self::TooManyRecords => "abuseipdb response exceeds its record bound",
            Self::MalformedResponse => "abuseipdb response is malformed",
            Self::InvalidProviderRecord => "abuseipdb provider record is invalid",
            Self::MissingStableIdentity => "abuseipdb record has no stable identity",
            Self::ProviderIdentityMismatch => "abuseipdb response changed request scope",
            Self::TenantMismatch => "abuseipdb payload attempted to supply tenant context",
            Self::CredentialMaterial => "abuseipdb payload contains credential-shaped material",
            Self::ConflictingDuplicate => "abuseipdb duplicate identity has conflicting content",
            Self::EventContractRejection => "abuseipdb event failed its catalog contract",
            Self::AppendFailure => "abuseipdb append failed",
            Self::ProjectionFailure => "abuseipdb projection failed",
            Self::LeaseLoss => "abuseipdb runtime lost its lease",
            Self::StaleAuthority => "abuseipdb runtime authority is stale",
            Self::InternalRuntimeFailure => "abuseipdb runtime failed internally",
        })
    }
}

impl Error for AbuseIpDbError {}
