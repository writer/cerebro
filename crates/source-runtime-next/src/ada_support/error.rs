use std::{error::Error, fmt};

/// Bounded Ada Support provider and runtime failure taxonomy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdaSupportError {
    /// Family is outside the closed catalog.
    InvalidFamily,
    /// Public configuration is malformed.
    InvalidConfiguration(&'static str),
    /// Provider origin is not an allowed HTTPS Ada tenant API origin.
    InvalidOrigin,
    /// Authenticated tenant context is malformed.
    InvalidTenantId,
    /// Trusted host has no credential reference.
    MissingCredentialReference,
    /// Trusted host could not redeem the credential lease.
    CredentialUnavailable,
    /// Cursor is invalid or cannot round-trip.
    InvalidCursor,
    /// Request does not belong to this kernel.
    RequestScopeMismatch,
    /// Provider rejected authentication.
    AuthenticationRejected,
    /// Credential lacks a required provider permission.
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
        /// Provider-declared retry delay.
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
    /// Response exceeds the family record bound.
    TooManyRecords,
    /// Response JSON does not match the family.
    MalformedResponse,
    /// Provider record violates the family shape.
    InvalidProviderRecord,
    /// Provider record has no stable identity.
    MissingStableIdentity,
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

impl AdaSupportError {
    /// Next safe operator action without provider content.
    pub const fn operator_action(&self) -> &'static str {
        match self {
            Self::InvalidFamily
            | Self::InvalidConfiguration(_)
            | Self::InvalidOrigin
            | Self::InvalidTenantId
            | Self::ProviderResourceNotFound => "repair source configuration",
            Self::MissingCredentialReference
            | Self::CredentialUnavailable
            | Self::AuthenticationRejected => "repair credential binding",
            Self::RequiredScopeMissing => "grant Ada Support API read access",
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

impl fmt::Display for AdaSupportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "ada_support family is invalid",
            Self::InvalidConfiguration(_) => "ada_support source configuration is invalid",
            Self::InvalidOrigin => "ada_support provider origin is invalid",
            Self::InvalidTenantId => "ada_support tenant ID is invalid",
            Self::MissingCredentialReference => "ada_support credential reference is missing",
            Self::CredentialUnavailable => "ada_support credential lease is unavailable",
            Self::InvalidCursor => "ada_support cursor is invalid or not round-trippable",
            Self::RequestScopeMismatch => "ada_support request does not match the kernel",
            Self::AuthenticationRejected => "ada_support rejected authentication",
            Self::RequiredScopeMissing => "ada_support credential lacks required scope",
            Self::ProviderResourceNotFound => "ada_support resource was not found",
            Self::EgressDenied => "ada_support egress was denied",
            Self::DnsFailure => "ada_support DNS resolution failed",
            Self::ConnectionFailure => "ada_support connection failed",
            Self::ProviderTimeout => "ada_support operation timed out",
            Self::RateLimited { .. } => "ada_support rate limited the operation",
            Self::ProviderUnavailable { .. } => "ada_support is temporarily unavailable",
            Self::UnexpectedStatus { .. } => "ada_support returned an unexpected status",
            Self::InvalidRetryAfter => "ada_support retry delay exceeds its bound",
            Self::ResponseTooLarge => "ada_support response exceeds its byte bound",
            Self::TooManyRecords => "ada_support response exceeds its record bound",
            Self::MalformedResponse => "ada_support response is malformed",
            Self::InvalidProviderRecord => "ada_support provider record is invalid",
            Self::MissingStableIdentity => "ada_support record has no stable identity",
            Self::TenantMismatch => "ada_support payload attempted to supply tenant context",
            Self::CredentialMaterial => "ada_support payload contains credential-shaped material",
            Self::ConflictingDuplicate => "ada_support duplicate identity has conflicting content",
            Self::EventContractRejection => "ada_support event failed its catalog contract",
            Self::AppendFailure => "ada_support append failed",
            Self::ProjectionFailure => "ada_support projection failed",
            Self::LeaseLoss => "ada_support runtime lost its lease",
            Self::StaleAuthority => "ada_support runtime authority is stale",
            Self::InternalRuntimeFailure => "ada_support runtime failed internally",
        })
    }
}

impl Error for AdaSupportError {}
