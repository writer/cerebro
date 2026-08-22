use std::{error::Error, fmt};

/// Bounded Aha provider and runtime failure taxonomy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AhaError {
    /// Family is outside the closed catalog.
    InvalidFamily,
    /// Public configuration is malformed.
    InvalidConfiguration(&'static str),
    /// Provider origin is not a valid account-specific HTTPS Aha! origin.
    InvalidOrigin,
    /// Authenticated tenant context is malformed.
    InvalidTenantId,
    /// The releases family has no configured product identifier.
    MissingProductId,
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
    /// Provider product conflicts with the configured release scope.
    ProductMismatch,
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

impl AhaError {
    /// Next safe operator action without provider content.
    pub const fn operator_action(&self) -> &'static str {
        match self {
            Self::InvalidFamily
            | Self::InvalidConfiguration(_)
            | Self::InvalidOrigin
            | Self::InvalidTenantId
            | Self::MissingProductId
            | Self::ProductMismatch
            | Self::ProviderResourceNotFound => "repair source configuration",
            Self::MissingCredentialReference
            | Self::CredentialUnavailable
            | Self::AuthenticationRejected => "repair credential binding",
            Self::RequiredScopeMissing => "grant Aha! API read access",
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

impl fmt::Display for AhaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "aha family is invalid",
            Self::InvalidConfiguration(_) => "aha source configuration is invalid",
            Self::InvalidOrigin => "aha provider origin is invalid",
            Self::InvalidTenantId => "aha tenant ID is invalid",
            Self::MissingProductId => "aha product ID is required",
            Self::MissingCredentialReference => "aha credential reference is missing",
            Self::CredentialUnavailable => "aha credential lease is unavailable",
            Self::InvalidCursor => "aha cursor is invalid or not round-trippable",
            Self::RequestScopeMismatch => "aha request does not match the kernel",
            Self::AuthenticationRejected => "aha rejected authentication",
            Self::RequiredScopeMissing => "aha credential lacks required scope",
            Self::ProviderResourceNotFound => "aha resource was not found",
            Self::EgressDenied => "aha egress was denied",
            Self::DnsFailure => "aha DNS resolution failed",
            Self::ConnectionFailure => "aha connection failed",
            Self::ProviderTimeout => "aha operation timed out",
            Self::RateLimited { .. } => "aha rate limited the operation",
            Self::ProviderUnavailable { .. } => "aha is temporarily unavailable",
            Self::UnexpectedStatus { .. } => "aha returned an unexpected status",
            Self::InvalidRetryAfter => "aha retry delay exceeds its bound",
            Self::ResponseTooLarge => "aha response exceeds its byte bound",
            Self::TooManyRecords => "aha response exceeds its record bound",
            Self::MalformedResponse => "aha response is malformed",
            Self::InvalidProviderRecord => "aha provider record is invalid",
            Self::MissingStableIdentity => "aha record has no stable identity",
            Self::ProductMismatch => "aha record conflicts with the product scope",
            Self::TenantMismatch => "aha payload attempted to supply tenant context",
            Self::CredentialMaterial => "aha payload contains credential-shaped material",
            Self::ConflictingDuplicate => "aha duplicate identity has conflicting content",
            Self::EventContractRejection => "aha event failed its catalog contract",
            Self::AppendFailure => "aha append failed",
            Self::ProjectionFailure => "aha projection failed",
            Self::LeaseLoss => "aha runtime lost its lease",
            Self::StaleAuthority => "aha runtime authority is stale",
            Self::InternalRuntimeFailure => "aha runtime failed internally",
        })
    }
}

impl Error for AhaError {}
