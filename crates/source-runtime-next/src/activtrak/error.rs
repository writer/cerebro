use std::{error::Error, fmt};

/// Bounded ActivTrak provider and runtime failure taxonomy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivTrakError {
    /// Family is outside the closed catalog.
    InvalidFamily,
    /// Public configuration is malformed.
    InvalidConfiguration(&'static str),
    /// Provider origin is not the declared HTTPS origin.
    InvalidOrigin,
    /// Authenticated tenant context is malformed.
    InvalidTenantId,
    /// Trusted host has no credential reference.
    MissingCredentialReference,
    /// Trusted host could not redeem its credential lease.
    CredentialUnavailable,
    /// Cursor is invalid or cannot round-trip.
    InvalidCursor,
    /// Request does not belong to this kernel.
    RequestScopeMismatch,
    /// Provider rejected authentication.
    AuthenticationRejected,
    /// Credential lacks required provider permission.
    RequiredScopeMissing,
    /// Provider resource was not found.
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
    /// Retry delay is outside its persistence bound.
    InvalidRetryAfter,
    /// Response exceeds the host byte bound.
    ResponseTooLarge,
    /// Response exceeds the family record bound.
    TooManyRecords,
    /// Response JSON does not match the family.
    MalformedResponse,
    /// Provider record violates the family shape.
    InvalidProviderRecord,
    /// Provider record has no stable identity.
    MissingStableIdentity,
    /// Provider payload attempted to supply tenant context.
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

impl ActivTrakError {
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
            Self::RequiredScopeMissing => "grant ActivTrak API read access",
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
            _ => "repair the forward runtime implementation",
        }
    }
}

impl fmt::Display for ActivTrakError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidFamily => "activtrak family is invalid",
            Self::InvalidConfiguration(_) => "activtrak source configuration is invalid",
            Self::InvalidOrigin => "activtrak provider origin is invalid",
            Self::InvalidTenantId => "activtrak tenant ID is invalid",
            Self::MissingCredentialReference => "activtrak credential reference is missing",
            Self::CredentialUnavailable => "activtrak credential lease is unavailable",
            Self::InvalidCursor => "activtrak cursor is invalid or not round-trippable",
            Self::RequestScopeMismatch => "activtrak request does not match the kernel",
            Self::AuthenticationRejected => "activtrak rejected authentication",
            Self::RequiredScopeMissing => "activtrak credential lacks required scope",
            Self::ProviderResourceNotFound => "activtrak resource was not found",
            Self::EgressDenied => "activtrak egress was denied",
            Self::DnsFailure => "activtrak DNS resolution failed",
            Self::ConnectionFailure => "activtrak connection failed",
            Self::ProviderTimeout => "activtrak operation timed out",
            Self::RateLimited { .. } => "activtrak rate limited the operation",
            Self::ProviderUnavailable { .. } => "activtrak is temporarily unavailable",
            Self::UnexpectedStatus { .. } => "activtrak returned an unexpected status",
            Self::InvalidRetryAfter => "activtrak retry delay exceeds its bound",
            Self::ResponseTooLarge => "activtrak response exceeds its byte bound",
            Self::TooManyRecords => "activtrak response exceeds its record bound",
            Self::MalformedResponse => "activtrak response is malformed",
            Self::InvalidProviderRecord => "activtrak provider record is invalid",
            Self::MissingStableIdentity => "activtrak record has no stable identity",
            Self::TenantMismatch => "activtrak payload attempted to supply tenant context",
            Self::CredentialMaterial => "activtrak payload contains credential-shaped material",
            Self::ConflictingDuplicate => "activtrak duplicate identity has conflicting content",
            Self::EventContractRejection => "activtrak event failed its catalog contract",
            Self::AppendFailure => "activtrak append failed",
            Self::ProjectionFailure => "activtrak projection failed",
            Self::LeaseLoss => "activtrak runtime lost its lease",
            Self::StaleAuthority => "activtrak runtime authority is stale",
            Self::InternalRuntimeFailure => "activtrak runtime failed internally",
        };
        formatter.write_str(message)
    }
}

impl Error for ActivTrakError {}
