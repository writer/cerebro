use std::{error::Error, fmt};

/// Bounded Akeneo provider and runtime failure taxonomy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AkeneoError {
    /// Family is outside the closed catalog.
    InvalidFamily,
    /// Public configuration is malformed.
    InvalidConfiguration(&'static str),
    /// Provider origin is not an HTTPS Akeneo tenant origin.
    InvalidOrigin,
    /// Authenticated tenant context is malformed.
    InvalidTenantId,
    /// A required public path parameter is absent.
    MissingPathParameter(&'static str),
    /// A public path parameter is malformed.
    InvalidPathParameter(&'static str),
    /// Trusted host has no credential reference.
    MissingCredentialReference,
    /// Trusted host could not redeem the credential lease.
    CredentialUnavailable,
    /// Cursor is unsupported or invalid.
    InvalidCursor,
    /// Request does not belong to this kernel.
    RequestScopeMismatch,
    /// Provider rejected authentication.
    AuthenticationRejected,
    /// Credential lacks required provider permission.
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
    /// Provider payload attempted to supply tenant context.
    TenantMismatch,
    /// Provider payload attempted to supply trusted envelope metadata.
    ProtectedContractField,
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

impl AkeneoError {
    /// Next safe operator action without provider content.
    pub const fn operator_action(&self) -> &'static str {
        match self {
            Self::InvalidFamily
            | Self::InvalidConfiguration(_)
            | Self::InvalidOrigin
            | Self::InvalidTenantId
            | Self::MissingPathParameter(_)
            | Self::InvalidPathParameter(_)
            | Self::ProviderResourceNotFound => "repair source configuration",
            Self::MissingCredentialReference
            | Self::CredentialUnavailable
            | Self::AuthenticationRejected => "repair credential binding",
            Self::RequiredScopeMissing => "grant Akeneo API read access",
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
            | Self::ProtectedContractField
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

impl fmt::Display for AkeneoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "akeneo family is invalid",
            Self::InvalidConfiguration(_) => "akeneo source configuration is invalid",
            Self::InvalidOrigin => "akeneo provider origin is invalid",
            Self::InvalidTenantId => "akeneo tenant ID is invalid",
            Self::MissingPathParameter(_) => "akeneo path parameter is required",
            Self::InvalidPathParameter(_) => "akeneo path parameter is invalid",
            Self::MissingCredentialReference => "akeneo credential reference is missing",
            Self::CredentialUnavailable => "akeneo credential lease is unavailable",
            Self::InvalidCursor => "akeneo cursor is unsupported or invalid",
            Self::RequestScopeMismatch => "akeneo request does not match the kernel",
            Self::AuthenticationRejected => "akeneo rejected authentication",
            Self::RequiredScopeMissing => "akeneo credential lacks required scope",
            Self::ProviderResourceNotFound => "akeneo resource was not found",
            Self::EgressDenied => "akeneo egress was denied",
            Self::DnsFailure => "akeneo DNS resolution failed",
            Self::ConnectionFailure => "akeneo connection failed",
            Self::ProviderTimeout => "akeneo operation timed out",
            Self::RateLimited { .. } => "akeneo rate limited the operation",
            Self::ProviderUnavailable { .. } => "akeneo is temporarily unavailable",
            Self::UnexpectedStatus { .. } => "akeneo returned an unexpected status",
            Self::InvalidRetryAfter => "akeneo retry delay exceeds its bound",
            Self::ResponseTooLarge => "akeneo response exceeds its byte bound",
            Self::TooManyRecords => "akeneo response exceeds its record bound",
            Self::MalformedResponse => "akeneo response is malformed",
            Self::InvalidProviderRecord => "akeneo provider record is invalid",
            Self::MissingStableIdentity => "akeneo record has no stable identity",
            Self::TenantMismatch => "akeneo payload attempted to supply tenant context",
            Self::ProtectedContractField => {
                "akeneo payload attempted to supply trusted contract metadata"
            }
            Self::CredentialMaterial => "akeneo payload contains credential-shaped material",
            Self::ConflictingDuplicate => "akeneo duplicate identity has conflicting content",
            Self::EventContractRejection => "akeneo event failed its catalog contract",
            Self::AppendFailure => "akeneo append failed",
            Self::ProjectionFailure => "akeneo projection failed",
            Self::LeaseLoss => "akeneo runtime lost its lease",
            Self::StaleAuthority => "akeneo runtime authority is stale",
            Self::InternalRuntimeFailure => "akeneo runtime failed internally",
        })
    }
}

impl Error for AkeneoError {}
