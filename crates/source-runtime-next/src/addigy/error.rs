use std::{error::Error, fmt};

/// Bounded Addigy provider and runtime failure taxonomy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AddigyError {
    /// Family is outside the closed catalog.
    InvalidFamily,
    /// Public configuration is malformed.
    InvalidConfiguration(&'static str),
    /// Provider origin is not the fixed HTTPS Addigy API v2 origin.
    InvalidOrigin,
    /// Authenticated tenant context is malformed.
    InvalidTenantId,
    /// An organization-scoped family has no organization identifier.
    MissingOrganizationId,
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
    /// Provider organization conflicts with the request scope.
    OrganizationMismatch,
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

impl AddigyError {
    /// Next safe operator action without provider content.
    pub const fn operator_action(&self) -> &'static str {
        match self {
            Self::InvalidFamily
            | Self::InvalidConfiguration(_)
            | Self::InvalidOrigin
            | Self::InvalidTenantId
            | Self::MissingOrganizationId
            | Self::OrganizationMismatch
            | Self::ProviderResourceNotFound => "repair source configuration",
            Self::MissingCredentialReference
            | Self::CredentialUnavailable
            | Self::AuthenticationRejected => "repair credential binding",
            Self::RequiredScopeMissing => "grant Addigy API v2 read access",
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

impl fmt::Display for AddigyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "addigy family is invalid",
            Self::InvalidConfiguration(_) => "addigy source configuration is invalid",
            Self::InvalidOrigin => "addigy provider origin is invalid",
            Self::InvalidTenantId => "addigy tenant ID is invalid",
            Self::MissingOrganizationId => "addigy organization ID is required",
            Self::MissingCredentialReference => "addigy credential reference is missing",
            Self::CredentialUnavailable => "addigy credential lease is unavailable",
            Self::InvalidCursor => "addigy cursor is invalid or not round-trippable",
            Self::RequestScopeMismatch => "addigy request does not match the kernel",
            Self::AuthenticationRejected => "addigy rejected authentication",
            Self::RequiredScopeMissing => "addigy credential lacks required scope",
            Self::ProviderResourceNotFound => "addigy resource was not found",
            Self::EgressDenied => "addigy egress was denied",
            Self::DnsFailure => "addigy DNS resolution failed",
            Self::ConnectionFailure => "addigy connection failed",
            Self::ProviderTimeout => "addigy operation timed out",
            Self::RateLimited { .. } => "addigy rate limited the operation",
            Self::ProviderUnavailable { .. } => "addigy is temporarily unavailable",
            Self::UnexpectedStatus { .. } => "addigy returned an unexpected status",
            Self::InvalidRetryAfter => "addigy retry delay exceeds its bound",
            Self::ResponseTooLarge => "addigy response exceeds its byte bound",
            Self::TooManyRecords => "addigy response exceeds its record bound",
            Self::MalformedResponse => "addigy response is malformed",
            Self::InvalidProviderRecord => "addigy provider record is invalid",
            Self::MissingStableIdentity => "addigy record has no stable identity",
            Self::OrganizationMismatch => "addigy record conflicts with the organization scope",
            Self::TenantMismatch => "addigy payload attempted to supply tenant context",
            Self::CredentialMaterial => "addigy payload contains credential-shaped material",
            Self::ConflictingDuplicate => "addigy duplicate identity has conflicting content",
            Self::EventContractRejection => "addigy event failed its catalog contract",
            Self::AppendFailure => "addigy append failed",
            Self::ProjectionFailure => "addigy projection failed",
            Self::LeaseLoss => "addigy runtime lost its lease",
            Self::StaleAuthority => "addigy runtime authority is stale",
            Self::InternalRuntimeFailure => "addigy runtime failed internally",
        })
    }
}

impl Error for AddigyError {}
