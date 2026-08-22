use std::{error::Error, fmt};

/// Bounded Acunetix provider and runtime failure taxonomy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcunetixError {
    /// Family is outside the closed catalog.
    InvalidFamily,
    /// Public configuration is malformed.
    InvalidConfiguration(&'static str),
    /// Provider origin is not an allowed HTTPS `/api/v1` base.
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

impl AcunetixError {
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
            Self::RequiredScopeMissing => "grant Acunetix API read access",
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

impl fmt::Display for AcunetixError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "acunetix family is invalid",
            Self::InvalidConfiguration(_) => "acunetix source configuration is invalid",
            Self::InvalidOrigin => "acunetix provider origin is invalid",
            Self::InvalidTenantId => "acunetix tenant ID is invalid",
            Self::MissingCredentialReference => "acunetix credential reference is missing",
            Self::CredentialUnavailable => "acunetix credential lease is unavailable",
            Self::InvalidCursor => "acunetix cursor is invalid or not round-trippable",
            Self::RequestScopeMismatch => "acunetix request does not match the kernel",
            Self::AuthenticationRejected => "acunetix rejected authentication",
            Self::RequiredScopeMissing => "acunetix credential lacks required scope",
            Self::ProviderResourceNotFound => "acunetix resource was not found",
            Self::EgressDenied => "acunetix egress was denied",
            Self::DnsFailure => "acunetix DNS resolution failed",
            Self::ConnectionFailure => "acunetix connection failed",
            Self::ProviderTimeout => "acunetix operation timed out",
            Self::RateLimited { .. } => "acunetix rate limited the operation",
            Self::ProviderUnavailable { .. } => "acunetix is temporarily unavailable",
            Self::UnexpectedStatus { .. } => "acunetix returned an unexpected status",
            Self::InvalidRetryAfter => "acunetix retry delay exceeds its bound",
            Self::ResponseTooLarge => "acunetix response exceeds its byte bound",
            Self::TooManyRecords => "acunetix response exceeds its record bound",
            Self::MalformedResponse => "acunetix response is malformed",
            Self::InvalidProviderRecord => "acunetix provider record is invalid",
            Self::MissingStableIdentity => "acunetix record has no stable identity",
            Self::TenantMismatch => "acunetix payload attempted to supply tenant context",
            Self::CredentialMaterial => "acunetix payload contains credential-shaped material",
            Self::ConflictingDuplicate => "acunetix duplicate identity has conflicting content",
            Self::EventContractRejection => "acunetix event failed its catalog contract",
            Self::AppendFailure => "acunetix append failed",
            Self::ProjectionFailure => "acunetix projection failed",
            Self::LeaseLoss => "acunetix runtime lost its lease",
            Self::StaleAuthority => "acunetix runtime authority is stale",
            Self::InternalRuntimeFailure => "acunetix runtime failed internally",
        })
    }
}

impl Error for AcunetixError {}
