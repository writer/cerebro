use std::{error::Error, fmt};

/// Bounded JumpCloud provider and runtime failure taxonomy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JumpCloudError {
    /// Family is outside the closed catalog.
    InvalidFamily,
    /// Required public configuration is missing.
    MissingConfiguration(&'static str),
    /// Public configuration is malformed.
    InvalidConfiguration(&'static str),
    /// Provider origin is not one of the closed HTTPS JumpCloud origins.
    InvalidOrigin,
    /// Authenticated tenant context is missing or malformed.
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
    /// Credential lacks the required JumpCloud scope.
    RequiredScopeMissing,
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
        /// Bounded retry delay supplied by the provider.
        retry_after_seconds: Option<u64>,
    },
    /// Provider returned a retryable server failure.
    ProviderUnavailable {
        /// Provider status in the 500-599 range.
        status: u16,
    },
    /// Provider returned an unexpected status.
    UnexpectedStatus {
        /// Provider status outside the typed cases.
        status: u16,
    },
    /// Retry delay is outside the persistence bound.
    InvalidRetryAfter,
    /// Response exceeds the host-declared byte bound.
    ResponseTooLarge,
    /// Response exceeds the planned record count.
    TooManyRecords,
    /// Response JSON does not match the selected family.
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
    /// Normalized record failed the exact compiled event contract.
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

impl JumpCloudError {
    /// Next safe operator action without provider content.
    pub const fn operator_action(&self) -> &'static str {
        match self {
            Self::InvalidFamily
            | Self::MissingConfiguration(_)
            | Self::InvalidConfiguration(_)
            | Self::InvalidOrigin
            | Self::InvalidTenantId
            | Self::MissingCredentialReference => "repair source configuration",
            Self::CredentialUnavailable | Self::AuthenticationRejected => {
                "repair credential binding"
            }
            Self::RequiredScopeMissing => "grant the required provider scope",
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

impl fmt::Display for JumpCloudError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "jumpcloud family is invalid",
            Self::MissingConfiguration(_) => "jumpcloud source configuration is missing",
            Self::InvalidConfiguration(_) => "jumpcloud source configuration is invalid",
            Self::InvalidOrigin => "jumpcloud provider origin is invalid",
            Self::InvalidTenantId => "jumpcloud tenant ID is invalid",
            Self::MissingCredentialReference => "jumpcloud credential reference is missing",
            Self::CredentialUnavailable => "jumpcloud credential lease is unavailable",
            Self::InvalidCursor => "jumpcloud cursor is invalid or not round-trippable",
            Self::RequestScopeMismatch => "jumpcloud request does not match the kernel",
            Self::AuthenticationRejected => "jumpcloud rejected authentication",
            Self::RequiredScopeMissing => "jumpcloud credential lacks required scope",
            Self::EgressDenied => "jumpcloud egress was denied",
            Self::DnsFailure => "jumpcloud DNS resolution failed",
            Self::ConnectionFailure => "jumpcloud connection failed",
            Self::ProviderTimeout => "jumpcloud operation timed out",
            Self::RateLimited { .. } => "jumpcloud rate limited the operation",
            Self::ProviderUnavailable { .. } => "jumpcloud is temporarily unavailable",
            Self::UnexpectedStatus { .. } => "jumpcloud returned an unexpected status",
            Self::InvalidRetryAfter => "jumpcloud retry delay exceeds its bound",
            Self::ResponseTooLarge => "jumpcloud response exceeds its byte bound",
            Self::TooManyRecords => "jumpcloud response exceeds its record bound",
            Self::MalformedResponse => "jumpcloud response is malformed",
            Self::InvalidProviderRecord => "jumpcloud provider record is invalid",
            Self::MissingStableIdentity => "jumpcloud record has no stable identity",
            Self::TenantMismatch => "jumpcloud payload attempted to supply tenant context",
            Self::CredentialMaterial => "jumpcloud payload contains credential-shaped material",
            Self::ConflictingDuplicate => "jumpcloud duplicate identity has conflicting content",
            Self::EventContractRejection => "jumpcloud event failed its catalog contract",
            Self::AppendFailure => "jumpcloud append failed",
            Self::ProjectionFailure => "jumpcloud projection failed",
            Self::LeaseLoss => "jumpcloud runtime lost its lease",
            Self::StaleAuthority => "jumpcloud runtime authority is stale",
            Self::InternalRuntimeFailure => "jumpcloud runtime failed internally",
        })
    }
}

impl Error for JumpCloudError {}
