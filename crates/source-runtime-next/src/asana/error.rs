use std::{error::Error, fmt};

/// Bounded Asana provider and runtime failure taxonomy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AsanaError {
    /// Family is outside the closed catalog.
    InvalidFamily,
    /// Required public configuration is missing.
    MissingConfiguration(&'static str),
    /// Public configuration is malformed.
    InvalidConfiguration(&'static str),
    /// Base URL is not a credential-free HTTPS origin.
    InvalidBaseUrl,
    /// Origin is local, private, or otherwise unsafe.
    UnsafeOrigin,
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
    /// Credential lacks Asana audit or workspace scope.
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

impl AsanaError {
    /// Next safe operator action without provider content.
    pub const fn operator_action(&self) -> &'static str {
        match self {
            Self::InvalidFamily
            | Self::MissingConfiguration(_)
            | Self::InvalidConfiguration(_)
            | Self::InvalidBaseUrl
            | Self::UnsafeOrigin
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

impl fmt::Display for AsanaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "asana family is invalid",
            Self::MissingConfiguration(_) => "asana source configuration is missing",
            Self::InvalidConfiguration(_) => "asana source configuration is invalid",
            Self::InvalidBaseUrl => "asana base URL must be a credential-free HTTPS origin",
            Self::UnsafeOrigin => "asana base URL contains an unsafe origin",
            Self::InvalidTenantId => "asana tenant ID is invalid",
            Self::MissingCredentialReference => "asana credential reference is missing",
            Self::CredentialUnavailable => "asana credential lease is unavailable",
            Self::InvalidCursor => "asana cursor is invalid or not round-trippable",
            Self::RequestScopeMismatch => "asana request does not match the kernel",
            Self::AuthenticationRejected => "asana rejected authentication",
            Self::RequiredScopeMissing => "asana credential lacks required scope",
            Self::EgressDenied => "asana egress was denied",
            Self::DnsFailure => "asana DNS resolution failed",
            Self::ConnectionFailure => "asana connection failed",
            Self::ProviderTimeout => "asana operation timed out",
            Self::RateLimited { .. } => "asana rate limited the operation",
            Self::ProviderUnavailable { .. } => "asana is temporarily unavailable",
            Self::UnexpectedStatus { .. } => "asana returned an unexpected status",
            Self::InvalidRetryAfter => "asana retry delay exceeds its bound",
            Self::ResponseTooLarge => "asana response exceeds its byte bound",
            Self::TooManyRecords => "asana response exceeds its record bound",
            Self::MalformedResponse => "asana response is malformed",
            Self::InvalidProviderRecord => "asana provider record is invalid",
            Self::MissingStableIdentity => "asana record has no stable identity",
            Self::TenantMismatch => "asana payload attempted to supply tenant context",
            Self::CredentialMaterial => "asana payload contains credential-shaped material",
            Self::ConflictingDuplicate => "asana duplicate identity has conflicting content",
            Self::EventContractRejection => "asana event failed its catalog contract",
            Self::AppendFailure => "asana append failed",
            Self::ProjectionFailure => "asana projection failed",
            Self::LeaseLoss => "asana runtime lost its lease",
            Self::StaleAuthority => "asana runtime authority is stale",
            Self::InternalRuntimeFailure => "asana runtime failed internally",
        })
    }
}

impl Error for AsanaError {}
