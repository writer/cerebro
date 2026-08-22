use std::{error::Error, fmt};

/// Bounded ActiveCampaign provider and runtime failure taxonomy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActiveCampaignError {
    /// Family is outside the closed catalog.
    InvalidFamily,
    /// Public configuration is malformed.
    InvalidConfiguration(&'static str),
    /// Provider origin is not an allowed HTTPS ActiveCampaign account origin.
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

impl ActiveCampaignError {
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
            Self::RequiredScopeMissing => "grant ActiveCampaign API read access",
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

impl fmt::Display for ActiveCampaignError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "activecampaign family is invalid",
            Self::InvalidConfiguration(_) => "activecampaign source configuration is invalid",
            Self::InvalidOrigin => "activecampaign provider origin is invalid",
            Self::InvalidTenantId => "activecampaign tenant ID is invalid",
            Self::MissingCredentialReference => "activecampaign credential reference is missing",
            Self::CredentialUnavailable => "activecampaign credential lease is unavailable",
            Self::InvalidCursor => "activecampaign cursor is invalid or not round-trippable",
            Self::RequestScopeMismatch => "activecampaign request does not match the kernel",
            Self::AuthenticationRejected => "activecampaign rejected authentication",
            Self::RequiredScopeMissing => "activecampaign credential lacks required scope",
            Self::ProviderResourceNotFound => "activecampaign resource was not found",
            Self::EgressDenied => "activecampaign egress was denied",
            Self::DnsFailure => "activecampaign DNS resolution failed",
            Self::ConnectionFailure => "activecampaign connection failed",
            Self::ProviderTimeout => "activecampaign operation timed out",
            Self::RateLimited { .. } => "activecampaign rate limited the operation",
            Self::ProviderUnavailable { .. } => "activecampaign is temporarily unavailable",
            Self::UnexpectedStatus { .. } => "activecampaign returned an unexpected status",
            Self::InvalidRetryAfter => "activecampaign retry delay exceeds its bound",
            Self::ResponseTooLarge => "activecampaign response exceeds its byte bound",
            Self::TooManyRecords => "activecampaign response exceeds its record bound",
            Self::MalformedResponse => "activecampaign response is malformed",
            Self::InvalidProviderRecord => "activecampaign provider record is invalid",
            Self::MissingStableIdentity => "activecampaign record has no stable identity",
            Self::TenantMismatch => "activecampaign payload attempted to supply tenant context",
            Self::CredentialMaterial => {
                "activecampaign payload contains credential-shaped material"
            }
            Self::ConflictingDuplicate => {
                "activecampaign duplicate identity has conflicting content"
            }
            Self::EventContractRejection => "activecampaign event failed its catalog contract",
            Self::AppendFailure => "activecampaign append failed",
            Self::ProjectionFailure => "activecampaign projection failed",
            Self::LeaseLoss => "activecampaign runtime lost its lease",
            Self::StaleAuthority => "activecampaign runtime authority is stale",
            Self::InternalRuntimeFailure => "activecampaign runtime failed internally",
        })
    }
}

impl Error for ActiveCampaignError {}
