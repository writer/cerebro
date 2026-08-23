use std::{error::Error, fmt};

/// Bounded ADP provider and runtime failure taxonomy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdpError {
    /// Family is outside the closed catalog.
    InvalidFamily,
    /// Public configuration is malformed.
    InvalidConfiguration(&'static str),
    /// Provider origin is not the fixed HTTPS ADP API origin.
    InvalidOrigin,
    /// Authenticated tenant context is malformed.
    InvalidTenantId,
    /// Trusted host has no OAuth credential reference.
    MissingCredentialReference,
    /// Trusted host could not redeem the OAuth credential lease.
    CredentialUnavailable,
    /// Trusted host has no mutual TLS client identity reference.
    MissingMutualTlsReference,
    /// Trusted host could not redeem the mutual TLS identity.
    MutualTlsUnavailable,
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
    /// Provider connection or mutual TLS handshake failed.
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

impl AdpError {
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
            | Self::AuthenticationRejected => "repair OAuth credential binding",
            Self::MissingMutualTlsReference
            | Self::MutualTlsUnavailable
            | Self::ConnectionFailure => "repair mutual TLS identity binding",
            Self::RequiredScopeMissing => "grant ADP Workforce Now API read access",
            Self::RateLimited { .. }
            | Self::ProviderUnavailable { .. }
            | Self::DnsFailure
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

impl fmt::Display for AdpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "adp_workforce_now family is invalid",
            Self::InvalidConfiguration(_) => "adp_workforce_now source configuration is invalid",
            Self::InvalidOrigin => "adp_workforce_now provider origin is invalid",
            Self::InvalidTenantId => "adp_workforce_now tenant ID is invalid",
            Self::MissingCredentialReference => "adp_workforce_now OAuth reference is missing",
            Self::CredentialUnavailable => "adp_workforce_now OAuth lease is unavailable",
            Self::MissingMutualTlsReference => "adp_workforce_now mutual TLS reference is missing",
            Self::MutualTlsUnavailable => "adp_workforce_now mutual TLS identity is unavailable",
            Self::InvalidCursor => "adp_workforce_now cursor is invalid or not round-trippable",
            Self::RequestScopeMismatch => "adp_workforce_now request does not match the kernel",
            Self::AuthenticationRejected => "adp_workforce_now rejected authentication",
            Self::RequiredScopeMissing => "adp_workforce_now credential lacks required scope",
            Self::ProviderResourceNotFound => "adp_workforce_now resource was not found",
            Self::EgressDenied => "adp_workforce_now egress was denied",
            Self::DnsFailure => "adp_workforce_now DNS resolution failed",
            Self::ConnectionFailure => "adp_workforce_now connection or mutual TLS failed",
            Self::ProviderTimeout => "adp_workforce_now operation timed out",
            Self::RateLimited { .. } => "adp_workforce_now rate limited the operation",
            Self::ProviderUnavailable { .. } => "adp_workforce_now is temporarily unavailable",
            Self::UnexpectedStatus { .. } => "adp_workforce_now returned an unexpected status",
            Self::InvalidRetryAfter => "adp_workforce_now retry delay exceeds its bound",
            Self::ResponseTooLarge => "adp_workforce_now response exceeds its byte bound",
            Self::TooManyRecords => "adp_workforce_now response exceeds its record bound",
            Self::MalformedResponse => "adp_workforce_now response is malformed",
            Self::InvalidProviderRecord => "adp_workforce_now provider record is invalid",
            Self::MissingStableIdentity => "adp_workforce_now record has no stable identity",
            Self::TenantMismatch => "adp_workforce_now payload attempted to supply tenant context",
            Self::CredentialMaterial => {
                "adp_workforce_now payload contains credential-shaped material"
            }
            Self::ConflictingDuplicate => {
                "adp_workforce_now duplicate identity has conflicting content"
            }
            Self::EventContractRejection => "adp_workforce_now event failed its catalog contract",
            Self::AppendFailure => "adp_workforce_now append failed",
            Self::ProjectionFailure => "adp_workforce_now projection failed",
            Self::LeaseLoss => "adp_workforce_now runtime lost its lease",
            Self::StaleAuthority => "adp_workforce_now runtime authority is stale",
            Self::InternalRuntimeFailure => "adp_workforce_now runtime failed internally",
        })
    }
}

impl Error for AdpError {}
