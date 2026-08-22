use std::{error::Error, fmt};

/// Bounded DigitalOcean provider and runtime failure taxonomy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DigitalOceanError {
    /// Family is outside droplets, VPCs, and firewalls.
    InvalidFamily,
    /// Configured HTTPS provider base is unsafe or malformed.
    InvalidBaseUrl,
    /// Authenticated tenant context is malformed.
    InvalidTenantId,
    /// Page size is outside the provider bound.
    InvalidPageSize,
    /// Cursor is invalid or cannot round-trip.
    InvalidCursor,
    /// Request does not belong to this kernel.
    RequestScopeMismatch,
    /// Trusted host has no credential reference.
    MissingCredentialReference,
    /// Trusted host could not redeem the credential lease.
    CredentialUnavailable,
    /// Provider rejected authentication.
    AuthenticationRejected,
    /// Credential lacks the selected family permission.
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
    /// Provider response exceeds the eight-mebibyte bound.
    ResponseTooLarge,
    /// Provider response exceeds the requested page size.
    TooManyRecords,
    /// Response JSON does not match the selected family.
    MalformedResponse,
    /// Provider record violates the family shape.
    InvalidProviderRecord,
    /// Provider record has no stable identity.
    MissingStableIdentity,
    /// Duplicate provider identity has conflicting content.
    ConflictingDuplicate,
    /// Provider payload attempted to provide tenant context.
    TenantMismatch,
    /// Credential-shaped material crossed into the kernel.
    CredentialMaterial,
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

impl DigitalOceanError {
    /// Next safe operator action without provider content.
    pub const fn operator_action(&self) -> &'static str {
        match self {
            Self::InvalidFamily
            | Self::InvalidBaseUrl
            | Self::InvalidTenantId
            | Self::InvalidPageSize => "repair source configuration",
            Self::MissingCredentialReference
            | Self::CredentialUnavailable
            | Self::AuthenticationRejected => "repair credential binding",
            Self::RequiredScopeMissing => "grant DigitalOcean read access",
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
            | Self::ConflictingDuplicate
            | Self::TenantMismatch
            | Self::CredentialMaterial
            | Self::EventContractRejection => "inspect quarantined provider records",
            Self::AppendFailure | Self::ProjectionFailure => "repair the durable commit path",
            Self::LeaseLoss | Self::StaleAuthority => "restart under the current lease",
            Self::RequestScopeMismatch
            | Self::ResponseTooLarge
            | Self::TooManyRecords
            | Self::UnexpectedStatus { .. }
            | Self::InternalRuntimeFailure => "repair the forward runtime implementation",
        }
    }
}

impl fmt::Display for DigitalOceanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "digitalocean family is invalid",
            Self::InvalidBaseUrl => "digitalocean base URL is invalid",
            Self::InvalidTenantId => "digitalocean tenant ID is invalid",
            Self::InvalidPageSize => "digitalocean per_page is invalid",
            Self::InvalidCursor => "digitalocean page cursor is invalid",
            Self::RequestScopeMismatch => "digitalocean request does not match the kernel",
            Self::MissingCredentialReference => "digitalocean credential reference is missing",
            Self::CredentialUnavailable => "digitalocean credential lease is unavailable",
            Self::AuthenticationRejected => "digitalocean rejected authentication",
            Self::RequiredScopeMissing => "digitalocean credential lacks selected family access",
            Self::EgressDenied => "digitalocean egress was denied",
            Self::DnsFailure => "digitalocean DNS resolution failed",
            Self::ConnectionFailure => "digitalocean connection failed",
            Self::ProviderTimeout => "digitalocean operation timed out",
            Self::RateLimited { .. } => "digitalocean rate limited the operation",
            Self::ProviderUnavailable { .. } => "digitalocean is temporarily unavailable",
            Self::UnexpectedStatus { .. } => "digitalocean returned an unexpected status",
            Self::ResponseTooLarge => "digitalocean response exceeds its byte bound",
            Self::TooManyRecords => "digitalocean response exceeds per_page",
            Self::MalformedResponse => "digitalocean response is malformed",
            Self::InvalidProviderRecord => "digitalocean provider record is invalid",
            Self::MissingStableIdentity => "digitalocean record has no stable identity",
            Self::ConflictingDuplicate => "digitalocean duplicate identity has conflicting content",
            Self::TenantMismatch => "digitalocean payload attempted to supply tenant context",
            Self::CredentialMaterial => "digitalocean payload contains credential-shaped material",
            Self::EventContractRejection => "digitalocean event failed its catalog contract",
            Self::AppendFailure => "digitalocean append failed",
            Self::ProjectionFailure => "digitalocean projection failed",
            Self::LeaseLoss => "digitalocean runtime lost its lease",
            Self::StaleAuthority => "digitalocean runtime authority is stale",
            Self::InternalRuntimeFailure => "digitalocean runtime failed internally",
        })
    }
}

impl Error for DigitalOceanError {}
