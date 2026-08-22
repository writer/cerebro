use std::{error::Error, fmt};

/// Bounded Docker Hub provider and runtime failure taxonomy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DockerHubError {
    /// Family is outside the closed provider-verified catalog.
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
    /// A private repository requires a host-side credential reference.
    MissingCredentialReference,
    /// Trusted host could not redeem the credential lease.
    CredentialUnavailable,
    /// Singleton repository reads cannot consume continuation state.
    InvalidCursor,
    /// Request does not belong to this kernel.
    RequestScopeMismatch,
    /// Provider rejected authentication.
    AuthenticationRejected,
    /// Credential lacks repository read scope.
    RequiredScopeMissing,
    /// Configured repository does not exist or is not visible.
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
    /// Response JSON does not match the repository family.
    MalformedResponse,
    /// Provider record violates the repository shape.
    InvalidProviderRecord,
    /// Provider record has no stable namespace/name identity.
    MissingStableIdentity,
    /// Provider response identifies a different configured repository.
    ProviderIdentityMismatch,
    /// Provider payload attempted to provide tenant context.
    TenantMismatch,
    /// Credential-shaped material crossed into the kernel.
    CredentialMaterial,
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

impl DockerHubError {
    /// Next safe operator action without provider content.
    pub const fn operator_action(&self) -> &'static str {
        match self {
            Self::InvalidFamily
            | Self::MissingConfiguration(_)
            | Self::InvalidConfiguration(_)
            | Self::InvalidBaseUrl
            | Self::UnsafeOrigin
            | Self::InvalidTenantId
            | Self::ProviderResourceNotFound => "repair source configuration",
            Self::MissingCredentialReference
            | Self::CredentialUnavailable
            | Self::AuthenticationRejected => "repair credential binding",
            Self::RequiredScopeMissing => "grant repository read scope",
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
            | Self::ProviderIdentityMismatch
            | Self::TenantMismatch
            | Self::CredentialMaterial
            | Self::EventContractRejection => "inspect quarantined provider records",
            Self::AppendFailure | Self::ProjectionFailure => "repair the durable commit path",
            Self::LeaseLoss | Self::StaleAuthority => "restart under the current lease",
            Self::RequestScopeMismatch
            | Self::InvalidRetryAfter
            | Self::ResponseTooLarge
            | Self::UnexpectedStatus { .. }
            | Self::InternalRuntimeFailure => "repair the forward runtime implementation",
        }
    }
}

impl fmt::Display for DockerHubError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "docker hub family is invalid",
            Self::MissingConfiguration(_) => "docker hub source configuration is missing",
            Self::InvalidConfiguration(_) => "docker hub source configuration is invalid",
            Self::InvalidBaseUrl => "docker hub base URL must be a credential-free HTTPS origin",
            Self::UnsafeOrigin => "docker hub base URL contains an unsafe origin",
            Self::InvalidTenantId => "docker hub tenant ID is invalid",
            Self::MissingCredentialReference => "docker hub credential reference is missing",
            Self::CredentialUnavailable => "docker hub credential lease is unavailable",
            Self::InvalidCursor => "docker hub repository cursor must be terminal",
            Self::RequestScopeMismatch => "docker hub request does not match the kernel",
            Self::AuthenticationRejected => "docker hub rejected authentication",
            Self::RequiredScopeMissing => "docker hub credential lacks repository read scope",
            Self::ProviderResourceNotFound => "docker hub repository was not found",
            Self::EgressDenied => "docker hub egress was denied",
            Self::DnsFailure => "docker hub DNS resolution failed",
            Self::ConnectionFailure => "docker hub connection failed",
            Self::ProviderTimeout => "docker hub operation timed out",
            Self::RateLimited { .. } => "docker hub rate limited the operation",
            Self::ProviderUnavailable { .. } => "docker hub is temporarily unavailable",
            Self::UnexpectedStatus { .. } => "docker hub returned an unexpected status",
            Self::InvalidRetryAfter => "docker hub retry delay exceeds its bound",
            Self::ResponseTooLarge => "docker hub response exceeds its byte bound",
            Self::MalformedResponse => "docker hub response is malformed",
            Self::InvalidProviderRecord => "docker hub provider record is invalid",
            Self::MissingStableIdentity => "docker hub record has no stable identity",
            Self::ProviderIdentityMismatch => "docker hub response does not match request scope",
            Self::TenantMismatch => "docker hub payload attempted to supply tenant context",
            Self::CredentialMaterial => "docker hub payload contains credential-shaped material",
            Self::EventContractRejection => "docker hub event failed its catalog contract",
            Self::AppendFailure => "docker hub append failed",
            Self::ProjectionFailure => "docker hub projection failed",
            Self::LeaseLoss => "docker hub runtime lost its lease",
            Self::StaleAuthority => "docker hub runtime authority is stale",
            Self::InternalRuntimeFailure => "docker hub runtime failed internally",
        })
    }
}

impl Error for DockerHubError {}
