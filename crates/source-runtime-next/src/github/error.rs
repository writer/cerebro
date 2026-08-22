use std::{error::Error, fmt};

/// Bounded, credential-free GitHub provider failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitHubError {
    /// The source family is not one of the six GitHub catalog families.
    InvalidFamily,
    /// Required public source configuration is absent or malformed.
    MissingConfiguration(&'static str),
    /// A public configuration value is malformed or exceeds its bound.
    InvalidConfiguration(&'static str),
    /// The base URL is not a credential-free HTTPS origin.
    InvalidBaseUrl,
    /// The base URL names a local, private, or otherwise unsafe IP literal.
    UnsafeOrigin,
    /// The authenticated runtime did not supply a valid tenant identifier.
    InvalidTenantId,
    /// The trusted host received no credential reference for this source runtime.
    MissingCredentialReference,
    /// The trusted host could not redeem the operation-scoped credential lease.
    CredentialUnavailable,
    /// A cursor cannot be safely round-tripped for this family and stage.
    InvalidCursor,
    /// A request does not belong to the configured kernel.
    RequestScopeMismatch,
    /// A response exceeds the byte bound declared to the host.
    ResponseTooLarge,
    /// A response contains more records than the planned page permits.
    TooManyRecords,
    /// Response JSON does not match the selected GitHub operation.
    MalformedResponse,
    /// A provider object violates the selected family contract.
    InvalidProviderRecord,
    /// A provider object lacks a stable identity.
    MissingStableIdentity,
    /// A provider payload attempted to provide authenticated tenant context.
    TenantMismatch,
    /// Credential-shaped material entered the portable response boundary.
    CredentialMaterial,
    /// The same provider identity appeared with conflicting content.
    ConflictingDuplicate,
    /// An audit actor needs a separately bounded public lookup.
    ActorResolutionRequired {
        /// Public GitHub login that must be resolved.
        actor: String,
    },
    /// GitHub rejected the externally applied credential.
    AuthenticationRejected,
    /// The credential lacks a permission required by the selected operation.
    RequiredScopeMissing,
    /// An organization-scoped repository request may use the declared user fallback.
    OrganizationNotFound,
    /// The trusted host denied the public operation's egress.
    EgressDenied,
    /// The trusted host could not connect to GitHub.
    ConnectionFailure,
    /// The trusted host could not resolve the declared GitHub hostname.
    DnsFailure,
    /// The trusted host reached the operation deadline.
    ProviderTimeout,
    /// GitHub requested a bounded retry later.
    RateLimited {
        /// Bounded provider retry delay, when supplied.
        retry_after_seconds: Option<u64>,
    },
    /// GitHub returned a retryable server response.
    ProviderUnavailable {
        /// HTTP status in the 500-599 range.
        status: u16,
    },
    /// GitHub returned a status outside the typed cases.
    UnexpectedStatus {
        /// Provider status outside the typed cases.
        status: u16,
    },
    /// Retry-After exceeds the one-hour persistence bound.
    InvalidRetryAfter,
    /// A normalized event failed its exact compiled catalog contract.
    EventContractRejection,
    /// The durable append operation failed.
    AppendFailure,
    /// The graph projection operation failed.
    ProjectionFailure,
    /// The runtime lost its source lease before commit.
    LeaseLoss,
    /// The runtime lease generation or authority record is stale.
    StaleAuthority,
    /// The runtime encountered an internal failure outside provider classification.
    InternalRuntimeFailure,
}

impl fmt::Display for GitHubError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidFamily => "github family is invalid",
            Self::MissingConfiguration(_) => "github source configuration is missing",
            Self::InvalidConfiguration(_) => "github source configuration is invalid",
            Self::InvalidBaseUrl => "github base URL must be a credential-free HTTPS origin",
            Self::UnsafeOrigin => "github base URL contains an unsafe origin",
            Self::InvalidTenantId => "github tenant ID is required and must be bounded",
            Self::MissingCredentialReference => "github credential reference is missing",
            Self::CredentialUnavailable => "github credential lease is unavailable",
            Self::InvalidCursor => "github cursor is invalid or not round-trippable",
            Self::RequestScopeMismatch => "github request does not match the configured kernel",
            Self::ResponseTooLarge => "github response exceeds the declared byte bound",
            Self::TooManyRecords => "github response exceeds the planned page bound",
            Self::MalformedResponse => "github response JSON does not match the operation",
            Self::InvalidProviderRecord => "github provider record is invalid",
            Self::MissingStableIdentity => "github provider record has no stable identity",
            Self::TenantMismatch => "github provider record attempted to supply tenant context",
            Self::CredentialMaterial => "github response contains credential-shaped material",
            Self::ConflictingDuplicate => "github provider identity has conflicting content",
            Self::ActorResolutionRequired { .. } => "github audit actor requires public resolution",
            Self::AuthenticationRejected => "github rejected the externally applied credential",
            Self::RequiredScopeMissing => "github credential lacks the required provider scope",
            Self::OrganizationNotFound => "github organization was not found",
            Self::EgressDenied => "github operation was denied by trusted-host egress policy",
            Self::ConnectionFailure => "trusted host could not connect to github",
            Self::DnsFailure => "trusted host could not resolve the github origin",
            Self::ProviderTimeout => "github operation timed out",
            Self::RateLimited { .. } => "github rate limited the operation",
            Self::ProviderUnavailable { .. } => "github is temporarily unavailable",
            Self::UnexpectedStatus { .. } => "github returned an unexpected status",
            Self::InvalidRetryAfter => "github Retry-After exceeds the one-hour bound",
            Self::EventContractRejection => "github event failed its compiled catalog contract",
            Self::AppendFailure => "github event append failed",
            Self::ProjectionFailure => "github event projection failed",
            Self::LeaseLoss => "github source runtime lost its lease",
            Self::StaleAuthority => "github source runtime authority is stale",
            Self::InternalRuntimeFailure => "github source runtime failed internally",
        };
        formatter.write_str(message)
    }
}

impl GitHubError {
    /// Return the next safe operator action without provider response content.
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
            | Self::ConnectionFailure
            | Self::DnsFailure
            | Self::ProviderTimeout => "retry the collection later",
            Self::EgressDenied => "repair trusted-host egress policy",
            Self::OrganizationNotFound => "use the declared repository user fallback",
            Self::InvalidCursor => "restart collection from the last committed checkpoint",
            Self::MalformedResponse
            | Self::InvalidProviderRecord
            | Self::MissingStableIdentity
            | Self::TenantMismatch
            | Self::CredentialMaterial
            | Self::ConflictingDuplicate
            | Self::ActorResolutionRequired { .. }
            | Self::EventContractRejection => "inspect quarantined provider records",
            Self::AppendFailure | Self::ProjectionFailure => "repair the durable commit path",
            Self::LeaseLoss | Self::StaleAuthority => "restart collection under the current lease",
            Self::RequestScopeMismatch
            | Self::ResponseTooLarge
            | Self::TooManyRecords
            | Self::UnexpectedStatus { .. }
            | Self::InvalidRetryAfter
            | Self::InternalRuntimeFailure => "repair the forward runtime implementation",
        }
    }
}

impl Error for GitHubError {}
