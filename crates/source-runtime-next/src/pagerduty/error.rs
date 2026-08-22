//! Stable fail-closed PagerDuty kernel errors.

use std::{error::Error, fmt};

/// Typed PagerDuty request, response, identity, and provider failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PagerDutyError {
    /// The configured API origin is not an allowlisted PagerDuty HTTPS origin.
    InvalidBaseUrl,
    /// The selected family is not in the closed PagerDuty definition.
    InvalidFamily,
    /// Source tenant identity is missing or malformed.
    MissingTenantId,
    /// The integration family has no bounded service scope.
    MissingServiceId,
    /// A service identifier is unsafe or ambiguous in a request path.
    InvalidServiceId,
    /// Page size is outside PagerDuty's inclusive 1 through 100 bound.
    InvalidPageSize,
    /// Continuation state is malformed, unsafe, or belongs to another scope.
    InvalidCursor,
    /// A request does not belong to the kernel that is decoding it.
    RequestScopeMismatch,
    /// PagerDuty rejected the configured credential.
    AuthenticationRejected,
    /// The credential lacks permission for the selected family.
    PermissionDenied,
    /// PagerDuty rate-limited the operation.
    RateLimited,
    /// PagerDuty or its network path is temporarily unavailable.
    ProviderUnavailable,
    /// PagerDuty returned a status outside the declared contract.
    UnexpectedProviderStatus,
    /// The response exceeds the eight-mebibyte kernel boundary.
    ResponseTooLarge,
    /// The response exceeds the declared page cardinality.
    TooManyRecords,
    /// The response envelope or one of its fields is malformed.
    MalformedResponse,
    /// A provider record has no stable PagerDuty identity.
    MissingProviderIdentity,
    /// A provider identity contains ambiguous or unsafe characters.
    InvalidProviderIdentity,
    /// Duplicate provider identities carried different canonical records.
    ConflictingProviderIdentity,
    /// A normalized record failed its exact event contract.
    EventContractRejected,
}

impl fmt::Display for PagerDutyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidBaseUrl => "invalid PagerDuty API origin",
            Self::InvalidFamily => "invalid PagerDuty family",
            Self::MissingTenantId => "PagerDuty tenant identity is required",
            Self::MissingServiceId => "PagerDuty integration service scope is required",
            Self::InvalidServiceId => "invalid PagerDuty service identity",
            Self::InvalidPageSize => "invalid PagerDuty page size",
            Self::InvalidCursor => "invalid PagerDuty continuation",
            Self::RequestScopeMismatch => "PagerDuty request scope mismatch",
            Self::AuthenticationRejected => "PagerDuty authentication rejected",
            Self::PermissionDenied => "PagerDuty permission denied",
            Self::RateLimited => "PagerDuty rate limited",
            Self::ProviderUnavailable => "PagerDuty provider unavailable",
            Self::UnexpectedProviderStatus => "unexpected PagerDuty provider status",
            Self::ResponseTooLarge => "PagerDuty response too large",
            Self::TooManyRecords => "PagerDuty page contains too many records",
            Self::MalformedResponse => "malformed PagerDuty response",
            Self::MissingProviderIdentity => "PagerDuty provider identity is required",
            Self::InvalidProviderIdentity => "invalid PagerDuty provider identity",
            Self::ConflictingProviderIdentity => "conflicting PagerDuty provider identity",
            Self::EventContractRejected => "PagerDuty event contract rejected",
        })
    }
}

impl Error for PagerDutyError {}
