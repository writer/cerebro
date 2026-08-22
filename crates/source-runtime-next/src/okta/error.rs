//! Stable fail-closed Okta kernel errors.

use std::{error::Error, fmt};

/// Stable Okta request, response, and provider failure states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OktaError {
    /// The configured API base URL is not an allowed secure origin.
    InvalidBaseUrl,
    /// The selected family is not in the closed Okta family set.
    InvalidFamily,
    /// Source tenant identity is required.
    MissingTenantId,
    /// A family-specific parent selector is absent.
    MissingScope(&'static str),
    /// Page size is outside the Go source's inclusive 1 through 200 range.
    InvalidPageSize,
    /// A selector is not valid for the selected family.
    InvalidConfiguration(&'static str),
    /// Provider continuation is oversized, control-bearing, or malformed.
    InvalidCursor,
    /// A planned request does not belong to this kernel.
    RequestScopeMismatch,
    /// Provider rejected the credential.
    AuthenticationRejected,
    /// Provider credential lacks the required family scope.
    PermissionDenied,
    /// Provider asked the runtime to retry later.
    RateLimited,
    /// Provider or network is temporarily unavailable.
    ProviderUnavailable,
    /// Provider returned a status outside the family contract.
    UnexpectedProviderStatus,
    /// Provider response exceeds the four-mebibyte Go compatibility bound.
    ResponseTooLarge,
    /// Provider response exceeds the requested page cardinality.
    TooManyRecords,
    /// Response JSON does not match the selected provider family.
    InvalidResponse,
    /// A provider record has no stable identity.
    MissingProviderIdentity,
    /// Tenant or provider identity is not collision-safe.
    InvalidEventIdentity,
    /// One page contains different records with the same provider identity.
    ConflictingProviderIdentity,
    /// A required event contract field is absent.
    EventContractRejected(&'static str),
}

impl fmt::Display for OktaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBaseUrl => formatter.write_str("okta base URL must be a secure origin"),
            Self::InvalidFamily => formatter.write_str("okta family is not registered"),
            Self::MissingTenantId => formatter.write_str("okta tenant_id is required"),
            Self::MissingScope(name) => write!(formatter, "okta family requires {name}"),
            Self::InvalidPageSize => formatter.write_str("okta per_page must be between 1 and 200"),
            Self::InvalidConfiguration(name) => {
                write!(formatter, "okta configuration is invalid for {name}")
            }
            Self::InvalidCursor => formatter.write_str("okta continuation cursor is invalid"),
            Self::RequestScopeMismatch => {
                formatter.write_str("okta request does not match the kernel")
            }
            Self::AuthenticationRejected => formatter.write_str("okta rejected the credential"),
            Self::PermissionDenied => {
                formatter.write_str("okta credential lacks the required scope")
            }
            Self::RateLimited => formatter.write_str("okta rate limit requires a bounded retry"),
            Self::ProviderUnavailable => formatter.write_str("okta provider is unavailable"),
            Self::UnexpectedProviderStatus => {
                formatter.write_str("okta returned an unexpected status")
            }
            Self::ResponseTooLarge => formatter.write_str("okta response exceeds 4194304 bytes"),
            Self::TooManyRecords => {
                formatter.write_str("okta response exceeds the requested page size")
            }
            Self::InvalidResponse => {
                formatter.write_str("okta response does not match the selected family")
            }
            Self::MissingProviderIdentity => {
                formatter.write_str("okta record has no stable provider identity")
            }
            Self::InvalidEventIdentity => {
                formatter.write_str("okta tenant or provider identity is not event-ID safe")
            }
            Self::ConflictingProviderIdentity => {
                formatter.write_str("okta page contains conflicting provider identities")
            }
            Self::EventContractRejected(field) => {
                write!(formatter, "okta event contract rejected {field}")
            }
        }
    }
}

impl Error for OktaError {}
