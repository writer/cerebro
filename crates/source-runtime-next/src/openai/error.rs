//! Typed OpenAI provider failures.

use std::{error::Error, fmt};

/// A bounded failure produced by the credential-free OpenAI kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpenAiError {
    /// A required public configuration value was not supplied.
    MissingConfiguration(&'static str),
    /// The trusted runtime tenant identity is invalid.
    InvalidTenant,
    /// A family is outside the closed OpenAI runtime table.
    UnknownFamily,
    /// A request attempted to pass credential-shaped configuration to the kernel.
    CredentialMaterialRejected,
    /// The prior provider continuation is invalid.
    InvalidCursor,
    /// The provider rejected authentication.
    AuthenticationRejected,
    /// The provider credential lacks the required organization scope.
    PermissionDenied,
    /// The provider rate limited this operation.
    RateLimited,
    /// Provider transport or a retryable upstream status failed.
    ProviderUnavailable(u16),
    /// The provider returned an unexpected non-success status.
    UnexpectedStatus(u16),
    /// Provider response bytes exceed the family limit.
    ResponseTooLarge,
    /// Provider bytes do not match the closed response contract.
    MalformedResponse,
    /// A record has no stable provider identity.
    MissingStableIdentity,
    /// A provider record contradicts the trusted request scope.
    TenantMismatch,
    /// A normalized record does not satisfy its event contract.
    EventContractRejected,
    /// The same event identity was reused for different canonical content.
    DuplicateConflict,
}

impl fmt::Display for OpenAiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingConfiguration(field) => {
                write!(formatter, "missing OpenAI configuration {field}")
            }
            Self::InvalidTenant => formatter.write_str("OpenAI tenant identity is invalid"),
            Self::UnknownFamily => {
                formatter.write_str("OpenAI family is not in the closed runtime table")
            }
            Self::CredentialMaterialRejected => {
                formatter.write_str("OpenAI kernel input cannot contain credential material")
            }
            Self::InvalidCursor => formatter.write_str("OpenAI continuation cursor is invalid"),
            Self::AuthenticationRejected => formatter.write_str("OpenAI rejected authentication"),
            Self::PermissionDenied => formatter.write_str("OpenAI organization scope is missing"),
            Self::RateLimited => formatter.write_str("OpenAI rate limit exceeded"),
            Self::ProviderUnavailable(status) => {
                write!(formatter, "OpenAI provider unavailable with HTTP {status}")
            }
            Self::UnexpectedStatus(status) => {
                write!(formatter, "OpenAI returned unexpected HTTP {status}")
            }
            Self::ResponseTooLarge => formatter.write_str("OpenAI response exceeds the byte limit"),
            Self::MalformedResponse => {
                formatter.write_str("OpenAI response does not match the family contract")
            }
            Self::MissingStableIdentity => {
                formatter.write_str("OpenAI record is missing a stable identity")
            }
            Self::TenantMismatch => {
                formatter.write_str("OpenAI record contradicts the requested scope")
            }
            Self::EventContractRejected => {
                formatter.write_str("OpenAI record violates the event contract")
            }
            Self::DuplicateConflict => {
                formatter.write_str("OpenAI event identity has conflicting content")
            }
        }
    }
}

impl Error for OpenAiError {}
