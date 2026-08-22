//! Typed Anthropic provider failures with credential-free diagnostics.

use std::{error::Error, fmt};

/// Closed Anthropic request, provider, normalization, and admission failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnthropicError {
    /// Family is outside the checked-in Anthropic contract.
    InvalidFamily,
    /// Provider base URL is not one secure origin.
    InvalidBaseUrl,
    /// Trusted runtime tenant identity is absent or unsafe.
    MissingTenantId,
    /// A required family path parameter is absent.
    MissingPathParameter,
    /// A path or query parameter is unsafe or undeclared.
    InvalidParameter,
    /// Requested page size is outside the provider bound.
    InvalidPageSize,
    /// Provider continuation cursor is unsafe or non-round-trippable.
    InvalidCursor,
    /// Decode request does not belong to this family and origin.
    RequestScopeMismatch,
    /// Provider rejected the credential.
    AuthenticationRejected,
    /// Credential cannot read the requested Anthropic family or scope.
    RequiredProviderScopeMissing,
    /// Provider returned a rate limit.
    ProviderRateLimit,
    /// Provider or network is temporarily unavailable.
    ProviderUnavailable,
    /// Provider returned another unexpected status.
    UnexpectedProviderStatus,
    /// Response exceeded the compiled byte bound.
    ResponseTooLarge,
    /// Response JSON or list envelope is malformed.
    MalformedResponse,
    /// One provider item is not a record object.
    InvalidRecord,
    /// Provider record cannot produce a stable identity.
    MissingStableIdentity,
    /// Required event attribute or payload field is absent.
    EventContractRejected,
    /// One stable provider identity has conflicting content in a page.
    DuplicateConflict,
    /// Observation time is not a valid RFC 3339 timestamp.
    InvalidObservedAt,
}

impl fmt::Display for AnthropicError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "anthropic family is outside the compiled contract",
            Self::InvalidBaseUrl => "anthropic base URL must be one secure origin",
            Self::MissingTenantId => "anthropic trusted tenant identity is required",
            Self::MissingPathParameter => "anthropic family path parameter is required",
            Self::InvalidParameter => "anthropic request parameter is invalid",
            Self::InvalidPageSize => "anthropic page size must be between 1 and 1000",
            Self::InvalidCursor => "anthropic continuation cursor is invalid",
            Self::RequestScopeMismatch => {
                "anthropic response request does not match the compiled family origin"
            }
            Self::AuthenticationRejected => "anthropic authentication was rejected",
            Self::RequiredProviderScopeMissing => {
                "anthropic credential lacks the required provider scope"
            }
            Self::ProviderRateLimit => "anthropic provider rate limit was reached",
            Self::ProviderUnavailable => "anthropic provider is unavailable",
            Self::UnexpectedProviderStatus => "anthropic provider returned an unexpected status",
            Self::ResponseTooLarge => "anthropic response exceeds the compiled byte bound",
            Self::MalformedResponse => "anthropic response does not match the family contract",
            Self::InvalidRecord => "anthropic provider record must be an object",
            Self::MissingStableIdentity => "anthropic provider record identity is missing",
            Self::EventContractRejected => "anthropic event contract rejected the record",
            Self::DuplicateConflict => {
                "anthropic duplicate provider identity has conflicting content"
            }
            Self::InvalidObservedAt => "anthropic observed_at must be RFC 3339",
        })
    }
}

impl Error for AnthropicError {}
