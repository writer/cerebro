//! Provider-local failures and their closed shared-runtime mapping.

use crate::source_execution::SourceExecutionError;

/// SentinelOne failures retained until the adapter crosses the shared edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SentinelOneAgentAdapterError {
    InvalidPlan,
    InvalidExecutionContext,
    AuthenticationRejected,
    PermissionDenied,
    RateLimited,
    ProviderUnavailable,
    UnexpectedProviderStatus,
    InvalidCursor,
    InvalidProviderResponse,
    MissingProviderIdentity,
    InvalidEventIdentity,
    ConflictingProviderIdentity,
}

impl From<SentinelOneAgentAdapterError> for SourceExecutionError {
    fn from(error: SentinelOneAgentAdapterError) -> Self {
        match error {
            SentinelOneAgentAdapterError::InvalidPlan => Self::InvalidPlan,
            SentinelOneAgentAdapterError::InvalidExecutionContext => Self::InvalidExecutionContext,
            SentinelOneAgentAdapterError::AuthenticationRejected => Self::AuthenticationRejected,
            SentinelOneAgentAdapterError::PermissionDenied => Self::RequiredProviderScopeMissing,
            SentinelOneAgentAdapterError::RateLimited => Self::ProviderRateLimit,
            SentinelOneAgentAdapterError::ProviderUnavailable
            | SentinelOneAgentAdapterError::UnexpectedProviderStatus => {
                Self::UnexpectedProviderStatus
            }
            SentinelOneAgentAdapterError::InvalidCursor => Self::InvalidCursor,
            SentinelOneAgentAdapterError::InvalidProviderResponse => Self::MalformedResponse,
            SentinelOneAgentAdapterError::MissingProviderIdentity
            | SentinelOneAgentAdapterError::InvalidEventIdentity => Self::MissingStableIdentity,
            SentinelOneAgentAdapterError::ConflictingProviderIdentity => Self::DuplicateConflict,
        }
    }
}
