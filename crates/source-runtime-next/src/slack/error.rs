use std::{error::Error, fmt};

/// Closed Slack provider and kernel failure taxonomy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SlackError {
    /// Family identifier is outside the checked-in Slack contract.
    InvalidFamily,
    /// Provider origin is not a bounded credential-free HTTPS origin.
    InvalidOrigin,
    /// Authenticated tenant identity is missing or unsafe.
    InvalidTenant,
    /// Required family scope such as a channel or user-group ID is missing.
    MissingScope,
    /// Page size is outside the family bound.
    InvalidPageSize,
    /// Cursor does not match the selected family contract.
    InvalidCursor,
    /// A cursor was supplied to a non-paginated family.
    UnsupportedCursor,
    /// Request was decoded by another family or kernel.
    RequestScopeMismatch,
    /// Provider rejected the externally applied credential.
    AuthenticationRejected,
    /// Credential lacks the selected family's provider scope.
    RequiredScopeMissing,
    /// Provider asked the host to retry later.
    RateLimited {
        /// Bounded Retry-After delay, when supplied.
        retry_after_seconds: Option<u64>,
    },
    /// Provider returned a retryable server status.
    ProviderUnavailable {
        /// HTTP status in the inclusive 500-599 range.
        status: u16,
    },
    /// Provider returned another unsupported status.
    UnexpectedStatus {
        /// Unsupported HTTP status.
        status: u16,
    },
    /// Response exceeded the compiled byte bound.
    ResponseTooLarge,
    /// Response did not match the selected Slack envelope.
    MalformedResponse,
    /// Provider record failed the family scalar/object contract.
    InvalidRecord,
    /// Provider response contained credential-bearing fields.
    CredentialMaterial,
    /// Provider payload attempted to supply the authenticated tenant identity.
    TenantMismatch,
    /// Provider record has no stable family identity.
    MissingStableIdentity,
    /// The same stable identity appeared with conflicting content.
    ConflictingDuplicate,
    /// Provider timestamp cannot be represented safely.
    InvalidTimestamp,
}

impl fmt::Display for SlackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "slack family is invalid",
            Self::InvalidOrigin => "slack origin must be a credential-free HTTPS origin",
            Self::InvalidTenant => "slack tenant identity is invalid",
            Self::MissingScope => "slack family scope is missing",
            Self::InvalidPageSize => "slack page size is outside the family bound",
            Self::InvalidCursor => "slack cursor is invalid",
            Self::UnsupportedCursor => "slack family does not support cursors",
            Self::RequestScopeMismatch => "slack request does not match the selected kernel",
            Self::AuthenticationRejected => "slack rejected the externally applied credential",
            Self::RequiredScopeMissing => "slack credential is missing the required scope",
            Self::RateLimited { .. } => "slack rate limited the request",
            Self::ProviderUnavailable { .. } => "slack provider is temporarily unavailable",
            Self::UnexpectedStatus { .. } => "slack returned an unexpected HTTP status",
            Self::ResponseTooLarge => "slack response exceeds the compiled byte bound",
            Self::MalformedResponse => "slack response envelope is malformed",
            Self::InvalidRecord => "slack record does not match the family contract",
            Self::CredentialMaterial => "slack response contains credential material",
            Self::TenantMismatch => "slack provider payload cannot supply the tenant identity",
            Self::MissingStableIdentity => "slack record is missing a stable identity",
            Self::ConflictingDuplicate => {
                "slack stable identity was repeated with conflicting content"
            }
            Self::InvalidTimestamp => "slack provider timestamp is invalid",
        })
    }
}

impl Error for SlackError {}
