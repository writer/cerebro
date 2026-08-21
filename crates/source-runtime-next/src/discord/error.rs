use std::{error::Error, fmt};

/// Safe Discord provider-kernel failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscordError {
    /// Family identifier is outside the four catalog contracts.
    InvalidFamily,
    /// Base URL is not a credential-free HTTPS provider URL.
    InvalidBaseUrl,
    /// Base URL contains an unsafe private, loopback, or link-local IP literal.
    UnsafeOrigin,
    /// Authenticated runtime context did not supply a bounded tenant identifier.
    InvalidTenantId,
    /// Guild identifier is not a positive Discord snowflake.
    InvalidGuildId,
    /// Application identifier is not a positive Discord snowflake.
    InvalidApplicationId,
    /// Permission collection did not receive an application identifier.
    MissingApplicationId,
    /// Page size is outside the selected Discord endpoint's bound.
    InvalidPageSize,
    /// A page size was supplied for a non-paginated family.
    UnsupportedPageSize,
    /// Cursor is not a bounded Discord snowflake.
    InvalidCursor,
    /// A cursor was supplied for a non-paginated family.
    UnsupportedCursor,
    /// Response JSON does not match the selected endpoint envelope.
    InvalidResponse,
    /// Response body exceeds the kernel byte bound.
    ResponseTooLarge,
    /// Response contains more top-level records than the family bound.
    TooManyRecords,
    /// A provider record contains more nested entries than its field bound.
    TooManyNestedRecords,
    /// A provider record contains the wrong scalar or nested shape.
    InvalidRecord,
    /// A provider response contains credential-bearing material.
    CredentialMaterial,
    /// A record is missing its required provider snowflake.
    MissingProviderId,
    /// An `after` page is not strictly ascending by provider snowflake.
    InvalidPageOrder,
    /// The same provider identity appeared with different content.
    ConflictingDuplicate,
    /// Discord rejected the externally applied credential.
    AuthenticationRejected,
    /// The bot credential is valid but lacks the audit-log permission.
    RequiredScopeMissing,
    /// Discord asked the host to retry the bounded operation later.
    RateLimited {
        /// Provider delay admitted by the kernel's one-hour bound.
        retry_after_seconds: Option<u64>,
    },
    /// Discord returned a retryable server status.
    ProviderUnavailable {
        /// Provider status in the inclusive 500-599 range.
        status: u16,
    },
    /// Discord returned a non-success status outside the typed cases.
    UnexpectedStatus {
        /// Provider status that did not match a supported success or failure class.
        status: u16,
    },
    /// Retry-After exceeded the provider-local persistence bound.
    InvalidRetryAfter,
    /// A request was decoded by a kernel for another family or scope.
    RequestScopeMismatch,
}

impl fmt::Display for DiscordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "discord family is invalid",
            Self::InvalidBaseUrl => "discord base URL must be a credential-free HTTPS URL",
            Self::UnsafeOrigin => "discord base URL contains an unsafe IP literal",
            Self::InvalidTenantId => "discord tenant ID is required and must be bounded",
            Self::InvalidGuildId => "discord guild ID must be a positive snowflake",
            Self::InvalidApplicationId => "discord application ID must be a positive snowflake",
            Self::MissingApplicationId => "discord permission family requires an application ID",
            Self::InvalidPageSize => "discord page size is outside the endpoint bound",
            Self::UnsupportedPageSize => "discord family does not support a page size",
            Self::InvalidCursor => "discord cursor must be a bounded snowflake",
            Self::UnsupportedCursor => "discord family does not support cursors",
            Self::InvalidResponse => "discord response JSON does not match the endpoint envelope",
            Self::ResponseTooLarge => "discord response exceeds the kernel byte bound",
            Self::TooManyRecords => "discord response exceeds the family record-count bound",
            Self::TooManyNestedRecords => "discord record exceeds a nested record-count bound",
            Self::InvalidRecord => "discord record does not match the provider scalar contract",
            Self::CredentialMaterial => "discord response contains credential material",
            Self::MissingProviderId => "discord record is missing a provider snowflake",
            Self::InvalidPageOrder => "discord after page is not strictly ascending",
            Self::ConflictingDuplicate => {
                "discord provider identity was repeated with conflicting content"
            }
            Self::AuthenticationRejected => "discord rejected the bot credential",
            Self::RequiredScopeMissing => {
                "discord bot credential requires the VIEW_AUDIT_LOG permission"
            }
            Self::RateLimited { .. } => "discord rate limited the audit-log request",
            Self::ProviderUnavailable { .. } => "discord provider is temporarily unavailable",
            Self::UnexpectedStatus { .. } => "discord returned an unexpected HTTP status",
            Self::InvalidRetryAfter => "discord Retry-After exceeds the one-hour bound",
            Self::RequestScopeMismatch => "discord request does not match the configured kernel",
        })
    }
}

impl Error for DiscordError {}
