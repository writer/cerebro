use std::{error::Error, fmt};

/// Bounded Cloudflare provider and contract failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CloudflareError {
    /// Family identifier is outside the checked-in Cloudflare catalog.
    InvalidFamily,
    /// Base URL is not a public credential-free HTTPS origin.
    InvalidBaseUrl,
    /// Authenticated tenant identifier is missing or unsafe.
    InvalidTenantId,
    /// A family-scoped account or zone identifier is missing or unsafe.
    InvalidScopeId,
    /// Page size is outside the Cloudflare API bound.
    InvalidPageSize,
    /// Continuation is not a bounded positive page number.
    InvalidCursor,
    /// Request was decoded by another family, scope, origin, or kernel instance.
    RequestScopeMismatch,
    /// Response exceeded the byte bound before decoding.
    ResponseTooLarge,
    /// Cloudflare returned a malformed success envelope.
    InvalidResponse,
    /// Response contains more records or pages than the kernel admits.
    BudgetExceeded,
    /// A provider record is missing its stable `id`.
    MissingProviderIdentity,
    /// A provider record carries a scope that conflicts with the request.
    ProviderScopeMismatch,
    /// The same scoped provider identity appeared with different content.
    ConflictingDuplicate,
    /// Provider payload contains credential-bearing field names.
    CredentialMaterial,
    /// Cloudflare rejected the externally applied bearer credential.
    AuthenticationRejected,
    /// The credential is valid but cannot read the selected family or scope.
    RequiredScopeMissing,
    /// Cloudflare asked the trusted host to retry later.
    RateLimited {
        /// Bounded retry delay admitted from `Retry-After`.
        retry_after_seconds: Option<u64>,
    },
    /// Cloudflare returned a retryable server status.
    ProviderUnavailable {
        /// Status in the inclusive 500-599 range.
        status: u16,
    },
    /// Provider returned another non-success status.
    UnexpectedStatus {
        /// Status outside the typed cases.
        status: u16,
    },
    /// Retry-After exceeded the one-hour persistence bound.
    InvalidRetryAfter,
    /// A success-status envelope explicitly reported failure.
    ProviderRejected,
}

impl CloudflareError {
    /// Next bounded operator action for this typed failure.
    pub const fn operator_action(&self) -> &'static str {
        match self {
            Self::InvalidFamily
            | Self::InvalidBaseUrl
            | Self::InvalidTenantId
            | Self::InvalidScopeId
            | Self::InvalidPageSize
            | Self::RequestScopeMismatch => "repair source configuration",
            Self::AuthenticationRejected => "repair credential binding",
            Self::RequiredScopeMissing => "grant required Cloudflare read scope",
            Self::RateLimited { .. } | Self::ProviderUnavailable { .. } => "retry later",
            Self::InvalidCursor => "restart collection from the last committed checkpoint",
            Self::ResponseTooLarge
            | Self::InvalidResponse
            | Self::BudgetExceeded
            | Self::MissingProviderIdentity
            | Self::ProviderScopeMismatch
            | Self::ConflictingDuplicate
            | Self::CredentialMaterial
            | Self::ProviderRejected => "inspect quarantined provider records",
            Self::UnexpectedStatus { .. } | Self::InvalidRetryAfter => {
                "inspect provider response and repair forward"
            }
        }
    }
}

impl fmt::Display for CloudflareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFamily => "cloudflare family is invalid",
            Self::InvalidBaseUrl => {
                "cloudflare base URL must be a public credential-free HTTPS origin"
            }
            Self::InvalidTenantId => "cloudflare tenant ID is required and must be bounded",
            Self::InvalidScopeId => {
                "cloudflare account or zone scope is required and must be bounded"
            }
            Self::InvalidPageSize => "cloudflare page size is outside the provider bound",
            Self::InvalidCursor => "cloudflare cursor must be a bounded positive page number",
            Self::RequestScopeMismatch => "cloudflare request does not match the configured kernel",
            Self::ResponseTooLarge => "cloudflare response exceeds the kernel byte bound",
            Self::InvalidResponse => "cloudflare response JSON does not match the selected family",
            Self::BudgetExceeded => "cloudflare response exceeds a page, record, or nesting bound",
            Self::MissingProviderIdentity => "cloudflare record is missing a stable provider ID",
            Self::ProviderScopeMismatch => {
                "cloudflare record scope conflicts with the requested account or zone"
            }
            Self::ConflictingDuplicate => {
                "cloudflare scoped provider identity has conflicting content"
            }
            Self::CredentialMaterial => "cloudflare response contains credential-bearing material",
            Self::AuthenticationRejected => "cloudflare rejected the bearer credential",
            Self::RequiredScopeMissing => {
                "cloudflare bearer credential lacks the selected family scope"
            }
            Self::RateLimited { .. } => "cloudflare rate limited the bounded request",
            Self::ProviderUnavailable { .. } => "cloudflare provider is temporarily unavailable",
            Self::UnexpectedStatus { .. } => "cloudflare returned an unexpected HTTP status",
            Self::InvalidRetryAfter => "cloudflare Retry-After exceeds the one-hour bound",
            Self::ProviderRejected => "cloudflare success envelope reported a provider failure",
        })
    }
}

impl Error for CloudflareError {}
