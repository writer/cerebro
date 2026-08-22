//! Stable, body-redacted Google Workspace provider failures.

use std::{error::Error, fmt};

/// Safe Google Workspace kernel failures. Messages never include credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GoogleWorkspaceError {
    /// Family identifier is not one of the five supported contracts.
    InvalidFamily,
    /// Base URL is not a secure provider origin.
    InvalidBaseUrl,
    /// Tenant domain is blank.
    MissingDomain,
    /// Group-member collection omitted its group key.
    MissingGroupKey,
    /// Page size is outside the provider's 1 through 200 bound.
    InvalidPageSize,
    /// Response JSON does not match the family page contract.
    InvalidResponse,
    /// A provider record is not an object.
    InvalidRecord,
    /// A provider record omitted its stable identity.
    MissingRecordIdentity,
    /// Role-assignee response decoding lost its request-bound state.
    MissingRoleState,
    /// A request was decoded by a kernel configured for another family or origin.
    RequestScopeMismatch,
    /// Caller-supplied page observation time is not RFC 3339.
    InvalidObservedAt,
    /// A normalized record cannot produce the Go discovery identity.
    MissingDiscoveryIdentity,
    /// The users adapter was invoked on a kernel configured for another family.
    UserFamilyRequired,
    /// Tenant domain cannot safely scope a stable user identity.
    InvalidTenantIdentity,
    /// Customer selector is oversized, control-bearing, or malformed.
    InvalidCustomerId,
    /// Provider continuation is oversized, control-bearing, or malformed.
    InvalidCursor,
    /// Provider response exceeds the shared eight-mebibyte host bound.
    ResponseTooLarge,
    /// Provider returned more user records than the requested page bound.
    TooManyUserRecords,
    /// One page contains different user records with the same provider identity.
    ConflictingUserIdentity,
    /// Provider rejected the operation-scoped bearer credential.
    AuthenticationRejected,
    /// Provider credential lacks the required Directory user read scope.
    RequiredUserScopeMissing,
    /// Provider credential is valid but cannot read the requested customer.
    PermissionDenied,
    /// Provider rate limit requires retrying the same cursor later.
    RateLimited,
    /// Provider is temporarily unavailable; progress must not advance.
    ProviderUnavailable(u16),
    /// Provider returned an unrecognized non-success status.
    UnexpectedProviderStatus(u16),
}

impl fmt::Display for GoogleWorkspaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidFamily => "google_workspace family is invalid",
            Self::InvalidBaseUrl => "google_workspace base URL must be a secure origin",
            Self::MissingDomain => "google_workspace domain is required",
            Self::MissingGroupKey => "google_workspace group key is required for group members",
            Self::InvalidPageSize => "google_workspace page size must be between 1 and 200",
            Self::InvalidResponse => "google_workspace response does not match the page contract",
            Self::InvalidRecord => "google_workspace record must be an object",
            Self::MissingRecordIdentity => "google_workspace record identity is missing",
            Self::MissingRoleState => "google_workspace role lookup state is missing",
            Self::RequestScopeMismatch => {
                "google_workspace request family or origin does not match the kernel"
            }
            Self::InvalidObservedAt => "google_workspace observed_at must be RFC 3339",
            Self::MissingDiscoveryIdentity => "google_workspace discovery identity is missing",
            Self::UserFamilyRequired => "google_workspace users adapter requires family=user",
            Self::InvalidTenantIdentity => {
                "google_workspace tenant domain is not a stable identity scope"
            }
            Self::InvalidCustomerId => "google_workspace customer identifier is invalid",
            Self::InvalidCursor => "google_workspace user page cursor is invalid",
            Self::ResponseTooLarge => "google_workspace user response exceeds 8388608 bytes",
            Self::TooManyUserRecords => {
                "google_workspace user response exceeds the requested page bound"
            }
            Self::ConflictingUserIdentity => {
                "google_workspace user page contains conflicting provider identities"
            }
            Self::AuthenticationRejected => {
                "google_workspace authentication was rejected; repair the credential binding"
            }
            Self::RequiredUserScopeMissing => {
                "google_workspace credential is missing the Directory user read scope"
            }
            Self::PermissionDenied => {
                "google_workspace credential cannot read the configured customer"
            }
            Self::RateLimited => {
                "google_workspace rate limit requires retrying the same cursor later"
            }
            Self::ProviderUnavailable(status) => {
                return write!(
                    formatter,
                    "google_workspace provider is unavailable with HTTP {status}; retry later"
                );
            }
            Self::UnexpectedProviderStatus(status) => {
                return write!(
                    formatter,
                    "google_workspace provider returned unexpected HTTP {status}"
                );
            }
        };
        formatter.write_str(message)
    }
}

impl Error for GoogleWorkspaceError {}
