//! Stable fail-closed GCP IAM kernel errors.

use std::{error::Error, fmt};

/// Stable GCP IAM kernel failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcpIamError {
    /// The configured IAM base URL is not an allowed secure origin.
    InvalidBaseUrl,
    /// The requested family is not owned by this kernel.
    InvalidFamily,
    /// Source tenant identity is required for Go-compatible event fields.
    MissingTenantId,
    /// GCP project identity is required.
    MissingProjectId,
    /// Service-account email is required for key inventory.
    MissingServiceAccountEmail,
    /// Page size is outside the Go source's inclusive 1 through 200 range.
    InvalidPageSize,
    /// Provider continuation is oversized, control-bearing, or otherwise unsafe.
    InvalidCursor,
    /// Provider response exceeds the Go source host's eight-mebibyte bound.
    ResponseTooLarge,
    /// Provider response exceeds the declared 200-record page bound.
    TooManyRecords,
    /// Response JSON does not match the selected provider family.
    InvalidResponse,
    /// A provider record has no stable identity under the Go fallback order.
    MissingProviderIdentity,
    /// A response request does not match this kernel's origin and endpoint.
    RequestScopeMismatch,
}

impl fmt::Display for GcpIamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidBaseUrl => "gcp IAM base URL must be a secure origin",
            Self::InvalidFamily => "gcp IAM family must be service_account or service_account_key",
            Self::MissingTenantId => "gcp tenant_id is required",
            Self::MissingProjectId => "gcp project_id is required",
            Self::MissingServiceAccountEmail => {
                "gcp service_account_email is required for service_account_key"
            }
            Self::InvalidPageSize => "gcp per_page must be between 1 and 200",
            Self::InvalidCursor => "gcp page cursor is invalid",
            Self::ResponseTooLarge => "gcp IAM response exceeds 8388608 bytes",
            Self::TooManyRecords => "gcp IAM response exceeds 200 records",
            Self::InvalidResponse => "gcp IAM response does not match the selected family",
            Self::MissingProviderIdentity => "gcp IAM record has no stable provider identity",
            Self::RequestScopeMismatch => "gcp IAM request does not match the kernel",
        })
    }
}

impl Error for GcpIamError {}
