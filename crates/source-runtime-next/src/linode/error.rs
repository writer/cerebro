//! Stable fail-closed Linode kernel errors.

use std::{error::Error, fmt};

/// Stable Linode request and response failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinodeError {
    /// The configured API base URL is not an allowed secure v4 origin.
    InvalidBaseUrl,
    /// Source tenant identity is required.
    MissingTenantId,
    /// Page size is outside Linode's inclusive 25 through 500 range.
    InvalidPageSize,
    /// Provider page continuation is oversized, non-canonical, or out of range.
    InvalidCursor,
    /// A planned request does not belong to this kernel.
    RequestScopeMismatch,
    /// Provider response exceeds the eight-mebibyte host bound.
    ResponseTooLarge,
    /// Provider response exceeds the requested page cardinality.
    TooManyRecords,
    /// Response JSON does not match the managed-issues wire contract.
    InvalidResponse,
    /// Response pagination does not match the requested page.
    ResponsePageMismatch,
    /// A provider record has no stable identity under the Go selector order.
    MissingProviderIdentity,
    /// Tenant, provider, or discriminator identity is not collision-safe.
    InvalidEventIdentity,
    /// One page contains different records with the same provider identity.
    ConflictingProviderIdentity,
    /// A catalog-required raw provider field is missing or empty.
    MissingRequiredPayloadField(&'static str),
    /// A catalog-required normalized attribute is missing.
    MissingRequiredAttribute(&'static str),
}

impl fmt::Display for LinodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBaseUrl => {
                formatter.write_str("linode base URL must be a secure v4 origin")
            }
            Self::MissingTenantId => formatter.write_str("linode tenant_id is required"),
            Self::InvalidPageSize => {
                formatter.write_str("linode page_size must be between 25 and 500")
            }
            Self::InvalidCursor => formatter.write_str("linode page cursor is invalid"),
            Self::RequestScopeMismatch => {
                formatter.write_str("linode request does not match the kernel")
            }
            Self::ResponseTooLarge => formatter.write_str("linode response exceeds 8388608 bytes"),
            Self::TooManyRecords => {
                formatter.write_str("linode response exceeds the requested page size")
            }
            Self::InvalidResponse => {
                formatter.write_str("linode response does not match managed issues")
            }
            Self::ResponsePageMismatch => {
                formatter.write_str("linode response page does not match the request")
            }
            Self::MissingProviderIdentity => {
                formatter.write_str("linode issue has no stable provider identity")
            }
            Self::InvalidEventIdentity => {
                formatter.write_str("linode tenant or issue identity is not event-ID safe")
            }
            Self::ConflictingProviderIdentity => {
                formatter.write_str("linode page contains conflicting provider identities")
            }
            Self::MissingRequiredPayloadField(name) => {
                write!(
                    formatter,
                    "linode issue is missing required payload field {name}"
                )
            }
            Self::MissingRequiredAttribute(name) => {
                write!(
                    formatter,
                    "linode issue is missing required attribute {name}"
                )
            }
        }
    }
}

impl Error for LinodeError {}
