//! Stable fail-closed Twilio kernel errors.

use std::{error::Error, fmt};

/// Stable Twilio request and response failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TwilioError {
    /// The configured API base URL is not an allowed secure origin.
    InvalidBaseUrl,
    /// The selected family is not in the Twilio source catalog.
    InvalidFamily,
    /// Source tenant identity is required.
    MissingTenantId,
    /// Account SID is required for the keys family.
    MissingAccountSid,
    /// Page size is outside the Go source's inclusive 1 through 500 range.
    InvalidPageSize,
    /// Provider continuation is oversized, control-bearing, or malformed.
    InvalidCursor,
    /// A planned request does not belong to this kernel.
    RequestScopeMismatch,
    /// Provider response exceeds the eight-mebibyte host bound.
    ResponseTooLarge,
    /// Provider response exceeds the requested maximum page cardinality.
    TooManyRecords,
    /// Response JSON does not match the selected provider family.
    InvalidResponse,
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

impl fmt::Display for TwilioError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBaseUrl => formatter.write_str("twilio base URL must be a secure origin"),
            Self::InvalidFamily => {
                formatter.write_str("twilio family must be accounts, keys, or audit_events")
            }
            Self::MissingTenantId => formatter.write_str("twilio tenant_id is required"),
            Self::MissingAccountSid => {
                formatter.write_str("twilio account_sid is required for keys")
            }
            Self::InvalidPageSize => {
                formatter.write_str("twilio per_page must be between 1 and 500")
            }
            Self::InvalidCursor => formatter.write_str("twilio page cursor is invalid"),
            Self::RequestScopeMismatch => {
                formatter.write_str("twilio request does not match the kernel")
            }
            Self::ResponseTooLarge => formatter.write_str("twilio response exceeds 8388608 bytes"),
            Self::TooManyRecords => formatter.write_str("twilio response exceeds 500 records"),
            Self::InvalidResponse => {
                formatter.write_str("twilio response does not match the selected family")
            }
            Self::MissingProviderIdentity => {
                formatter.write_str("twilio record has no stable provider identity")
            }
            Self::InvalidEventIdentity => {
                formatter.write_str("twilio tenant or provider identity is not event-ID safe")
            }
            Self::ConflictingProviderIdentity => {
                formatter.write_str("twilio page contains conflicting provider identities")
            }
            Self::MissingRequiredPayloadField(name) => {
                write!(
                    formatter,
                    "twilio record is missing required payload field {name}"
                )
            }
            Self::MissingRequiredAttribute(name) => {
                write!(
                    formatter,
                    "twilio record is missing required attribute {name}"
                )
            }
        }
    }
}

impl Error for TwilioError {}
