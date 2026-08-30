//! Stable, transport-neutral failure taxonomy for platform capabilities.
//!
//! Variants distinguish caller repair, retry, missing capability, and backend
//! failure classes without prescribing an HTTP or RPC status mapping. Adapters
//! own that mapping and must redact provider data and secret-bearing context
//! before constructing errors with owned messages.

use std::{error::Error, fmt};

/// Failure returned by platform SDK validation and capability implementations.
///
/// Shape-validation variants carry static field labels so user-controlled input
/// is not reflected automatically. Contextual variants accept owned messages;
/// those messages are displayed verbatim after a fixed category prefix and must
/// therefore already be safe for the caller and logs that receive them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SdkError {
    /// A required field or collection was absent.
    Empty(&'static str),
    /// A field was present but violated its syntax or structural contract.
    Invalid(&'static str),
    /// A field exceeded its byte, item, or other declared size ceiling.
    TooLong(&'static str),
    /// A numeric or collection value fell outside its allowed range.
    OutOfRange(&'static str),
    /// Current state conflicts with the requested transition.
    Conflict(String),
    /// A referenced platform value does not exist within the operation scope.
    NotFound(String),
    /// The selected deployment does not implement or own the requested capability.
    CapabilityUnavailable(String),
    /// An implementation dependency or internal operation failed.
    Backend(String),
}

impl fmt::Display for SdkError {
    /// Formats a stable category prefix followed by the stored field or message.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty(field) => write!(formatter, "{field} is required"),
            Self::Invalid(field) => write!(formatter, "{field} is invalid"),
            Self::TooLong(field) => write!(formatter, "{field} exceeds its size limit"),
            Self::OutOfRange(field) => write!(formatter, "{field} is outside its allowed range"),
            Self::Conflict(message) => write!(formatter, "platform conflict: {message}"),
            Self::NotFound(message) => write!(formatter, "platform value not found: {message}"),
            Self::CapabilityUnavailable(message) => {
                write!(formatter, "platform capability unavailable: {message}")
            }
            Self::Backend(message) => write!(formatter, "platform backend failed: {message}"),
        }
    }
}

impl Error for SdkError {}
