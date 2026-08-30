//! Bounded transport identifiers and content digests shared by platform contracts.
//!
//! The wrappers in this module make wire-level shape constraints explicit while
//! preserving the caller's exact identifier spelling. They do not establish
//! tenant ownership, resource existence, authorization, or cryptographic
//! authenticity; those checks remain at the importing boundary.

use std::{fmt, fmt::Write as _};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::SdkError;

const MAX_ID_BYTES: usize = 256;

/// Validated, transport-neutral identifier with no implied resource kind.
///
/// Values are non-empty, at most 256 bytes, and restricted to ASCII letters,
/// digits, `-`, `_`, `.`, `:`, and `/`. Parsing performs no case folding or
/// other normalization, so equality and ordering use the exact accepted bytes.
/// An opaque ID is not automatically safe as a filesystem path or URL segment.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct OpaqueId(String);

impl OpaqueId {
    /// Validates and preserves an identifier supplied by a contract caller.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Empty`] for an empty value, or
    /// [`SdkError::Invalid`] for surrounding whitespace, an unsupported byte,
    /// or a value longer than 256 bytes.
    pub fn parse(value: impl Into<String>) -> Result<Self, SdkError> {
        let value = value.into();
        if value.is_empty() {
            return Err(SdkError::Empty("platform id"));
        }
        if value.trim() != value
            || value.len() > MAX_ID_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte))
        {
            return Err(SdkError::Invalid("platform id"));
        }
        Ok(Self(value))
    }

    /// Borrows the exact validated identifier text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OpaqueId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

macro_rules! typed_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        ///
        /// This newtype prevents accidental interchange with other platform ID
        /// domains while retaining the syntax, ordering, and wire representation
        /// of [`OpaqueId`]. It does not prove resource existence or ownership.
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(OpaqueId);

        impl $name {
            /// Parses a value using the shared [`OpaqueId`] syntax contract.
            ///
            /// # Errors
            ///
            /// Returns the validation error produced by [`OpaqueId::parse`].
            pub fn parse(value: impl Into<String>) -> Result<Self, SdkError> {
                Ok(Self(OpaqueId::parse(value)?))
            }

            /// Borrows the exact validated identifier text.
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, formatter)
            }
        }
    };
}

typed_id!(
    ActionOperationId,
    "Identity of one action execution operation."
);
typed_id!(
    AssertionDefinitionId,
    "Identity of one assertion definition."
);
typed_id!(IncidentSnapshotId, "Identity of one incident snapshot.");
typed_id!(PluginId, "Identity of one registered platform plugin.");
typed_id!(SimulationId, "Identity of one action simulation.");
typed_id!(SubscriptionId, "Identity of one event subscription.");
typed_id!(ViewId, "Identity of one materialized platform view.");

/// Canonical lowercase hexadecimal SHA-256 digest.
///
/// The wrapper guarantees encoding shape only. [`Self::parse`] does not bind a
/// digest to content, and SHA-256 alone is neither an authenticity proof nor a
/// secret-bearing credential. Callers must recompute or otherwise verify the
/// digest at the boundary where content integrity matters.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ContentDigest(String);

impl ContentDigest {
    /// Parses a 64-character lowercase hexadecimal digest.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Invalid`] unless every character is an ASCII digit
    /// or lowercase `a` through `f` and the encoded value is exactly 64 bytes.
    pub fn parse(value: impl Into<String>) -> Result<Self, SdkError> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(SdkError::Invalid("content digest"));
        }
        Ok(Self(value))
    }

    /// Computes the SHA-256 digest of the supplied bytes.
    ///
    /// No framing or canonical serialization is added. Structured values must
    /// therefore be serialized canonically by the caller before hashing.
    pub fn of_bytes(value: impl AsRef<[u8]>) -> Self {
        let digest = Sha256::digest(value.as_ref());
        let mut encoded = String::with_capacity(64);
        for byte in digest {
            write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
        }
        Self(encoded)
    }

    /// Borrows the canonical lowercase hexadecimal encoding.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{ContentDigest, OpaqueId};

    #[test]
    fn ids_reject_whitespace_and_unbounded_values() {
        assert!(OpaqueId::parse("valid-id").is_ok());
        assert!(OpaqueId::parse(" invalid").is_err());
        assert!(OpaqueId::parse("invalid?").is_err());
        assert!(OpaqueId::parse("x".repeat(257)).is_err());
    }

    #[test]
    fn content_digests_are_canonical_lowercase_sha256() {
        let digest = ContentDigest::of_bytes("cerebro");
        assert_eq!(digest.as_str().len(), 64);
        assert!(ContentDigest::parse(digest.to_string()).is_ok());
        assert!(ContentDigest::parse("A".repeat(64)).is_err());
    }
}
