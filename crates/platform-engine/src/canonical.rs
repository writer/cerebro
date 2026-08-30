//! Shared JSON-to-SHA-256 content-addressing helper for platform engines.
//!
//! "Canonical" here means that a given [`Serialize`] implementation produces
//! the same compact JSON bytes and therefore the same digest. This helper does
//! not sort arbitrary map keys or normalize semantically equivalent JSON. Callers
//! must use structs, ordered collections, and stable field representations when
//! a digest is part of a durable or cross-language contract.

use cerebro_platform_sdk::{ContentDigest, SdkError};
use serde::Serialize;

/// Serializes a value as compact JSON and hashes the exact bytes with SHA-256.
///
/// Serialized field order, enum representation, omitted fields, vector order,
/// and numeric/string encoding all contribute to identity. Changing a derived
/// [`Serialize`] layout can therefore be a digest-contract migration even when
/// the Rust values appear semantically equivalent.
///
/// # Errors
///
/// Returns [`SdkError::Backend`] when JSON serialization fails. No partially
/// computed digest is returned.
pub(crate) fn digest<T: Serialize>(value: &T) -> Result<ContentDigest, SdkError> {
    // Hash only after serialization succeeds so error paths never identify
    // incomplete material as a valid content address.
    serde_json::to_vec(value)
        .map(ContentDigest::of_bytes)
        .map_err(|error| SdkError::Backend(format!("canonical serialization failed: {error}")))
}

#[cfg(test)]
mod tests {
    use super::digest;

    #[test]
    fn digest_is_deterministic_and_sensitive_to_serialized_values() {
        let first = digest(&("field", 1_u8)).unwrap();
        let repeat = digest(&("field", 1_u8)).unwrap();
        let changed = digest(&("field", 2_u8)).unwrap();

        assert_eq!(first, repeat);
        assert_ne!(first, changed);
    }
}
