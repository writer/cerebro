//! Shared bounded validators for external envelope and payload fields.
//!
//! These helpers enforce portable syntax and resource ceilings before typed
//! payload processing. They are not secret scanners, authorization checks,
//! signature verification, or substitutes for aggregate transport byte limits.

use serde_json::Value;

use crate::SdkError;

use super::{
    EXTERNAL_EVENT_ATTRIBUTE_KEYS, MAX_EXTERNAL_EVENT_ATTRIBUTE_VALUE_BYTES, MAX_ID_BYTES,
    MAX_PAYLOAD_BYTES, MAX_PAYLOAD_DEPTH, MAX_PAYLOAD_NODES, MAX_REFS, MAX_TEXT_BYTES,
};

/// Validates one allowlisted, non-secret operational metadata pair.
///
/// Values are capped at 256 bytes, use the wire ID alphabet, and are rejected
/// when a normalized substring resembles common credential names. The marker
/// check is defense in depth, not exhaustive secret detection; producers must
/// never place credential values in envelope attributes.
///
/// # Errors
///
/// Returns [`SdkError::Invalid`] for a key outside the allowlist, a credential
/// marker, or invalid identifier syntax, [`SdkError::TooLong`] above 256 bytes,
/// or [`SdkError::Empty`] for an empty value.
pub(super) fn validate_attribute(key: &str, value: &str) -> Result<(), SdkError> {
    if !EXTERNAL_EVENT_ATTRIBUTE_KEYS.contains(&key) {
        return Err(SdkError::Invalid("external event attribute key"));
    }
    if value.len() > MAX_EXTERNAL_EVENT_ATTRIBUTE_VALUE_BYTES {
        return Err(SdkError::TooLong("external event attribute value"));
    }

    // Collapse common separators and case so labels such as `api-key` and
    // `session_cookie` cannot evade the closed marker check.
    let normalized = value
        .to_ascii_lowercase()
        .replace(['-', '.', '/', ':', '@', '%'], "_");
    let compact = normalized.replace('_', "");
    if [
        "apikey",
        "authorization",
        "bearer",
        "credential",
        "password",
        "privatekey",
        "secret",
        "sessioncookie",
        "token",
    ]
    .iter()
    .any(|marker| compact.contains(marker))
    {
        return Err(SdkError::Invalid("external event attribute value"));
    }
    validate_id(value, "external event attribute value")
}

/// Validates a non-empty, bounded identifier without normalizing it.
///
/// Accepted values are at most 256 bytes and contain only ASCII alphanumerics
/// plus `-`, `_`, `.`, `:`, `/`, `@`, and `%`. Equality remains byte-exact.
///
/// # Errors
///
/// Returns [`SdkError::Empty`] for an empty value or [`SdkError::Invalid`] for
/// padding, excess length, or a byte outside the accepted alphabet.
pub(super) fn validate_id(value: &str, field: &'static str) -> Result<(), SdkError> {
    if value.is_empty() {
        return Err(SdkError::Empty(field));
    }
    if value.trim() != value
        || value.len() > MAX_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/@%".contains(&byte))
    {
        return Err(SdkError::Invalid(field));
    }
    Ok(())
}

/// Validates bounded human-readable wire text.
///
/// Text is non-empty after trimming, has no surrounding whitespace or control
/// characters, and is at most 1,024 bytes. Unicode and internal whitespace are
/// otherwise preserved.
///
/// # Errors
///
/// Returns [`SdkError::Empty`] for blank text or [`SdkError::Invalid`] for
/// padding, excess length, or control characters.
pub(super) fn validate_text(value: &str, field: &'static str) -> Result<(), SdkError> {
    if value.trim().is_empty() {
        return Err(SdkError::Empty(field));
    }
    if value.trim() != value || value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control)
    {
        return Err(SdkError::Invalid(field));
    }
    Ok(())
}

/// Validates lowercase hexadecimal SHA-256 encoding syntax.
///
/// This check does not recompute the digest or bind it to content.
///
/// # Errors
///
/// Returns [`SdkError::Invalid`] unless the value is exactly 64 bytes of ASCII
/// digits or lowercase `a` through `f`.
pub(super) fn validate_digest(value: &str, field: &'static str) -> Result<(), SdkError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SdkError::Invalid(field));
    }
    Ok(())
}

/// Validates up to 512 identifier references.
///
/// Empty collections and duplicate values are allowed; family-specific payload
/// validators must impose stronger presence or set semantics when required.
///
/// # Errors
///
/// Returns [`SdkError::OutOfRange`] above 512 entries or the first identifier
/// validation error.
pub(super) fn validate_refs(values: &[String], field: &'static str) -> Result<(), SdkError> {
    if values.len() > MAX_REFS {
        return Err(SdkError::OutOfRange(field));
    }
    for value in values {
        validate_id(value, field)?;
    }
    Ok(())
}

/// Recursively enforces JSON depth, node-count, key, and string bounds.
///
/// Callers pass depth zero and a zeroed shared node counter for the root. The
/// tree may contain at most 8,192 nodes and descend through depth 32. Object keys
/// use [`validate_text`]. The per-string limit is 256 KiB; callers separately
/// enforce the same ceiling over the serialized payload as a whole.
///
/// The node counter uses saturating arithmetic, ensuring an adversarial tree
/// cannot wrap the bound. On error it retains the number visited so far and is
/// not suitable for reuse as a fresh validation counter.
///
/// # Errors
///
/// Returns [`SdkError::OutOfRange`] for excess depth or node count,
/// [`SdkError::TooLong`] for an oversized string, or an object-key text error.
pub(super) fn validate_json_bounds(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), SdkError> {
    if depth > MAX_PAYLOAD_DEPTH {
        return Err(SdkError::OutOfRange("external payload depth"));
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_PAYLOAD_NODES {
        return Err(SdkError::OutOfRange("external payload node count"));
    }
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                validate_text(key, "external payload key")?;
                validate_json_bounds(child, depth + 1, nodes)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                validate_json_bounds(child, depth + 1, nodes)?;
            }
        }
        Value::String(text) if text.len() > MAX_PAYLOAD_BYTES => {
            return Err(SdkError::TooLong("external payload text"));
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}
