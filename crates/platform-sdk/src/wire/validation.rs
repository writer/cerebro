use serde_json::Value;

use crate::SdkError;

use super::{
    MAX_ID_BYTES, MAX_PAYLOAD_BYTES, MAX_PAYLOAD_DEPTH, MAX_PAYLOAD_NODES, MAX_REFS, MAX_TEXT_BYTES,
};

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

pub(super) fn validate_refs(values: &[String], field: &'static str) -> Result<(), SdkError> {
    if values.len() > MAX_REFS {
        return Err(SdkError::OutOfRange(field));
    }
    for value in values {
        validate_id(value, field)?;
    }
    Ok(())
}

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
