//! Opaque provider continuation validation.

use super::GcpIamError;

pub(super) const MAX_PROVIDER_CURSOR_BYTES: usize = 4_096;

pub(super) fn bounded_gcp_cursor(cursor: Option<&str>) -> Result<Option<String>, GcpIamError> {
    let cursor = cursor.filter(|value| !value.trim().is_empty());
    if cursor.is_some_and(|value| {
        value.len() > MAX_PROVIDER_CURSOR_BYTES || value.chars().any(char::is_control)
    }) {
        return Err(GcpIamError::InvalidCursor);
    }
    Ok(cursor.map(str::to_owned))
}
