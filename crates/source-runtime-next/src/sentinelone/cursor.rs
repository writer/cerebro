use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use super::model::{ApplicationCursor, SentinelOneError};

pub(super) const APPLICATION_CURSOR_PREFIX: &str = "cerebro-sentinelone-application-v1:";
pub(super) const MAX_PROVIDER_CURSOR_BYTES: usize = 4_096;
pub(super) const MAX_APPLICATION_CURSOR_BYTES: usize = 4_096;
const MAX_CURSOR_COMPONENT_BYTES: usize = 4_096;

pub(super) fn bounded_provider_cursor(
    cursor: Option<&str>,
) -> Result<Option<String>, SentinelOneError> {
    bounded_cursor(cursor, MAX_PROVIDER_CURSOR_BYTES)
}

pub(super) fn decode_application_cursor(
    cursor: Option<&str>,
) -> Result<(ApplicationCursor, Option<String>, bool), SentinelOneError> {
    let cursor = cursor.map(str::trim).filter(|value| !value.is_empty());
    let max_bytes = cursor.map_or(MAX_PROVIDER_CURSOR_BYTES, |value| {
        if value.starts_with(APPLICATION_CURSOR_PREFIX) {
            MAX_APPLICATION_CURSOR_BYTES
        } else {
            MAX_PROVIDER_CURSOR_BYTES
        }
    });
    let Some(cursor) = bounded_cursor(cursor, max_bytes)? else {
        return Ok((ApplicationCursor::default(), None, false));
    };
    let Some(encoded) = cursor.strip_prefix(APPLICATION_CURSOR_PREFIX) else {
        return Ok((ApplicationCursor::default(), Some(cursor), false));
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| SentinelOneError::InvalidCursor)?;
    let mut state: ApplicationCursor =
        serde_json::from_slice(&bytes).map_err(|_| SentinelOneError::InvalidCursor)?;
    state.parent_id = state.parent_id.trim().to_owned();
    state.next_parent_cursor = state.next_parent_cursor.trim().to_owned();
    state.after_record_id = state.after_record_id.trim().to_owned();
    if state.parent_id.is_empty() {
        return Err(SentinelOneError::CursorParentRequired);
    }
    if application_state_is_invalid(&state) {
        return Err(SentinelOneError::InvalidCursor);
    }
    Ok((state, None, true))
}

pub(super) fn encode_application_cursor(
    state: &ApplicationCursor,
) -> Result<String, SentinelOneError> {
    if state.parent_id.is_empty() || application_state_is_invalid(state) {
        return Err(SentinelOneError::InvalidCursor);
    }
    let payload = serde_json::to_vec(state).map_err(|_| SentinelOneError::InvalidCursor)?;
    let cursor = format!(
        "{APPLICATION_CURSOR_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(payload)
    );
    if cursor.len() > MAX_APPLICATION_CURSOR_BYTES {
        return Err(SentinelOneError::InvalidCursor);
    }
    Ok(cursor)
}

fn bounded_cursor(
    cursor: Option<&str>,
    max_bytes: usize,
) -> Result<Option<String>, SentinelOneError> {
    let cursor = cursor.map(str::trim).filter(|value| !value.is_empty());
    if cursor.is_some_and(|value| value.len() > max_bytes || value.chars().any(char::is_control)) {
        return Err(SentinelOneError::InvalidCursor);
    }
    Ok(cursor.map(str::to_owned))
}

fn application_state_is_invalid(state: &ApplicationCursor) -> bool {
    [
        state.parent_id.as_str(),
        state.next_parent_cursor.as_str(),
        state.after_record_id.as_str(),
    ]
    .into_iter()
    .any(|value| value.len() > MAX_CURSOR_COMPONENT_BYTES || value.chars().any(char::is_control))
}
