//! Go-compatible JumpCloud group-membership fanout continuations.

use serde::{Deserialize, Serialize};

use super::{JumpCloudError, request::validate_offset};

pub(super) const MAX_GROUP_FANOUT: usize = 1_000;
const MAX_CURSOR_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct FanoutCursorState {
    pub(super) index: usize,
    pub(super) offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct CursorEnvelope {
    #[serde(default)]
    version: u8,
    #[serde(default)]
    source: String,
    #[serde(default)]
    family: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    token: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct FanoutCursor {
    index: usize,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    cursor: String,
}

#[derive(Serialize)]
struct EncodedEnvelope<'a> {
    version: u8,
    source: &'a str,
    mode: &'a str,
    token: String,
}

pub(super) fn parse_fanout_cursor(
    group_count: usize,
    raw: Option<&str>,
) -> Result<FanoutCursorState, JumpCloudError> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(FanoutCursorState::default());
    };
    validate_cursor_text(raw)?;
    if !raw.starts_with('{') {
        return Ok(FanoutCursorState {
            offset: Some(validate_offset(raw)?),
            ..FanoutCursorState::default()
        });
    }
    let envelope: CursorEnvelope =
        serde_json::from_str(raw).map_err(|_| JumpCloudError::InvalidCursor)?;
    if envelope.version != 1
        || envelope.source != "jumpcloud"
        || (!envelope.family.is_empty() && envelope.family != "group_members")
        || envelope.mode != "fanout_path_param"
        || envelope.token.is_empty()
    {
        return Err(JumpCloudError::InvalidCursor);
    }
    let inner: FanoutCursor =
        serde_json::from_str(&envelope.token).map_err(|_| JumpCloudError::InvalidCursor)?;
    if inner.index >= group_count {
        return Err(JumpCloudError::InvalidCursor);
    }
    Ok(FanoutCursorState {
        index: inner.index,
        offset: (!inner.cursor.is_empty())
            .then(|| validate_offset(&inner.cursor))
            .transpose()?,
    })
}

pub(super) fn encode_fanout_cursor(
    index: usize,
    offset: Option<usize>,
) -> Result<String, JumpCloudError> {
    let token = serde_json::to_string(&FanoutCursor {
        index,
        cursor: offset.map(|value| value.to_string()).unwrap_or_default(),
    })
    .map_err(|_| JumpCloudError::InvalidCursor)?;
    let opaque = serde_json::to_string(&EncodedEnvelope {
        version: 1,
        source: "jumpcloud",
        mode: "fanout_path_param",
        token,
    })
    .map_err(|_| JumpCloudError::InvalidCursor)?;
    validate_cursor_text(&opaque)?;
    Ok(opaque)
}

fn validate_cursor_text(raw: &str) -> Result<(), JumpCloudError> {
    if raw.is_empty()
        || raw.len() > MAX_CURSOR_BYTES
        || raw.chars().any(char::is_control)
        || raw.starts_with("http://")
        || raw.starts_with("https://")
    {
        return Err(JumpCloudError::InvalidCursor);
    }
    Ok(())
}
