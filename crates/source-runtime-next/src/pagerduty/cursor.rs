//! Go-compatible PagerDuty offset and integration fan-out continuations.

use serde::{Deserialize, Serialize};

use super::{PagerDutyError, PagerDutyFamily};

const MAX_CURSOR_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct CursorState {
    pub(super) service_index: usize,
    pub(super) offset: Option<u64>,
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

pub(super) fn parse_cursor(
    family: PagerDutyFamily,
    service_count: usize,
    raw: Option<&str>,
) -> Result<CursorState, PagerDutyError> {
    let raw = raw.map(str::trim).filter(|value| !value.is_empty());
    let Some(raw) = raw else {
        return Ok(CursorState::default());
    };
    validate_cursor_text(raw)?;
    if !raw.starts_with('{') {
        return Ok(CursorState {
            offset: Some(parse_offset(raw)?),
            ..CursorState::default()
        });
    }
    let envelope: CursorEnvelope =
        serde_json::from_str(raw).map_err(|_| PagerDutyError::InvalidCursor)?;
    if !matches!(envelope.version, 0 | 1)
        || (!envelope.source.is_empty() && envelope.source != "pagerduty")
        || (!envelope.family.is_empty() && envelope.family != family.as_str())
    {
        return Err(PagerDutyError::InvalidCursor);
    }
    if family != PagerDutyFamily::Integration {
        if !envelope.mode.is_empty() || envelope.token.is_empty() {
            return Err(PagerDutyError::InvalidCursor);
        }
        return Ok(CursorState {
            offset: Some(parse_offset(&envelope.token)?),
            ..CursorState::default()
        });
    }
    if envelope.mode != "fanout_path_param" || envelope.token.is_empty() {
        return Err(PagerDutyError::InvalidCursor);
    }
    let inner: FanoutCursor =
        serde_json::from_str(&envelope.token).map_err(|_| PagerDutyError::InvalidCursor)?;
    if inner.index >= service_count {
        return Err(PagerDutyError::InvalidCursor);
    }
    Ok(CursorState {
        service_index: inner.index,
        offset: (!inner.cursor.is_empty())
            .then(|| parse_offset(&inner.cursor))
            .transpose()?,
    })
}

pub(super) fn encode_fanout_cursor(
    service_index: usize,
    offset: Option<u64>,
) -> Result<String, PagerDutyError> {
    let inner = serde_json::to_string(&FanoutCursor {
        index: service_index,
        cursor: offset.map(|value| value.to_string()).unwrap_or_default(),
    })
    .map_err(|_| PagerDutyError::InvalidCursor)?;
    let encoded = serde_json::to_string(&EncodedEnvelope {
        version: 1,
        source: "pagerduty",
        mode: "fanout_path_param",
        token: inner,
    })
    .map_err(|_| PagerDutyError::InvalidCursor)?;
    validate_cursor_text(&encoded)?;
    Ok(encoded)
}

fn parse_offset(raw: &str) -> Result<u64, PagerDutyError> {
    if raw.is_empty()
        || raw.starts_with('+')
        || raw.starts_with('-')
        || !raw.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(PagerDutyError::InvalidCursor);
    }
    raw.parse().map_err(|_| PagerDutyError::InvalidCursor)
}

fn validate_cursor_text(raw: &str) -> Result<(), PagerDutyError> {
    if raw.len() > MAX_CURSOR_BYTES
        || raw.chars().any(char::is_control)
        || raw.starts_with("http://")
        || raw.starts_with("https://")
    {
        return Err(PagerDutyError::InvalidCursor);
    }
    Ok(())
}
