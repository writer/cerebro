use serde::{Deserialize, Serialize};

use super::{SlackError, SlackFamily};

const MAX_CURSOR_BYTES: usize = 4_096;
const AUDIT_CURSOR_MODE: &str = "rolling_window";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct ParsedCursor {
    pub(super) token: String,
    pub(super) audit_window: Option<(String, String)>,
}

#[derive(Deserialize, Serialize)]
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
    #[serde(default)]
    extra: std::collections::BTreeMap<String, String>,
}

pub(super) fn parse(family: SlackFamily, value: Option<&str>) -> Result<ParsedCursor, SlackError> {
    let value = value.unwrap_or_default().trim();
    if value.is_empty() {
        return Ok(ParsedCursor::default());
    }
    if !family.supports_cursor() {
        return Err(SlackError::UnsupportedCursor);
    }
    if value.len() > MAX_CURSOR_BYTES || value.chars().any(char::is_control) {
        return Err(SlackError::InvalidCursor);
    }
    if family == SlackFamily::AccessLog {
        let page = value
            .parse::<usize>()
            .map_err(|_| SlackError::InvalidCursor)?;
        if page == 0 || page > 1_000_000 {
            return Err(SlackError::InvalidCursor);
        }
        return Ok(ParsedCursor {
            token: page.to_string(),
            audit_window: None,
        });
    }
    if family == SlackFamily::AuditLog && value.starts_with('{') {
        let envelope: CursorEnvelope =
            serde_json::from_str(value).map_err(|_| SlackError::InvalidCursor)?;
        let oldest = envelope
            .extra
            .get("oldest")
            .map(String::as_str)
            .unwrap_or("")
            .trim();
        let latest = envelope
            .extra
            .get("latest")
            .map(String::as_str)
            .unwrap_or("")
            .trim();
        if envelope.version != 1
            || envelope.source.trim() != "slack"
            || envelope.family.trim() != "audit_log"
            || envelope.mode.trim() != AUDIT_CURSOR_MODE
            || envelope.token.trim().is_empty()
            || oldest.is_empty()
            || latest.is_empty()
            || !unix_seconds(oldest)
            || !unix_seconds(latest)
        {
            return Err(SlackError::InvalidCursor);
        }
        return Ok(ParsedCursor {
            token: envelope.token.trim().to_owned(),
            audit_window: Some((oldest.to_owned(), latest.to_owned())),
        });
    }
    Ok(ParsedCursor {
        token: value.to_owned(),
        audit_window: None,
    })
}

pub(super) fn audit_next(
    token: &str,
    window: Option<&(String, String)>,
) -> Result<Option<String>, SlackError> {
    let token = token.trim();
    if token.is_empty() {
        return Ok(None);
    }
    if token.len() > MAX_CURSOR_BYTES || token.chars().any(char::is_control) {
        return Err(SlackError::InvalidCursor);
    }
    let Some((oldest, latest)) = window else {
        return Ok(Some(token.to_owned()));
    };
    let envelope = CursorEnvelope {
        version: 1,
        source: "slack".to_owned(),
        family: "audit_log".to_owned(),
        mode: AUDIT_CURSOR_MODE.to_owned(),
        token: token.to_owned(),
        extra: std::collections::BTreeMap::from([
            ("latest".to_owned(), latest.to_owned()),
            ("oldest".to_owned(), oldest.to_owned()),
        ]),
    };
    serde_json::to_string(&envelope)
        .map(Some)
        .map_err(|_| SlackError::InvalidCursor)
}

pub(super) fn unix_seconds(value: &str) -> bool {
    value.parse::<u64>().is_ok_and(|value| value > 0)
}
